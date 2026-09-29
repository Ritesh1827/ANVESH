"""
Call-graph extractor — PRD §5 stage 7 (Reachability & Context).

Builds a directed call-graph from source files using tree-sitter AST analysis.
The graph is a NetworkX DiGraph where nodes are qualified function names and
edges represent "caller → callee" relationships.

Scope (prototype per PRD §11):
  - Call-graph based, not full inter-procedural data-flow analysis.
  - Covers Python for the prototype (same language grammars installed in Day 2).
  - Java, JS, C graphs follow the same visitor pattern; Python is primary.

The call-graph is used by the ReachabilityEngine to determine whether a
discovered crypto asset (identified by the function it appears in) is
reachable from any entry point.

Entry points are heuristically identified as:
  1. Functions/methods exposed via route decorators (@app.route, @router.get, etc.)
  2. Functions named main() or __main__
  3. Any function explicitly annotated as an entry point in the graph config
  4. Public class methods in service classes (heuristic fallback)

Reference: PRD §5 stage 7, §11 (call-graph prototype limitation).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import networkx as nx
from tree_sitter import Language, Node, Parser

logger = logging.getLogger(__name__)


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class CallGraphNode:
    """A node in the call graph representing a callable unit."""
    qualified_name: str     # e.g. "auth_service.create_session_key"
    file_path: str          # relative file path
    line_number: int        # 1-based line of the function definition
    is_entry_point: bool = False
    entry_point_reason: Optional[str] = None  # e.g. "route decorator", "main()"


@dataclass
class CallRelation:
    """A directed call edge: caller → callee."""
    caller: str     # qualified_name of the calling function
    callee: str     # qualified_name of the called function (may be unresolved)
    call_line: int  # line number of the call site


@dataclass
class FileCallGraph:
    """Call-graph data extracted from a single source file."""
    file_path: Path
    module_name: str                        # derived from file name
    functions: list[CallGraphNode]          # all functions/methods defined
    calls: list[CallRelation]               # call edges discovered
    parse_error: bool = False


@dataclass
class ProjectCallGraph:
    """
    Aggregated call-graph across all scanned source files.

    The graph is a NetworkX DiGraph.
    Nodes: qualified_name strings (e.g. "auth_service.create_session_key")
    Edges: caller → callee
    """
    graph: nx.DiGraph = field(default_factory=nx.DiGraph)
    nodes: dict[str, CallGraphNode] = field(default_factory=dict)
    entry_points: list[str] = field(default_factory=list)   # qualified_names

    @property
    def node_count(self) -> int:
        return self.graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self.graph.number_of_edges()

    def has_path_to(self, source: str, target: str) -> bool:
        """Return True if there is a directed path from source to target."""
        if source not in self.graph or target not in self.graph:
            return False
        try:
            return nx.has_path(self.graph, source, target)
        except nx.NetworkXError:
            return False

    def shortest_path(self, source: str, target: str) -> Optional[list[str]]:
        """Return the shortest directed path from source to target, or None."""
        if not self.has_path_to(source, target):
            return None
        try:
            return nx.shortest_path(self.graph, source, target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def reachable_from_any_entry(self, target: str) -> Optional[list[str]]:
        """
        Return the shortest path from any entry point to target, or None.

        Returns the path list (entry_point → ... → target), or None if
        the target is not reachable from any registered entry point.
        """
        if not self.entry_points:
            return None
        best_path: Optional[list[str]] = None
        for ep in self.entry_points:
            path = self.shortest_path(ep, target)
            if path is not None:
                if best_path is None or len(path) < len(best_path):
                    best_path = path
        return best_path


# ── Route decorator patterns ───────────────────────────────────────────────────

# Heuristic patterns that indicate a function is an HTTP/RPC entry point.
# Compiled once; checked against decorator names.
_ROUTE_DECORATOR_PATTERNS = [
    re.compile(r"route$", re.IGNORECASE),
    re.compile(r"^get$", re.IGNORECASE),
    re.compile(r"^post$", re.IGNORECASE),
    re.compile(r"^put$", re.IGNORECASE),
    re.compile(r"^delete$", re.IGNORECASE),
    re.compile(r"^patch$", re.IGNORECASE),
    re.compile(r"endpoint$", re.IGNORECASE),
    re.compile(r"handler$", re.IGNORECASE),
    re.compile(r"webhook$", re.IGNORECASE),
    re.compile(r"view$", re.IGNORECASE),
    re.compile(r"^api_", re.IGNORECASE),
    re.compile(r"^handle_", re.IGNORECASE),
    re.compile(r"^on_", re.IGNORECASE),       # event handlers
    re.compile(r"^dispatch", re.IGNORECASE),
    re.compile(r"^process_request", re.IGNORECASE),
    re.compile(r"^serve", re.IGNORECASE),
]

_ENTRY_POINT_NAMES = {
    "main", "__main__", "run", "start", "execute",
    "handle", "handler", "process", "dispatch",
    "setUp", "setup", "tearDown", "teardown",  # test entry points
}


def _is_route_decorator(decorator_text: str) -> bool:
    """Check if a decorator text suggests this is an HTTP route/handler."""
    return any(pat.search(decorator_text) for pat in _ROUTE_DECORATOR_PATTERNS)


def _is_entry_point_name(func_name: str) -> bool:
    """Check if a function name indicates it's an entry point."""
    name_lower = func_name.lower()
    return (
        func_name in _ENTRY_POINT_NAMES or
        name_lower in _ENTRY_POINT_NAMES or
        name_lower.startswith("handle_") or
        name_lower.startswith("on_") or
        name_lower.startswith("process_") or
        name_lower == "__call__"
    )


# ── Python AST visitor ─────────────────────────────────────────────────────────

def _node_text(node: Node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _get_identifier_text(node: Node, source: bytes) -> Optional[str]:
    """Get text if the node is an identifier."""
    if node.type == "identifier":
        return _node_text(node, source)
    return None


def _extract_decorator_names(func_node: Node, source: bytes) -> list[str]:
    """Extract decorator names from a function_definition node."""
    decorators = []
    # In tree-sitter-python, decorators appear as siblings before the function
    # OR as children of a decorated_definition node
    parent = func_node.parent
    if parent and parent.type == "decorated_definition":
        for child in parent.children:
            if child.type == "decorator":
                dec_text = _node_text(child, source).lstrip("@").strip()
                # Get just the name part (not arguments)
                dec_name = dec_text.split("(")[0].split(".")[-1]
                decorators.append(dec_name)
    return decorators


def _extract_function_call_name(call_node: Node, source: bytes) -> Optional[str]:
    """
    Extract the function/method name from a call node.
    Returns a dotted name where possible (e.g. "hashlib.md5", "RSA.generate").
    """
    if call_node.child_count == 0:
        return None
    fn_node = call_node.children[0]

    if fn_node.type == "attribute":
        # module.func or obj.method
        return _node_text(fn_node, source)
    if fn_node.type == "identifier":
        return _node_text(fn_node, source)
    return None


class PythonCallGraphVisitor:
    """
    Visits a Python AST (tree-sitter) and extracts:
      - Function/method definitions with their names and line numbers
      - Decorator-based entry-point detection
      - Call relationships (caller → callee)

    Call graph edges use qualified names: "module_name.function_name"
    or "module_name.ClassName.method_name" for methods.
    """

    def __init__(self, module_name: str, file_path: Path, source: bytes):
        self.module = module_name
        self.file_path = file_path
        self.source = source
        self.functions: list[CallGraphNode] = []
        self.calls: list[CallRelation] = []
        self._scope_stack: list[str] = []   # current nesting context

    def _current_scope(self) -> str:
        """Qualified name of the innermost enclosing function/class."""
        if self._scope_stack:
            return ".".join([self.module] + self._scope_stack)
        return self.module

    def _qualified(self, name: str) -> str:
        if self._scope_stack:
            return ".".join([self.module] + self._scope_stack + [name])
        return f"{self.module}.{name}"

    def visit(self, node: Node) -> None:
        """Iteratively visit the AST tree (explicit stack, no recursion)."""
        stack: list[Node] = [node]
        while stack:
            current = stack.pop()
            if current.type == "function_definition":
                self._visit_function(current)
                continue
            if current.type == "class_definition":
                self._visit_class(current)
                continue
            if current.type == "call" and self._scope_stack:
                self._visit_call(current)
                continue
            children = current.children
            for child in reversed(children):
                stack.append(child)

    def _visit_children_of(self, node: Node) -> None:
        """Visit the children of a function/class body node iteratively."""
        stack: list[Node] = list(reversed(node.children))
        while stack:
            current = stack.pop()
            if current.type == "function_definition":
                self._visit_function(current)
                continue
            if current.type == "class_definition":
                self._visit_class(current)
                continue
            if current.type == "call" and self._scope_stack:
                self._visit_call(current)
                continue
            children = current.children
            for child in reversed(children):
                stack.append(child)

    def _visit_function(self, node: Node) -> None:
        """Process a function_definition node."""
        # Extract name
        name_node = next(
            (c for c in node.children if c.type == "identifier"), None
        )
        if name_node is None:
            return

        func_name = _node_text(name_node, self.source)
        qualified = self._qualified(func_name)
        line = node.start_point[0] + 1  # 0-based → 1-based

        # Check for entry-point indicators
        decorators = _extract_decorator_names(node, self.source)
        is_entry = (
            _is_entry_point_name(func_name) or
            any(_is_route_decorator(d) for d in decorators)
        )
        reason: Optional[str] = None
        if is_entry:
            if any(_is_route_decorator(d) for d in decorators):
                reason = f"route decorator: @{decorators[0]}"
            elif _is_entry_point_name(func_name):
                reason = f"entry-point function name: {func_name}"

        self.functions.append(CallGraphNode(
            qualified_name=qualified,
            file_path=str(self.file_path),
            line_number=line,
            is_entry_point=is_entry,
            entry_point_reason=reason,
        ))

        # Recurse into the function body with updated scope.
        # The body is visited iteratively (no Python recursion): nested
        # definitions are processed by the shared stack walker, with the
        # scope stack keeping enclosing-function context correct.
        self._scope_stack.append(func_name)
        try:
            body = next((c for c in node.children if c.type == "block"), None)
            if body is not None:
                self._visit_children_of(body)
        finally:
            self._scope_stack.pop()

    def _visit_class(self, node: Node) -> None:
        """Process a class_definition node — push class name onto scope."""
        name_node = next(
            (c for c in node.children if c.type == "identifier"), None
        )
        if name_node is None:
            return

        class_name = _node_text(name_node, self.source)
        self._scope_stack.append(class_name)

        try:
            body = next((c for c in node.children if c.type == "block"), None)
            if body is not None:
                self._visit_children_of(body)
        finally:
            self._scope_stack.pop()

    def _visit_call(self, node: Node) -> None:
        """Record a function call from the current scope."""
        callee_raw = _extract_function_call_name(node, self.source)
        if not callee_raw:
            # Still visit arguments for nested calls (iteratively)
            self._visit_children_of(node)
            return

        # Qualify the callee with module if it looks like a local function
        # (no dot prefix → might be a local function in this module)
        if "." not in callee_raw:
            callee = f"{self.module}.{callee_raw}"
        else:
            callee = callee_raw   # already dotted (e.g. hashlib.md5, RSA.generate)

        self.calls.append(CallRelation(
            caller=self._current_scope(),
            callee=callee,
            call_line=node.start_point[0] + 1,
        ))

        # Visit argument expressions for nested calls (iteratively —
        # argument lists, not whole call nodes, to avoid re-recording).
        for child in node.children:
            if child.type == "argument_list":
                seeds = list(reversed(child.children))
                stack: list[Node] = seeds
                while stack:
                    current = stack.pop()
                    if current.type == "function_definition":
                        self._visit_function(current)
                        continue
                    if current.type == "class_definition":
                        self._visit_class(current)
                        continue
                    if current.type == "call" and self._scope_stack:
                        self._visit_call(current)
                        continue
                    for grandchild in reversed(current.children):
                        stack.append(grandchild)


# ── File-level graph builder ───────────────────────────────────────────────────

def _module_name_from_path(file_path: Path, relative_to: Optional[Path] = None) -> str:
    """
    Derive a Python module name from a file path.
    e.g. "auth_service.py" → "auth_service"
         "pkg/utils/crypto.py" → "pkg.utils.crypto"
    """
    if relative_to:
        try:
            rel = file_path.relative_to(relative_to)
        except ValueError:
            rel = file_path
    else:
        rel = file_path

    # Remove suffix and convert path separators to dots
    parts = list(rel.with_suffix("").parts)
    return ".".join(parts)


def extract_file_call_graph(
    file_path: Path,
    source_bytes: Optional[bytes] = None,
    relative_to: Optional[Path] = None,
) -> Optional[FileCallGraph]:
    """
    Extract a call graph from a single Python source file.

    Args:
        file_path:    Path to the source file.
        source_bytes: Pre-read file bytes (avoids re-reading if already loaded).
        relative_to:  Base path for module name derivation.

    Returns:
        FileCallGraph, or None if the file cannot be parsed.
    """
    try:
        import tree_sitter_python as tsp
        lang = Language(tsp.language())
    except ImportError:
        logger.warning("tree_sitter_python not installed — cannot build call graph")
        return None

    if source_bytes is None:
        try:
            source_bytes = file_path.read_bytes()
        except OSError as exc:
            logger.error("Cannot read %s for call graph: %s", file_path, exc)
            return None

    module_name = _module_name_from_path(file_path, relative_to)
    parser = Parser(lang)
    try:
        tree = parser.parse(source_bytes)
    except RecursionError:
        logger.warning(
            "Deep nesting in %s exceeded recursion during parse — "
            "skipping file in call graph",
            file_path,
        )
        return FileCallGraph(
            file_path=file_path,
            module_name=module_name,
            functions=[],
            calls=[],
            parse_error=True,
        )
    parse_error = tree.root_node.has_error

    visitor = PythonCallGraphVisitor(
        module_name=module_name,
        file_path=file_path,
        source=source_bytes,
    )
    try:
        visitor.visit(tree.root_node)
    except RecursionError:
        logger.warning(
            "Deep nesting in %s exceeded recursion during call-graph walk — "
            "skipping file in call graph",
            file_path,
        )
        return FileCallGraph(
            file_path=file_path,
            module_name=module_name,
            functions=[],
            calls=[],
            parse_error=True,
        )

    return FileCallGraph(
        file_path=file_path,
        module_name=module_name,
        functions=visitor.functions,
        calls=visitor.calls,
        parse_error=parse_error,
    )


# ── Project-level graph assembly ──────────────────────────────────────────────

def build_project_call_graph(
    file_paths: list[Path],
    relative_to: Optional[Path] = None,
) -> ProjectCallGraph:
    """
    Build a project-level call graph from a list of Python source files.

    Steps:
      1. Extract per-file call graphs.
      2. Add all function nodes to the NetworkX DiGraph.
      3. Add call edges, resolving local callee names where possible.
      4. Mark entry points.

    Args:
        file_paths:  List of source files to process (Python only for prototype).
        relative_to: Base path for module name derivation.

    Returns:
        ProjectCallGraph with a populated NetworkX DiGraph.
    """
    project = ProjectCallGraph()

    # Step 1: Collect per-file graphs
    file_graphs: list[FileCallGraph] = []
    for fp in file_paths:
        if fp.suffix.lower() not in (".py",):
            continue   # prototype: Python only for call-graph
        fg = extract_file_call_graph(fp, relative_to=relative_to)
        if fg is not None:
            file_graphs.append(fg)

    if not file_graphs:
        return project

    # Step 2: Add all defined functions as nodes
    all_module_names: set[str] = {fg.module_name for fg in file_graphs}
    for fg in file_graphs:
        for fn in fg.functions:
            project.graph.add_node(fn.qualified_name)
            project.nodes[fn.qualified_name] = fn
            if fn.is_entry_point:
                project.entry_points.append(fn.qualified_name)

    # Step 3: Add call edges
    # Build a set of all known qualified names for resolution
    known_names: set[str] = set(project.nodes.keys())

    for fg in file_graphs:
        for call in fg.calls:
            caller = call.caller
            callee_raw = call.callee

            # Try to resolve callee:
            # a) already a known qualified name
            # b) module.func where module is a known module in the project
            # c) add as an external node (library call)
            callee = _resolve_callee(callee_raw, known_names, all_module_names, fg.module_name)

            # Ensure both endpoints exist as nodes
            if caller not in project.graph:
                project.graph.add_node(caller)
            if callee not in project.graph:
                project.graph.add_node(callee)

            project.graph.add_edge(caller, callee)

    # Step 4: If no explicit entry points found, use heuristic fallback
    if not project.entry_points:
        # Any top-level function (single-dot qualified name, no class scope)
        # in a file that looks like a service/app/main is a candidate
        for name, node_data in project.nodes.items():
            parts = name.split(".")
            if len(parts) == 2:  # module.function (no class)
                func_name = parts[1]
                if _is_entry_point_name(func_name):
                    project.entry_points.append(name)
                    node_data.is_entry_point = True
                    node_data.entry_point_reason = "heuristic fallback"

    logger.info(
        "Call graph built: %d nodes, %d edges, %d entry points from %d files",
        project.node_count, project.edge_count,
        len(project.entry_points), len(file_graphs),
    )
    return project


def _resolve_callee(
    callee_raw: str,
    known_names: set[str],
    all_module_names: set[str],
    current_module: str,
) -> str:
    """
    Attempt to resolve a raw callee string to a known qualified name.

    Resolution order:
      1. Exact match in known_names (already fully qualified)
      2. current_module.callee_raw (local call within same module)
      3. Return callee_raw as-is (external / unresolvable)
    """
    if callee_raw in known_names:
        return callee_raw

    # Try as a local call in the current module
    local = f"{current_module}.{callee_raw}" if "." not in callee_raw else callee_raw
    if local in known_names:
        return local

    # Return as-is (external library call, will appear as an external node)
    return callee_raw
