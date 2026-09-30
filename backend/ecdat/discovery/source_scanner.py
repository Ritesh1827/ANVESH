"""
Source scanner — scans a single source file using tree-sitter AST analysis.

For each file:
  1. Select the correct tree-sitter language grammar by file extension.
  2. Parse the file into an AST.
  3. Walk every call_expression node in the tree.
  4. Test each call node against every applicable rule (via ast_matchers).
  5. Return a list of RawMatch objects for the Evidence Engine to process.

This module is deterministic — given the same file and rules, it always
produces the same output. No LLM involvement here.

Reference: PRD §5 stage 2 (Source & Binary Discovery — deterministic findings).
           PRD §5 stage 3a (deterministic findings pass through without LLM).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from tree_sitter import Language, Parser, Node

from .ast_matchers import RawMatch, try_match
from .rule_loader import DetectionRule, rules_for_language

logger = logging.getLogger(__name__)


# ── Language registry ─────────────────────────────────────────────────────────

# Lazy-loaded language objects — initialised on first use, not at import time.
_LANGUAGE_CACHE: dict[str, Language] = {}

# Maps normalised language name → grammar import function
_GRAMMAR_FACTORIES: dict[str, str] = {
    "python": "tree_sitter_python",
    "java": "tree_sitter_java",
    "javascript": "tree_sitter_javascript",
    "c": "tree_sitter_c",
}

# Per-language call node type names (differ across grammars)
# Confirmed by probing tree-sitter-python 0.25, tree-sitter-java 0.23,
# tree-sitter-javascript 0.25, tree-sitter-c 0.24.
CALL_NODE_TYPES: dict[str, set[str]] = {
    "python":     {"call"},
    "java":       {"method_invocation"},
    "javascript": {"call_expression"},
    "c":          {"call_expression"},
}

# Maps file extension → normalised language name
EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".pyw": "python",
    ".java": "java",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".c": "c",
    ".h": "c",
    ".cpp": "c",
    ".cc": "c",
    ".cxx": "c",
    ".hpp": "c",
}


def _get_language(language_name: str) -> Optional[Language]:
    """
    Return the tree-sitter Language object for the given language name.
    Returns None if the grammar module is not installed.
    """
    if language_name in _LANGUAGE_CACHE:
        return _LANGUAGE_CACHE[language_name]

    module_name = _GRAMMAR_FACTORIES.get(language_name)
    if module_name is None:
        logger.warning("No grammar factory registered for language '%s'", language_name)
        return None

    try:
        import importlib
        grammar_module = importlib.import_module(module_name)
        lang = Language(grammar_module.language())
        _LANGUAGE_CACHE[language_name] = lang
        return lang
    except ImportError:
        logger.warning(
            "Grammar module '%s' not installed — skipping '%s' files. "
            "Install with: pip install %s",
            module_name, language_name, module_name.replace("_", "-"),
        )
        return None
    except Exception as exc:
        logger.error("Failed to load grammar for '%s': %s", language_name, exc)
        return None


def language_for_file(file_path: Path) -> Optional[str]:
    """Return the normalised language name for a file path, or None."""
    return EXTENSION_TO_LANGUAGE.get(file_path.suffix.lower())


# ── AST node walker ───────────────────────────────────────────────────────────

def _walk_call_nodes(node: Node, results: list[Node],
                     call_types: set[str] | None = None) -> None:
    """
    Iterative depth-first walk of the AST, collecting nodes of interest.

    Explicit stack — no Python call-stack depth ceiling regardless of
    file nesting depth (a deeply nested generated file must degrade,
    never crash the scan). Accepts a set of node type names to collect
    (call nodes plus, for C, bare identifier nodes feeding c_symbol
    rules). Defaults to the union of all known call node types plus C
    identifiers for safety.
    """
    if call_types is None:
        call_types = {"call", "call_expression", "method_invocation",
                      "identifier", "type_identifier"}
    # Comment and string-literal subtrees never carry code evidence
    # (PRD §8: no comment/string matches). Prune them before descending
    # so identifier collection for C cannot pick up names from them.
    _COMMENT_STRING_TYPES = {
        "comment", "string", "string_literal", "string_content",
        "string_fragment", "template_string", "raw_string",
        "interpreted_string_literal", "raw_string_literal",
    }
    stack: list[Node] = [node]
    while stack:
        current = stack.pop()
        if current.type in call_types:
            results.append(current)
        children = current.children
        for child in reversed(children):
            if child.type in _COMMENT_STRING_TYPES:
                continue
            stack.append(child)


# ── Single-file scanner ───────────────────────────────────────────────────────

@dataclass
class FileScanResult:
    """Result of scanning a single source file."""
    file_path: Path
    language: str
    raw_matches: list[RawMatch]
    lines_scanned: int
    parse_error: bool = False        # True if tree-sitter reported parse errors
    error_message: Optional[str] = None

    @property
    def match_count(self) -> int:
        return len(self.raw_matches)


def scan_file(
    file_path: Path,
    rules: list[DetectionRule],
    *,
    max_file_size_bytes: int = 5 * 1024 * 1024,  # 5 MB limit
    relative_to: Optional[Path] = None,
) -> Optional[FileScanResult]:
    """
    Scan a single source file for cryptographic API usage.

    Args:
        file_path:           Absolute path to the file to scan.
        rules:               All loaded DetectionRule objects (filtered by language here).
        max_file_size_bytes: Skip files larger than this (avoids memory issues on
                             generated or minified files).
        relative_to:         If provided, file paths in RawMatch snippets are
                             made relative to this base path.

    Returns:
        FileScanResult, or None if the file extension is not supported.
    """
    file_path = Path(file_path)

    language = language_for_file(file_path)
    if language is None:
        logger.debug("Skipping unsupported file: %s", file_path)
        return None

    # Skip oversized files
    try:
        file_size = file_path.stat().st_size
    except OSError as exc:
        logger.warning("Cannot stat file %s: %s", file_path, exc)
        return None

    if file_size > max_file_size_bytes:
        logger.warning(
            "Skipping %s (%d bytes > %d byte limit)",
            file_path, file_size, max_file_size_bytes,
        )
        return None

    # Load the grammar
    lang = _get_language(language)
    if lang is None:
        return None

    # Get language-specific rules
    lang_rules = rules_for_language(rules, language)
    if not lang_rules:
        logger.debug("No rules for language '%s' — skipping %s", language, file_path)
        return None

    # Read and parse
    try:
        source_bytes = file_path.read_bytes()
    except OSError as exc:
        logger.error("Cannot read %s: %s", file_path, exc)
        return FileScanResult(
            file_path=file_path,
            language=language,
            raw_matches=[],
            lines_scanned=0,
            parse_error=True,
            error_message=str(exc),
        )

    parser = Parser(lang)
    try:
        tree = parser.parse(source_bytes)
    except RecursionError:
        logger.warning(
            "Deep nesting in %s exceeded recursion during parse — skipping file",
            file_path,
        )
        return FileScanResult(
            file_path=file_path,
            language=language,
            raw_matches=[],
            lines_scanned=source_bytes.count(b"\n") + 1,
            parse_error=True,
            error_message="RecursionError during parse (deeply nested file)",
        )

    parse_error = tree.root_node.has_error
    if parse_error:
        logger.debug("Parse errors in %s — continuing with partial AST", file_path)

    # Count lines
    lines_scanned = source_bytes.count(b"\n") + 1

    # Collect all call nodes using the language-specific node type names.
    # Iterative walk — but a pathological tree can still recurse inside
    # tree-sitter's own bindings, so guard per file, never per scan.
    # For C we also collect bare identifiers so c_symbol rules (NID/OBJ
    # constants, macro uses, dispatch references) can match; matchers for
    # other languages ignore non-call nodes. The C identifier collection
    # skips comment/string subtrees so the no-comment/no-string guarantee
    # (PRD §8) holds for every language.
    call_types = CALL_NODE_TYPES.get(language, {"call", "call_expression", "method_invocation"})
    if language == "c":
        call_types = set(call_types) | {"identifier", "type_identifier"}
    call_nodes: list[Node] = []
    try:
        _walk_call_nodes(tree.root_node, call_nodes, call_types)
    except RecursionError:
        logger.warning(
            "Deep nesting in %s exceeded recursion during walk — skipping file",
            file_path,
        )
        return FileScanResult(
            file_path=file_path,
            language=language,
            raw_matches=[],
            lines_scanned=lines_scanned,
            parse_error=True,
            error_message="RecursionError during AST walk (deeply nested file)",
        )

    # Test each call node against all applicable rules
    raw_matches: list[RawMatch] = []
    for call_node in call_nodes:
        for rule in lang_rules:
            match = try_match(call_node, source_bytes, rule)
            if match is not None:
                raw_matches.append(match)

    display_path = (
        file_path.relative_to(relative_to)
        if relative_to and file_path.is_relative_to(relative_to)
        else file_path
    )

    logger.debug(
        "Scanned %s (%s): %d call nodes, %d matches",
        display_path, language, len(call_nodes), len(raw_matches),
    )

    return FileScanResult(
        file_path=file_path,
        language=language,
        raw_matches=raw_matches,
        lines_scanned=lines_scanned,
        parse_error=parse_error,
    )


# ── Directory scanner ─────────────────────────────────────────────────────────

@dataclass
class DirectoryScanResult:
    """Aggregate result of scanning a directory tree."""
    root_path: Path
    file_results: list[FileScanResult]
    files_scanned: int
    files_skipped: int
    total_lines: int
    total_matches: int
    # Languages whose files were present but skipped because the
    # tree-sitter grammar package is not installed. Surfaced as a scan
    # warning instead of silently reporting the file as skipped.
    missing_grammars: list[str] = field(default_factory=list)

    @property
    def all_raw_matches(self) -> list[RawMatch]:
        """Flat list of all RawMatch objects across all files."""
        matches = []
        for fr in self.file_results:
            matches.extend(fr.raw_matches)
        return matches


def scan_directory(
    root_path: Path,
    rules: list[DetectionRule],
    *,
    exclude_dirs: Optional[set[str]] = None,
    max_file_size_bytes: int = 5 * 1024 * 1024,
) -> DirectoryScanResult:
    """
    Recursively scan a directory tree for cryptographic API usage.

    Args:
        root_path:           Root directory to scan.
        rules:               Loaded detection rules.
        exclude_dirs:        Directory names to skip (e.g. {'node_modules', '.git'}).
        max_file_size_bytes: Per-file size limit.

    Returns:
        DirectoryScanResult with per-file results and aggregate statistics.
    """
    root_path = Path(root_path)
    if not root_path.exists():
        raise FileNotFoundError(f"Scan root not found: {root_path}")

    if exclude_dirs is None:
        exclude_dirs = {
            ".git", ".venv", "venv", "env", "node_modules",
            "__pycache__", ".mypy_cache", ".ruff_cache",
            "dist", "build", ".eggs",
        }

    file_results: list[FileScanResult] = []
    files_skipped = 0
    missing_grammars: set[str] = set()

    # Walk the directory tree
    for item in sorted(root_path.rglob("*")):
        # Skip excluded directories
        if any(part in exclude_dirs for part in item.parts):
            continue
        if not item.is_file():
            continue

        # Only attempt files with supported extensions
        language = EXTENSION_TO_LANGUAGE.get(item.suffix.lower())
        if language is None:
            files_skipped += 1
            continue

        # A supported file whose grammar is unavailable is NOT a silent
        # skip: record the missing grammar so the scan reports a warning
        # instead of completing with zero findings and no explanation.
        if _get_language(language) is None:
            files_skipped += 1
            missing_grammars.add(language)
            logger.warning(
                "Skipping %s: tree-sitter grammar '%s' is not installed",
                item, language,
            )
            continue

        result = scan_file(
            item,
            rules,
            max_file_size_bytes=max_file_size_bytes,
            relative_to=root_path,
        )
        if result is not None:
            file_results.append(result)
        else:
            files_skipped += 1

    total_lines = sum(r.lines_scanned for r in file_results)
    total_matches = sum(r.match_count for r in file_results)

    logger.info(
        "Directory scan complete: %s — %d files scanned, %d skipped, "
        "%d total matches across %d lines%s",
        root_path, len(file_results), files_skipped,
        total_matches, total_lines,
        f" (missing grammars: {sorted(missing_grammars)})" if missing_grammars else "",
    )

    return DirectoryScanResult(
        root_path=root_path,
        file_results=file_results,
        files_scanned=len(file_results),
        files_skipped=files_skipped,
        total_lines=total_lines,
        total_matches=total_matches,
        missing_grammars=sorted(missing_grammars),
    )
