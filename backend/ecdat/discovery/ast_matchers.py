"""
AST matchers — tree-sitter node matching logic for each rule match_type.

Each matcher receives a tree-sitter call node (or call_expression node) and
a DetectionRule, and returns a RawMatch if the node satisfies the rule or
None if it does not.

Design principles:
  - Matchers operate on AST nodes, NOT on raw source text. This prevents
    false positives from matching algorithm names in comments or strings
    that are not actual API calls (PRD §8: tree-sitter avoids regex FPs).
  - Matchers are pure functions — no side effects, no I/O.
  - Key size extraction is best-effort: if the argument is not a simple
    integer literal, key_size_bits is left as None.

Reference: PRD §5 stage 2 (deterministic findings from AST analysis).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from tree_sitter import Node

from .rule_loader import DetectionRule, MatchSpec

logger = logging.getLogger(__name__)


@dataclass
class RawMatch:
    """
    A raw match produced by an AST matcher before the Evidence Engine runs.

    Contains all information needed to build an Evidence + CryptoAsset record.
    """
    rule: DetectionRule
    # 0-based row/col from tree-sitter (converted to 1-based line in Evidence)
    start_row: int
    start_col: int
    end_row: int
    end_col: int
    snippet: str                    # source text of the matched node
    extracted_key_size: Optional[int] = None   # from argument if extractable
    extracted_curve: Optional[str] = None      # for EC key generation
    observed_symbol: Optional[str] = None      # exact callee/symbol text observed
    sibling_symbols: tuple = ()                # nearby identifiers in the same statement
    # (Phase 3: EVP/NID disambiguation context — what surrounded the match)


# ── Node helpers ──────────────────────────────────────────────────────────────

def _node_text(node: Node, source: bytes) -> str:
    """Extract UTF-8 text for a tree-sitter node from the source bytes."""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _get_call_node_type(language: str) -> str:
    """
    Return the tree-sitter node type name for a function call in each language.

    tree-sitter grammar node names differ across languages:
      Python / Java / C:  call_expression
      JavaScript:         call_expression
    All grammars we use share 'call_expression' for Python, Java, JS, C.
    """
    return "call_expression"


def _get_children_of_type(node: Node, type_name: str) -> list[Node]:
    """Return all direct children of a node with the given type."""
    return [c for c in node.children if c.type == type_name]


def _get_function_name(call_node: Node, source: bytes) -> Optional[str]:
    """
    Extract the final function/method name from a call node.

    Handles all four grammar variants:
      Python:     call → attribute → identifier  (hashlib.md5)
                  call → identifier              (foo)
      Java:       method_invocation → identifier (MessageDigest.getInstance)
      JavaScript: call_expression → member_expression → property_identifier
      C:          call_expression → identifier   (MD5, RSA_generate_key)
    """
    if call_node.child_count == 0:
        return None

    fn_node = call_node.children[0]

    # Python attribute access: hashlib.md5
    if fn_node.type == "attribute":
        for child in reversed(fn_node.children):
            if child.type == "identifier":
                return _node_text(child, source)

    # JavaScript member expression: crypto.createHash
    if fn_node.type == "member_expression":
        for child in reversed(fn_node.children):
            if child.type in ("identifier", "property_identifier"):
                return _node_text(child, source)

    # Java method_invocation: the function name is the second identifier child
    # Structure: [receiver "." methodName argumentList]
    if call_node.type == "method_invocation":
        # Collect all identifiers at the top level of the method_invocation
        idents = [c for c in call_node.children if c.type == "identifier"]
        if idents:
            # Last identifier before argument_list is the method name
            return _node_text(idents[-1], source)

    # Simple identifier call: foo() or MD5()
    if fn_node.type in ("identifier",):
        return _node_text(fn_node, source)

    # Fallback: last dot-component of whatever text we have
    text = _node_text(fn_node, source)
    return text.split(".")[-1] if "." in text else text


def _get_module_name(call_node: Node, source: bytes) -> Optional[str]:
    """
    Extract the module/object/class name from a chained call.

    hashlib.md5(...)          → "hashlib"
    RSA.generate(...)         → "RSA"
    MessageDigest.getInstance → "MessageDigest"
    foo(...)                  → None
    """
    if call_node.child_count == 0:
        return None

    fn_node = call_node.children[0]

    # Python attribute: attribute → [identifier "." identifier]
    if fn_node.type == "attribute":
        for child in fn_node.children:
            if child.type == "identifier":
                return _node_text(child, source)

    # JavaScript member_expression: similar structure
    if fn_node.type == "member_expression":
        for child in fn_node.children:
            if child.type in ("identifier",):
                return _node_text(child, source)

    # Java method_invocation: first identifier is the receiver
    if call_node.type == "method_invocation":
        idents = [c for c in call_node.children if c.type == "identifier"]
        if len(idents) >= 2:
            return _node_text(idents[0], source)

    return None


def _get_arguments_node(call_node: Node) -> Optional[Node]:
    """Return the argument list node of a call (language-agnostic)."""
    for child in call_node.children:
        if child.type in ("argument_list", "arguments"):
            return child
    return None


# ── Named-curve NID mapping (C, config-adjacent constants) ───────────────────
# Maps OpenSSL NID constant text → canonical curve token used by
# _normalise_algorithm (P256/P384/P521/K256). Kept as data, not branches:
# the table is the single place curve spellings are recognised.

_NID_CURVE_TABLE: tuple[tuple[str, ...], ...] = (
    ("P256", ("PRIME256V1", "PRIME256", "SECP256R1", "P-256", "P256")),
    ("P384", ("SECP384R1", "P-384", "P384")),
    ("P521", ("SECP521R1", "P-521", "P521")),
    ("K256", ("SECP256K1", "P256K1")),
)


def _curve_from_nid_text(text: str) -> Optional[str]:
    """Map NID/curve text to a canonical curve token, or None."""
    upper = (text or "").upper()
    for canonical, spellings in _NID_CURVE_TABLE:
        for spelling in spellings:
            if spelling in upper:
                return canonical
    return None


def _sibling_identifiers(call_node: Node, source: bytes,
                         limit: int = 8) -> tuple:
    """Collect nearby identifier texts around a call node (same statement).

    Walks up to the enclosing expression_statement (C) / expression
    statement equivalent and gathers identifier-like tokens: bare
    identifiers, macro names (preproc_*), and constant references
    (e.g. NID_rsaEncryption, EVP_PKEY_RSA). Used ONLY as disambiguation
    context for generic wrappers — never as standalone findings.
    """
    node = call_node
    for _ in range(4):
        parent = node.parent
        if parent is None:
            break
        node = parent
        if node.type in ("expression_statement", "declaration",
                         "assignment_expression", "init_declarator"):
            break
    found: list[str] = []
    stack = [node]
    while stack and len(found) < limit * 2:
        current = stack.pop()
        if current.type in ("identifier", "type_identifier"):
            text = _node_text(current, source).strip()
            if text and text not in found and len(text) < 80:
                found.append(text)
        for child in reversed(current.children):
            stack.append(child)
    return tuple(found[:limit])


def _unwrap_string_literal(node: Node, source: bytes) -> Optional[str]:
    """
    Extract the string value from a string literal node across all grammars.

    Python:     string → string_start string_content string_end
    Java:       string_literal → '"' string_fragment '"'
    JavaScript: string → text (or template_string)
    C:          string_literal → '"' ... '"'
    """
    # Python string_content child
    for child in node.children:
        if child.type in ("string_content", "string_fragment"):
            return _node_text(child, source)

    # JavaScript / C: raw string text with quotes stripped
    text = _node_text(node, source).strip()
    if (text.startswith('"') and text.endswith('"')) or \
       (text.startswith("'") and text.endswith("'")):
        return text[1:-1]

    return None


def _get_positional_args(args_node: Node, source: bytes) -> list[str]:
    """
    Extract positional argument text values from an argument list node.

    For string literals, returns the unquoted content.
    For other node types, returns the raw text.
    Skips commas, parens, and keyword arguments.
    """
    if args_node is None:
        return []

    values: list[str] = []
    for child in args_node.children:
        if child.type in (",", "(", ")", "[", "]", ";"):
            continue
        # Skip keyword args (Python named_argument, Java — not applicable)
        if child.type in ("keyword_argument", "named_argument", "assignment"):
            continue

        # String literal nodes — unwrap to get the content
        if child.type in ("string", "string_literal"):
            val = _unwrap_string_literal(child, source)
            if val is not None:
                values.append(val)
            continue

        text = _node_text(child, source).strip()
        # Bare quoted text (fallback)
        if text and (
            (text.startswith('"') and text.endswith('"')) or
            (text.startswith("'") and text.endswith("'"))
        ):
            values.append(text[1:-1])
        elif text:
            values.append(text)

    return values


def _extract_integer_arg(args_node: Node, source: bytes,
                          arg_index: int) -> Optional[int]:
    """
    Try to extract an integer literal from the given positional arg index.
    Returns None if the argument is not a simple integer literal.
    """
    if args_node is None:
        return None

    positional = [
        c for c in args_node.children
        if c.type not in (",", "(", ")", "keyword_argument", "named_argument",
                          "assignment", ";")
    ]
    if arg_index >= len(positional):
        return None

    target = positional[arg_index]
    # Python: integer node; C/Java: number_literal / decimal_integer_literal
    if target.type in ("integer", "number_literal", "decimal_integer_literal",
                        "decimal_floating_point_literal"):
        text = _node_text(target, source).strip()
        try:
            return int(text)
        except ValueError:
            return None

    # Fallback: try parsing whatever text is there
    text = _node_text(target, source).strip()
    try:
        return int(text)
    except ValueError:
        return None


def _extract_kwarg_integer(args_node: Node, source: bytes,
                            kwarg_name: str) -> Optional[int]:
    """Try to extract an integer from a keyword argument by name."""
    if args_node is None:
        return None

    for child in args_node.children:
        if child.type in ("keyword_argument", "named_argument", "assignment"):
            # keyword_argument structure: identifier = value
            children = [c for c in child.children if c.type != "="]
            if len(children) >= 2:
                name_text = _node_text(children[0], source).strip()
                val_text = _node_text(children[1], source).strip()
                if name_text == kwarg_name:
                    try:
                        return int(val_text)
                    except ValueError:
                        return None
    return None


# ── Match type implementations ────────────────────────────────────────────────

def match_call_chain(call_node: Node, source: bytes,
                     rule: DetectionRule) -> Optional[RawMatch]:
    """
    Match a call_chain rule: module.function() pattern.

    A call_chain rule requires:
      - The function name matches rule.match.function
      - If rule.match.module is specified, the receiver matches it

    A rule function ending in "*" is a PREFIX rule: any called function
    whose name starts with the prefix matches (e.g. "OQS_KEM_ml_kem_*"
    matches OQS_KEM_ml_kem_512_keypair, OQS_KEM_ml_kem_768_encaps, ...).
    Prefix rules carry the family's canonical algorithm/purpose; they are
    config data, not scanner logic.

    Example rules: hashlib.md5(), RSA.generate(), DES.new()
    """
    spec: MatchSpec = rule.match

    fn_name = _get_function_name(call_node, source)

    is_prefix = spec.function.endswith("*")
    if is_prefix:
        if not fn_name.startswith(spec.function[:-1]):
            return None
    elif fn_name != spec.function:
        return None

    # If a module is required, verify it
    if spec.module is not None:
        module_name = _get_module_name(call_node, source)
        if module_name != spec.module:
            return None

    # Key size extraction (best-effort)
    key_size: Optional[int] = None
    curve: Optional[str] = None

    kse = rule.key_size_extraction
    if kse is not None:
        args_node = _get_arguments_node(call_node)
        if kse.arg_index is not None:
            key_size = _extract_integer_arg(args_node, source, kse.arg_index)
        elif kse.kwarg_name is not None:
            key_size = _extract_kwarg_integer(args_node, source, kse.kwarg_name)

    # If rule has a fixed key_size_bits, use it as fallback
    if key_size is None and rule.key_size_bits is not None:
        key_size = rule.key_size_bits

    # For EC key generation, try to extract the curve name from first arg
    if rule.algorithm == "ECDSA" and spec.function == "generate_private_key":
        args_node = _get_arguments_node(call_node)
        if args_node:
            args = _get_positional_args(args_node, source)
            if args:
                # args[0] is typically ec.SECP256R1() — extract the curve class name
                curve_text = args[0]
                for curve_name in ("SECP256R1", "SECP384R1", "SECP521R1",
                                   "SECP256K1", "BRAINPOOLP256R1"):
                    if curve_name in curve_text.upper():
                        curve = curve_name
                        break

    # Named-curve NID argument extraction (C): EC_KEY_new_by_curve_name(NID)
    # and EVP_PKEY_CTX_set_ec_paramgen_curve_nid(NID) carry the curve in
    # arg 0 as a bare NID constant. Map to canonical curve names.
    if spec.function in ("EC_KEY_new_by_curve_name",
                         "EVP_PKEY_CTX_set_ec_paramgen_curve_nid"):
        args_node = _get_arguments_node(call_node)
        if args_node:
            args = _get_positional_args(args_node, source)
            if args:
                curve = _curve_from_nid_text(args[0]) or curve

    # NID constant rules (R-403..R-406) carry the curve in the symbol itself.
    if rule.rule_id in ("R-403", "R-404", "R-405", "R-406") or (
            rule.match.symbol_kind == "constant"
            and spec.function.startswith("NID_")):
        curve = _curve_from_nid_text(spec.function) or curve

    snippet = _node_text(call_node, source)
    return RawMatch(
        rule=rule,
        start_row=call_node.start_point[0],
        start_col=call_node.start_point[1],
        end_row=call_node.end_point[0],
        end_col=call_node.end_point[1],
        snippet=snippet[:512],  # cap snippet length
        extracted_key_size=key_size,
        extracted_curve=curve,
        observed_symbol=fn_name,
        sibling_symbols=_sibling_identifiers(call_node, source),
    )


def match_call_with_arg(call_node: Node, source: bytes,
                        rule: DetectionRule) -> Optional[RawMatch]:
    """
    Match a call_with_arg rule: function called with a specific string literal.

    Requires:
      - Function name matches rule.match.function
      - The argument at arg_index is a string literal matching one of arg_values

    Example rules: hashlib.new('md5'), MessageDigest.getInstance('SHA-1')
    """
    spec: MatchSpec = rule.match

    fn_name = _get_function_name(call_node, source)
    if fn_name != spec.function:
        return None

    args_node = _get_arguments_node(call_node)
    if args_node is None:
        return None

    positional_args = _get_positional_args(args_node, source)

    arg_idx = spec.arg_index if spec.arg_index is not None else 0
    if arg_idx >= len(positional_args):
        return None

    actual_value = positional_args[arg_idx]
    if actual_value not in spec.arg_values:
        return None

    snippet = _node_text(call_node, source)
    return RawMatch(
        rule=rule,
        start_row=call_node.start_point[0],
        start_col=call_node.start_point[1],
        end_row=call_node.end_point[0],
        end_col=call_node.end_point[1],
        snippet=snippet[:512],
        extracted_key_size=rule.key_size_bits,
        observed_symbol=_get_function_name(call_node, source),
        sibling_symbols=_sibling_identifiers(call_node, source),
    )


# ── C symbol matcher (Phase 3: OpenSSL-style evidence) ───────────────────────

# Bare-identifier node types that can carry crypto evidence in C beyond
# direct calls: macro invocations, NID/OBJ constants, dispatch-table
# function references. Comments and string contents are NEVER visited
# (the walker only yields these node types).
_C_SYMBOL_NODE_TYPES = frozenset({
    "identifier",
    "type_identifier",
})


def match_c_symbol(node: Node, source: bytes,
                   rule: DetectionRule) -> Optional[RawMatch]:
    """
    Match a c_symbol rule: a bare C identifier occurrence.

    Unlike call_chain (which requires a call_expression), this fires on
    the identifier node itself — covering macro uses (EVP_PKEY_RSA as a
    constant arg), NID constants (NID_rsaEncryption), and dispatch-table
    references (ossl_rsa_keygen). The identifier must still be a real AST
    identifier node: occurrences inside comments or string literals are
    different node types and never match.

    symbol_kind filters the syntactic role:
      call     — identifier that is the callee of a call_expression
      macro    — identifier under a preproc_* node
      constant — UPPER_CASE identifier not in call position (NID_/OBJ_ style)
      any      — any identifier occurrence (default)
    """
    spec: MatchSpec = rule.match
    if node.type not in _C_SYMBOL_NODE_TYPES:
        return None
    text = _node_text(node, source).strip()
    if not text:
        return None

    is_prefix = spec.function.endswith("*")
    if is_prefix:
        if not text.startswith(spec.function[:-1]):
            return None
    elif text != spec.function:
        return None

    kind = (spec.symbol_kind or "any").lower()
    parent = node.parent
    parent_type = parent.type if parent is not None else ""
    grandparent = parent.parent if parent is not None else None
    grandparent_type = grandparent.type if grandparent is not None else ""

    # Precise callee check: identifier is the function child of call_expression
    is_call_callee = (
        parent_type == "call_expression"
        and bool(parent.children)
        and parent.children[0] is node
    )
    under_preproc = "preproc" in parent_type or "preproc" in grandparent_type

    if kind == "call" and not is_call_callee:
        return None
    if kind == "macro" and not under_preproc:
        return None
    if kind == "constant":
        if is_call_callee:
            return None
        if not (text == text.upper() or text.startswith(("NID_", "OBJ_", "EVP_"))):
            return None

    snippet_node = parent if parent is not None else node
    snippet = _node_text(snippet_node, source)
    return RawMatch(
        rule=rule,
        start_row=node.start_point[0],
        start_col=node.start_point[1],
        end_row=node.end_point[0],
        end_col=node.end_point[1],
        snippet=snippet[:512],
        observed_symbol=text,
        sibling_symbols=_sibling_identifiers(node, source),
    )


# ── Dispatcher ────────────────────────────────────────────────────────────────

MATCHERS = {
    "call_chain": match_call_chain,
    "call_with_arg": match_call_with_arg,
    "c_symbol": match_c_symbol,
}


def try_match(call_node: Node, source: bytes,
              rule: DetectionRule) -> Optional[RawMatch]:
    """
    Dispatch to the correct matcher for the rule's match_type.
    Returns None if the node does not match this rule.
    """
    matcher = MATCHERS.get(rule.match_type)
    if matcher is None:
        logger.warning("Unknown match_type '%s' for rule %s — skipping",
                       rule.match_type, rule.rule_id)
        return None
    try:
        return matcher(call_node, source, rule)
    except Exception as exc:
        logger.debug("Error matching rule %s against node: %s", rule.rule_id, exc)
        return None
