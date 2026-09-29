"""
Unit tests — ast_matchers.py

Tests individual matcher functions against hand-crafted tree-sitter AST nodes
parsed from minimal code snippets. Validates that:
  - call_chain rules match the right call patterns
  - call_with_arg rules match on correct string literal args
  - false positives (comments, wrong names) return None
  - key size extraction works for integer literals
  - module name matching is correct
"""

from __future__ import annotations

import pytest
from pathlib import Path
from tree_sitter import Language, Parser
import tree_sitter_python as tsp

from ecdat.discovery.rule_loader import load_rules, rules_for_language
from ecdat.discovery.ast_matchers import (
    try_match,
    _get_function_name,
    _get_module_name,
    RawMatch,
)
from ecdat.discovery.source_scanner import scan_file, _walk_call_nodes

RULES_PATH = Path(__file__).parent.parent.parent.parent / "config" / "detection_rules.yaml"

# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_python(code: str):
    lang = Language(tsp.language())
    parser = Parser(lang)
    return parser.parse(code.encode()), code.encode()


def _collect_call_nodes(code: str):
    tree, src = _parse_python(code)
    calls = []
    _walk_call_nodes(tree.root_node, calls)
    return calls, src


def _get_rule(rule_id: str):
    rules = load_rules(RULES_PATH)
    r = next((r for r in rules if r.rule_id == rule_id), None)
    assert r is not None, f"Rule {rule_id} not found"
    return r


# ── Function name extraction ──────────────────────────────────────────────────

class TestFunctionNameExtraction:
    def test_bare_function_call(self):
        calls, src = _collect_call_nodes("foo()")
        assert calls
        name = _get_function_name(calls[0], src)
        assert name == "foo"

    def test_module_dot_function(self):
        calls, src = _collect_call_nodes("hashlib.md5()")
        assert calls
        name = _get_function_name(calls[0], src)
        assert name == "md5"

    def test_chained_call(self):
        calls, src = _collect_call_nodes("RSA.generate(2048)")
        assert calls
        name = _get_function_name(calls[0], src)
        assert name == "generate"

    def test_module_name_extracted(self):
        calls, src = _collect_call_nodes("hashlib.md5()")
        assert calls
        mod = _get_module_name(calls[0], src)
        assert mod == "hashlib"

    def test_bare_call_module_is_none(self):
        calls, src = _collect_call_nodes("md5()")
        assert calls
        mod = _get_module_name(calls[0], src)
        assert mod is None


# ── call_chain matcher ────────────────────────────────────────────────────────

class TestCallChainMatcher:
    def test_hashlib_md5_matches_r007(self):
        rule = _get_rule("R-007")
        calls, src = _collect_call_nodes("hashlib.md5(data)")
        assert calls
        result = try_match(calls[0], src, rule)
        assert result is not None
        assert result.rule.rule_id == "R-007"

    def test_hashlib_sha1_matches_r017(self):
        rule = _get_rule("R-017")
        calls, src = _collect_call_nodes("hashlib.sha1(data)")
        assert calls
        result = try_match(calls[0], src, rule)
        assert result is not None

    def test_hashlib_sha256_matches_r008(self):
        rule = _get_rule("R-008")
        calls, src = _collect_call_nodes("hashlib.sha256(data)")
        assert calls
        result = try_match(calls[0], src, rule)
        assert result is not None

    def test_rsa_generate_matches_r001(self):
        rule = _get_rule("R-001")
        calls, src = _collect_call_nodes("RSA.generate(2048)")
        assert calls
        result = try_match(calls[0], src, rule)
        assert result is not None
        assert result.rule.rule_id == "R-001"

    def test_wrong_module_does_not_match(self):
        rule = _get_rule("R-007")   # hashlib.md5
        calls, src = _collect_call_nodes("other.md5(data)")
        assert calls
        result = try_match(calls[0], src, rule)
        assert result is None, "Should not match with wrong module"

    def test_wrong_function_does_not_match(self):
        rule = _get_rule("R-007")   # hashlib.md5
        calls, src = _collect_call_nodes("hashlib.sha256(data)")
        assert calls
        result = try_match(calls[0], src, rule)
        assert result is None

    def test_des_new_matches_r004(self):
        rule = _get_rule("R-004")
        calls, src = _collect_call_nodes("DES.new(key, DES.MODE_ECB)")
        assert calls
        result = try_match(calls[0], src, rule)
        assert result is not None
        assert result.rule.rule_id == "R-004"

    def test_aes_new_matches_r005(self):
        rule = _get_rule("R-005")
        calls, src = _collect_call_nodes("AES.new(key, AES.MODE_ECB)")
        assert calls
        result = try_match(calls[0], src, rule)
        assert result is not None


# ── Key size extraction ───────────────────────────────────────────────────────

class TestKeySizeExtraction:
    def test_rsa_generate_extracts_2048(self):
        rule = _get_rule("R-001")
        calls, src = _collect_call_nodes("RSA.generate(2048)")
        result = try_match(calls[0], src, rule)
        assert result is not None
        assert result.extracted_key_size == 2048

    def test_rsa_generate_extracts_4096(self):
        rule = _get_rule("R-001")
        calls, src = _collect_call_nodes("RSA.generate(4096)")
        result = try_match(calls[0], src, rule)
        assert result is not None
        assert result.extracted_key_size == 4096

    def test_non_integer_arg_gives_none_key_size(self):
        rule = _get_rule("R-001")
        calls, src = _collect_call_nodes("RSA.generate(key_bits)")
        result = try_match(calls[0], src, rule)
        assert result is not None
        # Variable reference — cannot extract integer
        assert result.extracted_key_size is None

    def test_des_fixed_key_size_56(self):
        rule = _get_rule("R-004")
        calls, src = _collect_call_nodes("DES.new(key, DES.MODE_ECB)")
        result = try_match(calls[0], src, rule)
        assert result is not None
        assert result.extracted_key_size == 56   # Fixed in rule config


# ── call_with_arg matcher ─────────────────────────────────────────────────────

class TestCallWithArgMatcher:
    def test_hashlib_new_md5_matches_r021(self):
        rule = _get_rule("R-021")
        calls, src = _collect_call_nodes("hashlib.new('md5')")
        assert calls
        # hashlib.new() creates a nested call — find the right node
        matches = [try_match(c, src, rule) for c in calls]
        matched = [m for m in matches if m is not None]
        assert len(matched) >= 1

    def test_hashlib_new_sha1_matches_r022(self):
        rule = _get_rule("R-022")
        calls, src = _collect_call_nodes("hashlib.new('sha1')")
        matches = [try_match(c, src, rule) for c in calls]
        matched = [m for m in matches if m is not None]
        assert len(matched) >= 1

    def test_hashlib_new_wrong_arg_no_match(self):
        rule = _get_rule("R-021")   # md5 only
        calls, src = _collect_call_nodes("hashlib.new('sha256')")
        matches = [try_match(c, src, rule) for c in calls]
        matched = [m for m in matches if m is not None]
        assert len(matched) == 0

    def test_match_returns_snippet(self):
        rule = _get_rule("R-007")
        calls, src = _collect_call_nodes("hashlib.md5(data)")
        result = try_match(calls[0], src, rule)
        assert result is not None
        assert "hashlib.md5" in result.snippet


# ── False positive prevention ─────────────────────────────────────────────────

class TestFalsePositivePrevention:
    def test_algorithm_name_in_comment_not_matched(self):
        """RSA in a comment must not match any crypto rule."""
        rule = _get_rule("R-007")
        code = "# The system uses RSA-2048 for authentication\nx = 1"
        calls, src = _collect_call_nodes(code)
        matches = [try_match(c, src, rule) for c in calls]
        matched = [m for m in matches if m is not None]
        # Comments produce no call_expression nodes and no crypto findings
        assert len(matched) == 0

    def test_algorithm_name_in_string_literal_not_matched(self):
        """String assignment containing algorithm name is not a call."""
        rule = _get_rule("R-007")
        calls, src = _collect_call_nodes('LOG_LABEL = "sha256_audit_log"')
        matches = [try_match(c, src, rule) for c in calls]
        matched = [m for m in matches if m is not None]
        assert len(matched) == 0

    def test_import_statement_not_matched(self):
        """An import line alone produces no call nodes to match."""
        rule = _get_rule("R-007")
        calls, src = _collect_call_nodes("import hashlib")
        matches = [try_match(c, src, rule) for c in calls]
        matched = [m for m in matches if m is not None]
        assert len(matched) == 0

    def test_variable_named_md5_not_matched(self):
        """Variable assignment with 'md5' in name is not a crypto call."""
        rule = _get_rule("R-007")
        calls, src = _collect_call_nodes("md5_value = stored_hash")
        matches = [try_match(c, src, rule) for c in calls]
        matched = [m for m in matches if m is not None]
        assert len(matched) == 0


# ── Match coordinates ─────────────────────────────────────────────────────────

class TestMatchCoordinates:
    def test_match_reports_correct_row(self):
        rule = _get_rule("R-007")
        code = "import hashlib\nhashlib.md5(data)"
        calls, src = _collect_call_nodes(code)
        matches = [try_match(c, src, rule) for c in calls]
        matched = [m for m in matches if m is not None]
        assert matched
        # hashlib.md5 is on line index 1 (0-based), so row=1
        assert matched[0].start_row == 1

    def test_match_on_first_line(self):
        rule = _get_rule("R-007")
        calls, src = _collect_call_nodes("hashlib.md5(data)")
        result = try_match(calls[0], src, rule)
        assert result is not None
        assert result.start_row == 0   # first line, 0-based
