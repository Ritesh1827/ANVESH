"""
Unit tests — rule_loader.py

Tests that the YAML rules load correctly, validate their constraints,
and that language filtering works.
"""

from __future__ import annotations

import pytest
from pathlib import Path

from ecdat.discovery.rule_loader import (
    load_rules,
    rules_for_language,
    DetectionRule,
    MatchSpec,
)

# Path to the real rules file
RULES_PATH = Path(__file__).parent.parent.parent.parent / "config" / "detection_rules.yaml"


class TestRuleLoader:
    def test_rules_file_exists(self):
        assert RULES_PATH.exists(), f"Rules file not found: {RULES_PATH}"

    def test_loads_rules_successfully(self):
        rules = load_rules(RULES_PATH)
        assert len(rules) > 0

    def test_all_rules_have_required_fields(self):
        rules = load_rules(RULES_PATH)
        for r in rules:
            assert r.rule_id, f"Empty rule_id in rule: {r}"
            assert r.algorithm, f"Empty algorithm in {r.rule_id}"
            assert r.purpose, f"Empty purpose in {r.rule_id}"
            assert 0.0 <= r.confidence <= 1.0, f"Confidence out of range in {r.rule_id}"
            assert len(r.languages) > 0, f"No languages in {r.rule_id}"
            assert r.match_type in ("call_chain", "call_with_arg", "c_symbol"), \
                f"Invalid match_type '{r.match_type}' in {r.rule_id}"
            assert isinstance(r.match, MatchSpec), f"match not a MatchSpec in {r.rule_id}"

    def test_no_duplicate_rule_ids(self):
        rules = load_rules(RULES_PATH)
        ids = [r.rule_id for r in rules]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found"

    def test_python_rules_exist(self):
        rules = load_rules(RULES_PATH)
        py = rules_for_language(rules, "python")
        assert len(py) > 5

    def test_java_rules_exist(self):
        rules = load_rules(RULES_PATH)
        java = rules_for_language(rules, "java")
        assert len(java) >= 2

    def test_javascript_rules_exist(self):
        rules = load_rules(RULES_PATH)
        js = rules_for_language(rules, "javascript")
        assert len(js) >= 2

    def test_c_rules_exist(self):
        rules = load_rules(RULES_PATH)
        c_rules = rules_for_language(rules, "c")
        assert len(c_rules) >= 2

    def test_language_filter_is_case_insensitive(self):
        rules = load_rules(RULES_PATH)
        py_lower = rules_for_language(rules, "python")
        py_upper = rules_for_language(rules, "PYTHON")
        assert len(py_lower) == len(py_upper)

    def test_r001_rsa_generate_rule(self):
        rules = load_rules(RULES_PATH)
        r001 = next((r for r in rules if r.rule_id == "R-001"), None)
        assert r001 is not None, "Rule R-001 not found"
        assert r001.algorithm == "RSA"
        assert r001.purpose == "key_establishment"
        assert r001.match.function == "generate"
        assert r001.match.module == "RSA"
        assert "python" in r001.languages

    def test_r007_hashlib_md5_rule(self):
        rules = load_rules(RULES_PATH)
        r007 = next((r for r in rules if r.rule_id == "R-007"), None)
        assert r007 is not None
        assert r007.algorithm == "MD5"
        assert r007.purpose == "hashing"
        assert r007.match.module == "hashlib"
        assert r007.match.function == "md5"

    def test_missing_file_raises_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_rules(tmp_path / "nonexistent.yaml")

    def test_invalid_yaml_raises_value_error(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("not_rules: true")
        with pytest.raises(ValueError, match="rules"):
            load_rules(bad)

    def test_duplicate_rule_id_raises_value_error(self, tmp_path):
        dup = tmp_path / "dup.yaml"
        content = (
            'version: "1.0"\n'
            'rules:\n'
            '  - rule_id: "R-DUP"\n'
            '    description: "First"\n'
            '    algorithm: "MD5"\n'
            '    purpose: "hashing"\n'
            '    confidence: 0.9\n'
            '    severity: "high"\n'
            '    languages: ["python"]\n'
            '    match_type: "call_chain"\n'
            '    match:\n'
            '      function: "md5"\n'
            '      module: "hashlib"\n'
            '  - rule_id: "R-DUP"\n'
            '    description: "Second same ID"\n'
            '    algorithm: "SHA-1"\n'
            '    purpose: "hashing"\n'
            '    confidence: 0.9\n'
            '    severity: "medium"\n'
            '    languages: ["python"]\n'
            '    match_type: "call_chain"\n'
            '    match:\n'
            '      function: "sha1"\n'
            '      module: "hashlib"\n'
        )
        dup.write_text(content, encoding="utf-8")
        with pytest.raises(ValueError, match="Duplicate"):
            load_rules(dup)

    def test_out_of_range_confidence_raises(self, tmp_path):
        bad = tmp_path / "bad_conf.yaml"
        bad.write_text("""
version: "1.0"
rules:
  - rule_id: "R-BAD"
    description: "Bad confidence"
    algorithm: "MD5"
    purpose: "hashing"
    confidence: 1.5
    severity: "high"
    languages: ["python"]
    match_type: "call_chain"
    match:
      function: "md5"
""")
        with pytest.raises(ValueError, match="confidence"):
            load_rules(bad)
