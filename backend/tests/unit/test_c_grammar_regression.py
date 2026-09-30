"""Focused regression test: C grammar must be present and productive.

Production symptom: an uploaded .c file staged fine, the scan completed,
but produced 0 assets — consistent with tree-sitter-c being absent in the
deployed environment (undeclared dependency) so scan_file returned None
and the scan completed with no findings and no explanation.

Covers:
  - C grammar loads (_get_language returns a Language, not None).
  - A staged .c file with one covered crypto API is discovered by
    scan_directory (not counted as skipped, no missing grammar).
  - At least one crypto finding is produced for that file.
  - Missing-grammar files surface via DirectoryScanResult.missing_grammars
    and the completeness engine marks source_code SKIPPED (not silent).
"""

from pathlib import Path

import pytest

from ecdat.discovery import source_scanner
from ecdat.discovery.rule_loader import load_rules
from ecdat.discovery.source_scanner import scan_directory

C_PROBE = (
    "#include <openssl/evp.h>\n"
    "void f(void) {\n"
    "  const EVP_MD *m = EVP_sha256();\n"
    "  (void)m;\n"
    "}\n"
)


def test_c_grammar_loads() -> None:
    lang = source_scanner._get_language("c")
    assert lang is not None, (
        "tree-sitter-c is not installed; Render installs only declared "
        "dependencies — it must be pinned in backend/pyproject.toml "
        "and backend/requirements.txt."
    )


def test_staged_c_file_produces_crypto_finding(tmp_path: Path) -> None:
    target = tmp_path / "crypto_probe.c"
    target.write_text(C_PROBE)
    result = scan_directory(tmp_path, load_rules())
    assert result.missing_grammars == []
    assert result.files_scanned == 1
    assert result.files_skipped == 0
    assert result.total_matches >= 1
    paths = [str(fr.file_path) for fr in result.file_results]
    assert any(p.endswith("crypto_probe.c") for p in paths)


def test_all_supported_grammars_declared() -> None:
    import tomllib

    pyproject = (
        Path(__file__).resolve().parents[3] / "backend" / "pyproject.toml"
    )
    with open(pyproject, "rb") as handle:
        declared = " ".join(
            tomllib.load(handle)["project"]["dependencies"]
        )
    for package in (
        "tree-sitter-python",
        "tree-sitter-c",
        "tree-sitter-java",
        "tree-sitter-javascript",
    ):
        assert package in declared, (
            f"{package} must be declared in backend/pyproject.toml"
        )


def test_missing_grammar_surfaces_as_warning(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "probe.c"
    target.write_text(C_PROBE)
    monkeypatch.setattr(
        source_scanner, "_get_language", lambda name: None)
    result = scan_directory(tmp_path, load_rules())
    assert result.files_scanned == 0
    assert result.files_skipped == 1
    assert result.missing_grammars == ["c"]


def test_missing_grammar_marks_surface_skipped(tmp_path: Path) -> None:
    from ecdat.engines.completeness_engine import (
        DiscoveryCompletenessEngine,
        SurfaceStatus,
    )

    target = tmp_path / "probe.c"
    target.write_text(C_PROBE)
    result = scan_directory(tmp_path, load_rules())
    assert result.missing_grammars == []
    # Simulate the production condition on an otherwise healthy result.
    result.missing_grammars = ["c"]
    engine = DiscoveryCompletenessEngine(
        scan_result=result, assets=[], scanned_surfaces=["source_code"])
    computed = engine.compute()
    source = next(
        sc for sc in computed.surface_coverage if sc.surface == "source_code")
    assert source.status == SurfaceStatus.SKIPPED
    assert "tree-sitter" in (source.notes or "").lower()
