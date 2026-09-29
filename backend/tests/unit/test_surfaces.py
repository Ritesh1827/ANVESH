"""Tests for the binary, container, and infrastructure discovery surfaces.

Each surface is verified end to end through run_pipeline: findings flow
through the shared inventory, config-driven ClassificationEngine, and
ReachabilityEngine (reachable=None for binary/container; reachable=True
for live TLS-probe assets), and register in Discovery Completeness.
"""

from pathlib import Path

from ecdat.discovery.binary_scanner import (
    load_fingerprint_rules,
    scan_binary_file,
)
from ecdat.discovery.container_scanner import scan_container_refs
from ecdat.discovery.infra_scanner import parse_endpoint
from ecdat.pipeline import run_pipeline

REPO_ROOT = Path(__file__).parent.parent.parent.parent


def _copy_openssl_binary(tmp_path: Path) -> Path:
    import shutil

    candidates = [
        Path(r"C:\Program Files\Git\mingw64\bin\libcrypto-3-x64.dll"),
        Path(r"C:\Program Files\Git\usr\bin\msys-crypto-3.dll"),
    ]
    for candidate in candidates:
        if candidate.exists():
            dest = tmp_path / candidate.name
            shutil.copy(candidate, dest)
            return dest
    raise FileNotFoundError("No OpenSSL binary available for the binary test")


def test_binary_fingerprint_rules_are_config_driven() -> None:
    rules = load_fingerprint_rules()
    assert len(rules) >= 10
    assert all(rule.rule_id.startswith("B-") for rule in rules)
    assert all(0.0 <= rule.confidence <= 1.0 for rule in rules)


def test_binary_scan_finds_openssl_symbols(tmp_path) -> None:
    binary = _copy_openssl_binary(tmp_path)
    result = scan_binary_file(binary, scan_id="test-binary-1", relative_to=tmp_path)
    assert result is not None
    assert result.asset_count >= 1
    assert all(a.source_surface == "binary" for a in result.assets)
    assert all(a.evidence.detection_method.value == "binary_fingerprint"
               for a in result.assets)
    assert all(a.reachable is None for a in result.assets)


def test_binary_pipeline_end_to_end(tmp_path) -> None:
    binary = _copy_openssl_binary(tmp_path)
    result = run_pipeline(
        target_path=REPO_ROOT / "test_repos" / "demo_app",
        binary_paths=[binary],
        scan_id="test-binary-pipe",
        run_migration=True,
        run_cbom_export=True,
    )
    binary_assets = [a for a in result.scored_assets if a.source_surface == "binary"]
    assert binary_assets
    assert all(a.classification is not None for a in binary_assets)
    assert all(a.reachable is None for a in binary_assets)
    assert all(a.risk is not None for a in binary_assets)
    assert all(a.recommendation is not None for a in binary_assets)
    assert result.completeness is not None
    surfaces = {c.surface: c.status for c in result.completeness.surface_coverage}
    assert surfaces.get("binary") == "scanned"


def test_container_manifest_inspection(tmp_path) -> None:
    context = tmp_path / "imgctx"
    context.mkdir()
    (context / "Dockerfile").write_text("FROM python:3.12\nRUN pip install cryptography==42\n")
    (context / "requirements.txt").write_text("cryptography==42.0.0\nboto3\n")
    results = scan_container_refs(
        ["myapp:1.0"], scan_id="test-container-1",
        local_contexts={"myapp:1.0": context},
    )
    assert results.total_assets >= 1
    assert all(a.source_surface == "container" for a in results.all_assets)
    assert all(a.evidence.detection_method.value == "layer_inspection"
               for a in results.all_assets)
    assert all(a.reachable is None for a in results.all_assets)


def test_container_bare_ref_recorded_without_findings() -> None:
    results = scan_container_refs(["nginx:1.25"], scan_id="test-container-2")
    assert results.total_assets == 0
    assert results.refs_recorded_only == 1


def test_container_pipeline_end_to_end(tmp_path) -> None:
    context = tmp_path / "imgctx"
    context.mkdir()
    (context / "requirements.txt").write_text("cryptography==42.0.0\n")
    result = run_pipeline(
        target_path=REPO_ROOT / "test_repos" / "demo_app",
        container_refs=["myapp:1.0"],
        container_contexts={"myapp:1.0": context},
        scan_id="test-container-pipe",
    )
    container_assets = [
        a for a in result.scored_assets if a.source_surface == "container"]
    assert container_assets
    assert all(a.classification is not None for a in container_assets)
    assert all(a.reachable is None for a in container_assets)


def test_endpoint_parsing_rejects_garbage() -> None:
    assert parse_endpoint("example.com") == ("example.com", 443)
    assert parse_endpoint("example.com:8443") == ("example.com", 8443)
    import pytest

    for bad in ["", "http://example.com", "host:notaport", "host:99999", "a b"]:
        with pytest.raises(ValueError):
            parse_endpoint(bad)
