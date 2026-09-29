"""Robustness tests: iterative traversal, per-file guards, partial persistence."""

import sys
from pathlib import Path

import pytest

from ecdat.discovery.source_scanner import _walk_call_nodes, scan_file
from ecdat.engines.call_graph import PythonCallGraphVisitor, extract_file_call_graph
from ecdat.pipeline import run_pipeline


class _FakeNode:
    """Minimal tree-sitter Node stand-in for traversal tests."""

    def __init__(self, node_type: str, children=None):
        self.type = node_type
        self.children = children or []


def _deep_chain(depth: int) -> _FakeNode:
    root: _FakeNode = _FakeNode("call")
    current = root
    for _ in range(depth):
        child = _FakeNode("expression")
        current.children.append(child)
        current = child
    current.children.append(_FakeNode("call"))
    return root


def test_walk_call_nodes_handles_deep_nesting_without_recursion() -> None:
    old_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(200)
    try:
        results: list = []
        _walk_call_nodes(_deep_chain(5000), results)
        assert len(results) == 2
    finally:
        sys.setrecursionlimit(old_limit)


def test_call_graph_visitor_handles_deep_nesting(tmp_path) -> None:
    depth = 3000
    source = ("def f():\n" + "    x = 1\n") * 1
    nested = "def outer():\n"
    for _ in range(depth):
        nested += "    def inner():\n"
    nested += "        pass\n"
    target = tmp_path / "deep.py"
    target.write_text(nested + source)
    old_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(500)
    try:
        graph = extract_file_call_graph(target, relative_to=tmp_path)
    finally:
        sys.setrecursionlimit(old_limit)
    assert graph is not None
    assert any("outer" in fn.qualified_name for fn in graph.functions)


def test_scan_file_skips_deeply_nested_file(tmp_path) -> None:
    from ecdat.discovery.rule_loader import load_rules

    rules = load_rules()
    nested = "x = [" * 20000 + "1" + "]" * 20000 + "\n"
    target = tmp_path / "nested.py"
    target.write_text(nested)
    result = scan_file(target, rules, relative_to=tmp_path)
    assert result is not None


def test_partial_result_persisted_on_stage_failure(tmp_path, monkeypatch) -> None:
    from fastapi.testclient import TestClient

    from ecdat.api import app as app_module
    from ecdat.api.app import app
    from ecdat.persistence.store import ScanStore
    import time

    db_path = tmp_path / "partial.sqlite3"
    fresh = ScanStore(database_url=f"sqlite:///{db_path}")
    monkeypatch.setattr(app_module, "store", fresh)
    monkeypatch.setattr(
        "ecdat.persistence.store.JOB_ROOT", tmp_path / "jobs", raising=False
    )
    monkeypatch.setattr(
        "ecdat.persistence.store.UPLOAD_ROOT", tmp_path / "uploads", raising=False
    )
    client = TestClient(app)

    import ecdat.pipeline as pipeline_module

    real_mosca = pipeline_module.MoscaEngine

    class _BoomMosca(real_mosca):
        def process(self, assets):  # noqa: ANN202
            raise RuntimeError("simulated mosca failure")

    monkeypatch.setattr(pipeline_module, "MoscaEngine", _BoomMosca)
    created = client.post("/api/scans", json={"source_kind": "demo"})
    assert created.status_code == 202
    scan_id = created.json()["scan_id"]
    deadline = time.time() + 60
    last: dict = {}
    while time.time() < deadline:
        last = client.get(f"/api/scans/{scan_id}").json()
        if last["status"] in {"complete", "failed", "partial"}:
            break
        time.sleep(0.5)
    assert last["status"] == "partial", last
    assert last["asset_count"] > 0
    assert "mosca" in (last.get("error") or "")

    assets = client.get("/api/assets", params={"scan_id": scan_id}).json()
    assert assets["page"]["total"] == last["asset_count"]
    dashboard = client.get("/api/dashboard", params={"scan_id": scan_id})
    assert dashboard.status_code == 200
    assert "partial_note" in dashboard.json()


def test_reaper_leaves_partial_alone(tmp_path, monkeypatch) -> None:
    from datetime import datetime, timedelta, timezone

    from ecdat.persistence import database
    from ecdat.persistence.models import ScanRecord
    from ecdat.persistence.store import ScanStore

    db_path = tmp_path / "reap.sqlite3"
    url = f"sqlite:///{db_path}"
    store = ScanStore(database_url=url)
    store._ensure_init()
    with database.session() as session:
        session.add(ScanRecord(
            id="partial-old",
            status="partial",
            stage="partial",
            source_kind="demo",
            target_label="old",
            include_certificates=False,
            created_at=datetime.now(timezone.utc) - timedelta(hours=5),
            started_at=datetime.now(timezone.utc) - timedelta(hours=5),
            completed_at=datetime.now(timezone.utc) - timedelta(hours=5),
        ))
        session.commit()
    assert store.reap_stale_jobs(timeout_s=30 * 60) == 0
    assert store.get_scan("partial-old")["status"] == "partial"


def test_demo_pipeline_reports_completed_stages() -> None:
    from pathlib import Path as _Path

    repo_root = _Path(__file__).parent.parent.parent.parent
    result = run_pipeline(
        target_path=repo_root / "test_repos" / "demo_app",
        cert_paths=[repo_root / "test_repos" / "demo_certs"],
        scan_id="stages-probe",
        run_migration=True,
        run_cbom_export=True,
    )
    assert result.failure_stage is None
    for stage in ("source_discovery", "inventory", "classification",
                  "reachability", "mosca", "recommendations"):
        assert stage in result.completed_stages
