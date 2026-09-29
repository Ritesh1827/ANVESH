"""Contract tests for the FastAPI adapter over the persistent scan-job API."""

import time

from fastapi.testclient import TestClient

from ecdat.api import app as app_module
from ecdat.api.app import app
from ecdat.persistence.store import ScanStore

REPO_ROOT_DB = None


def _fresh_store(tmp_path, monkeypatch) -> ScanStore:
    db_path = tmp_path / "api_ecdat.sqlite3"
    fresh = ScanStore(database_url=f"sqlite:///{db_path}")
    monkeypatch.setattr(app_module, "store", fresh)
    monkeypatch.setattr(
        "ecdat.persistence.store.JOB_ROOT", tmp_path / "jobs", raising=False
    )
    monkeypatch.setattr(
        "ecdat.persistence.store.UPLOAD_ROOT", tmp_path / "uploads", raising=False
    )
    return fresh


def _wait_for(scan_id: str, client: TestClient, timeout_s: float = 60.0) -> dict:
    deadline = time.time() + timeout_s
    last: dict = {}
    while time.time() < deadline:
        response = client.get(f"/api/scans/{scan_id}")
        assert response.status_code == 200
        last = response.json()
        if last["status"] in {"complete", "failed"}:
            return last
        time.sleep(0.25)
    raise AssertionError(f"Scan {scan_id} did not finish in time: {last}")


def _start_demo_scan(client: TestClient) -> str:
    created = client.post("/api/scans", json={"source_kind": "demo"})
    assert created.status_code == 202
    return created.json()["scan_id"]


def test_health_endpoint_is_available(tmp_path, monkeypatch) -> None:
    _fresh_store(tmp_path, monkeypatch)
    response = TestClient(app).get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_dashboard_and_assets_are_backed_by_real_pipeline_data(tmp_path, monkeypatch) -> None:
    _fresh_store(tmp_path, monkeypatch)
    client = TestClient(app)

    scan_id = _start_demo_scan(client)
    finished = _wait_for(scan_id, client)
    assert finished["status"] == "complete"

    dashboard = client.get("/api/dashboard", params={"scan_id": scan_id})
    assets = client.get("/api/assets", params={"scan_id": scan_id})

    assert dashboard.status_code == 200
    assert assets.status_code == 200
    assert dashboard.json()["metrics"]["total_assets"] == len(assets.json()["items"])
    assert dashboard.json()["metrics"]["p1_count"] == dashboard.json()["priority_counts"]["P1"]
    assert all("evidence" in asset and "risk" in asset for asset in assets.json()["items"])


def test_cbom_and_migration_endpoints_use_current_pipeline_result(tmp_path, monkeypatch) -> None:
    _fresh_store(tmp_path, monkeypatch)
    client = TestClient(app)

    scan_id = _start_demo_scan(client)
    finished = _wait_for(scan_id, client)
    assert finished["status"] == "complete"

    migration = client.get("/api/migration", params={"scan_id": scan_id})
    download = client.get(f"/api/scans/{scan_id}/cbom/download")

    assert migration.status_code == 200
    assert migration.json()["items"]
    assert download.status_code == 200
    assert "components" in download.json()

    regenerated = client.post(f"/api/scans/{scan_id}/cbom/export")
    assert regenerated.status_code == 200
    assert regenerated.json()["component_count"] == len(
        regenerated.json()["export"]["assets"]
    )
