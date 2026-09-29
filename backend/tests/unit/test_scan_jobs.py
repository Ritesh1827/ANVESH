"""Contract tests for the persistent, asynchronous scan-job API."""

import time
from pathlib import Path

from fastapi.testclient import TestClient

from ecdat.api import app as app_module
from ecdat.api.app import app
from ecdat.persistence.store import ScanStore

REPO_ROOT = Path(__file__).parent.parent.parent.parent


def _fresh_store(tmp_path: Path, monkeypatch) -> ScanStore:
    db_path = tmp_path / "test_ecdat.sqlite3"
    monkeypatch.setenv("ECDAT_TEST_DB", str(db_path))
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


def test_health_endpoint_is_available(tmp_path, monkeypatch) -> None:
    _fresh_store(tmp_path, monkeypatch)
    response = TestClient(app).get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_demo_scan_runs_async_and_persists(tmp_path, monkeypatch) -> None:
    _fresh_store(tmp_path, monkeypatch)
    client = TestClient(app)

    created = client.post("/api/scans", json={"source_kind": "demo"})
    assert created.status_code == 202
    scan_id = created.json()["scan_id"]
    assert created.json()["status"] in {"pending", "running"}

    finished = _wait_for(scan_id, client)
    assert finished["status"] == "complete"
    assert finished["asset_count"] > 0

    dashboard = client.get("/api/dashboard", params={"scan_id": scan_id})
    assets = client.get("/api/assets", params={"scan_id": scan_id})
    assert dashboard.status_code == 200
    assert assets.status_code == 200
    assert dashboard.json()["metrics"]["total_assets"] == len(assets.json()["items"])
    assert dashboard.json()["metrics"]["p1_count"] == dashboard.json()["priority_counts"]["P1"]
    assert all("evidence" in asset and "risk" in asset for asset in assets.json()["items"])


def test_local_path_scan_uses_user_supplied_input(tmp_path, monkeypatch) -> None:
    _fresh_store(tmp_path, monkeypatch)
    client = TestClient(app)
    source = tmp_path / "user_code"
    source.mkdir()
    (source / "crypto_mod.py").write_text(
        "import hashlib\nhashlib.sha256(b'data')\n"
    )

    created = client.post(
        "/api/scans",
        json={"source_kind": "local_path", "source_path": str(source),
              "include_certificates": False},
    )
    assert created.status_code == 202
    finished = _wait_for(created.json()["scan_id"], client)
    assert finished["status"] == "complete"
    assert finished["target"] == str(source.resolve())
    assert finished["asset_count"] >= 1

    assets = client.get(
        "/api/assets", params={"scan_id": finished["scan_id"]}
    ).json()["items"]
    assert assets
    assert all(asset["evidence"]["location"]["file_path"].endswith("crypto_mod.py")
               for asset in assets)


def test_invalid_inputs_rejected_with_400(tmp_path, monkeypatch) -> None:
    _fresh_store(tmp_path, monkeypatch)
    client = TestClient(app)

    assert client.post(
        "/api/scans", json={"source_kind": "local_path", "source_path": "/no/such/dir"}
    ).status_code == 400
    assert client.post(
        "/api/scans", json={"source_kind": "repo_url", "repo_url": "ftp://evil/x"}
    ).status_code == 400
    assert client.post(
        "/api/scans", json={"source_kind": "bogus"}
    ).status_code in {400, 422}


def test_scan_history_lists_multiple_scans(tmp_path, monkeypatch) -> None:
    _fresh_store(tmp_path, monkeypatch)
    client = TestClient(app)

    first = client.post("/api/scans", json={"source_kind": "demo"}).json()
    second = client.post("/api/scans", json={"source_kind": "demo"}).json()
    _wait_for(first["scan_id"], client)
    _wait_for(second["scan_id"], client)

    listing = client.get("/api/scans").json()["items"]
    ids = {item["scan_id"] for item in listing}
    assert first["scan_id"] in ids and second["scan_id"] in ids

    reports = client.get("/api/reports").json()
    assert reports["history_supported"] is True
    assert any(item["id"] == "cbom" for item in reports["items"])


def test_persistence_survives_store_recreation(tmp_path, monkeypatch) -> None:
    """Results live in the database, not in memory: a new store sees them."""
    db_path = tmp_path / "persist.sqlite3"
    url = f"sqlite:///{db_path}"
    first_store = ScanStore(database_url=url)
    monkeypatch.setattr(app_module, "store", first_store)
    monkeypatch.setattr(
        "ecdat.persistence.store.JOB_ROOT", tmp_path / "jobs", raising=False
    )
    monkeypatch.setattr(
        "ecdat.persistence.store.UPLOAD_ROOT", tmp_path / "uploads", raising=False
    )
    client = TestClient(app)
    created = client.post("/api/scans", json={"source_kind": "demo"})
    scan_id = created.json()["scan_id"]
    finished = _wait_for(scan_id, client)
    assert finished["status"] == "complete"

    second_store = ScanStore(database_url=url)
    monkeypatch.setattr(app_module, "store", second_store)
    reread = client.get(f"/api/scans/{scan_id}").json()
    assert reread["status"] == "complete"
    assert reread["asset_count"] == finished["asset_count"]
    reread_assets = client.get("/api/assets", params={"scan_id": scan_id}).json()
    assert len(reread_assets["items"]) == finished["asset_count"]

    reachability = client.get("/api/reachability", params={"scan_id": scan_id}).json()
    assert reachability["summary"]["graph_node_count"] > 0
    assert (
        reachability["summary"]["reachable_count"]
        + reachability["summary"]["unreachable_count"]
        + reachability["summary"]["unknown_count"]
        == finished["asset_count"]
    )


def test_cbom_migration_and_reports_serve_persisted_results(tmp_path, monkeypatch) -> None:
    _fresh_store(tmp_path, monkeypatch)
    client = TestClient(app)

    created = client.post("/api/scans", json={"source_kind": "demo"})
    scan_id = created.json()["scan_id"]
    _wait_for(scan_id, client)

    migration = client.get("/api/migration", params={"scan_id": scan_id})
    download = client.get(f"/api/scans/{scan_id}/cbom/download")
    report = client.get(f"/api/scans/{scan_id}/reports/pipeline.txt")
    migration_report = client.get(f"/api/scans/{scan_id}/reports/migration.txt")
    certificate_report = client.get(f"/api/scans/{scan_id}/reports/certificates.txt")

    assert migration.status_code == 200
    assert migration.json()["items"]
    assert download.status_code == 200
    assert "components" in download.json()
    assert report.status_code == 200
    assert "ECDAT" in report.text
    assert migration_report.status_code == 200
    assert "Migration" in migration_report.text
    assert certificate_report.status_code == 200
    assert "Certificate" in certificate_report.text

    second = client.post("/api/scans", json={"source_kind": "demo"}).json()
    _wait_for(second["scan_id"], client)
    diff = client.get(
        f"/api/scans/{second['scan_id']}/cbom/diff",
        params={"baseline_scan_id": scan_id},
    )
    assert diff.status_code == 200
    assert diff.json()["baseline_scan_id"] == scan_id
    assert diff.json()["current_scan_id"] == second["scan_id"]


def test_upload_tree_scan_accepts_user_files(tmp_path, monkeypatch) -> None:
    _fresh_store(tmp_path, monkeypatch)
    client = TestClient(app)

    staged = client.post("/api/uploads").json()["upload_id"]
    uploaded = client.post(
        f"/api/uploads/{staged}/files",
        files={"file": ("service.py", b"import hashlib\nhashlib.md5(b'x')\n")},
    )
    assert uploaded.status_code == 200

    created = client.post(
        "/api/scans",
        json={"source_kind": "upload_tree", "upload_id": staged,
              "include_certificates": False},
    )
    assert created.status_code == 202
    finished = _wait_for(created.json()["scan_id"], client)
    assert finished["status"] == "complete"
    assert finished["asset_count"] >= 1
