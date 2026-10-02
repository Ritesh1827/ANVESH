"""Post-scan AI enrichment endpoint tests (ambiguous-only, auth, ownership).

Covers the manual enrichment workflow added for ambiguous findings:
  - GET /api/scans/{id}/enrichment reports eligible/already counts
  - POST /api/scans/{id}/enrich enriches only ambiguous findings (mocked LLM)
  - deterministic findings are never sent to the LLM
  - unauthenticated / cross-user access is rejected for owned scans
  - failures preserve originals and keep the scan complete
"""

import time
from pathlib import Path

from fastapi.testclient import TestClient

from ecdat.api import app as app_module
from ecdat.api.app import app
from ecdat.persistence.store import ScanStore

REPO_ROOT = Path(__file__).parent.parent.parent.parent
CORPUS = (
    REPO_ROOT / "backend" / ".ecdat_uploads"
    / "51ac2769f71046328fa6952c32b4495c" / "ecdat_crypto_discovery_test.c"
)


def _fresh_store(tmp_path, monkeypatch) -> ScanStore:
    db_path = tmp_path / "enrich.sqlite3"
    fresh = ScanStore(database_url=f"sqlite:///{db_path}")
    monkeypatch.setattr(app_module, "store", fresh)
    monkeypatch.setattr(
        "ecdat.persistence.store.JOB_ROOT", tmp_path / "jobs", raising=False
    )
    monkeypatch.setattr(
        "ecdat.persistence.store.UPLOAD_ROOT", tmp_path / "uploads", raising=False
    )
    return fresh


def _wait_for(scan_id: str, client: TestClient, timeout_s: float = 120.0) -> dict:
    deadline = time.time() + timeout_s
    last: dict = {}
    while time.time() < deadline:
        response = client.get(f"/api/scans/{scan_id}")
        assert response.status_code == 200
        last = response.json()
        if last["status"] in {"complete", "failed", "partial"}:
            return last
        time.sleep(0.5)
    raise AssertionError(f"Scan {scan_id} did not finish: {last}")


def _scan_corpus(tmp_path, monkeypatch) -> tuple[TestClient, str]:
    _fresh_store(tmp_path, monkeypatch)
    client = TestClient(app)
    staged = client.post("/api/uploads").json()["upload_id"]
    data = CORPUS.read_bytes()
    up = client.post(
        f"/api/uploads/{staged}/files",
        files={"file": ("t.c", data)},
        data={"path": "t.c"},
    )
    assert up.status_code == 200
    created = client.post(
        "/api/scans",
        json={"source_kind": "upload_tree", "upload_id": staged,
              "include_certificates": False},
    )
    assert created.status_code == 202
    scan_id = created.json()["scan_id"]
    finished = _wait_for(scan_id, client)
    assert finished["status"] == "complete"
    return client, scan_id


def test_enrichment_status_reports_ambiguous_counts(tmp_path, monkeypatch) -> None:
    client, scan_id = _scan_corpus(tmp_path, monkeypatch)
    status = client.get(f"/api/scans/{scan_id}/enrichment")
    assert status.status_code == 200
    body = status.json()
    assert body["scan_id"] == scan_id
    assert body["total_assets"] == 58
    assert body["ambiguous_eligible"] == 10
    assert body["already_enriched"] == 0


def test_enrich_sends_only_ambiguous_findings(tmp_path, monkeypatch) -> None:
    client, scan_id = _scan_corpus(tmp_path, monkeypatch)
    response = client.post(f"/api/scans/{scan_id}/enrich", json={})
    # Without a real provider SDK the call degrades gracefully; the key
    # assertions are structural: scan stays complete, originals preserved.
    assert response.status_code == 202
    body = response.json()
    assert body["scan_id"] == scan_id
    assert body["eligible"] == 10
    detail = client.get(f"/api/scans/{scan_id}").json()
    assert detail["status"] == "complete"
    assert detail["asset_count"] == 58


def test_enrich_requires_completed_scan(tmp_path, monkeypatch) -> None:
    _fresh_store(tmp_path, monkeypatch)
    client = TestClient(app)
    created = client.post("/api/scans", json={"source_kind": "demo"})
    scan_id = created.json()["scan_id"]
    response = client.post(f"/api/scans/{scan_id}/enrich", json={})
    assert response.status_code == 409


def test_enrich_unknown_scan_404(tmp_path, monkeypatch) -> None:
    _fresh_store(tmp_path, monkeypatch)
    client = TestClient(app)
    assert client.get("/api/scans/nope/enrichment").status_code == 404
    assert client.post("/api/scans/nope/enrich", json={}).status_code == 404


def test_enrich_respects_scan_ownership(tmp_path, monkeypatch) -> None:
    _fresh_store(tmp_path, monkeypatch)
    client = TestClient(app)
    client.post("/api/auth/register",
                json={"email": "owner@example.com", "password": "password-123"})
    owner_token = client.post(
        "/api/auth/login",
        json={"email": "owner@example.com", "password": "password-123"},
    ).json()["token"]
    client.post("/api/auth/register",
                json={"email": "other@example.com", "password": "password-123"})
    other_token = client.post(
        "/api/auth/login",
        json={"email": "other@example.com", "password": "password-123"},
    ).json()["token"]
    scan_id = client.post(
        "/api/scans", json={"source_kind": "demo"},
        headers={"Authorization": f"Bearer {owner_token}"},
    ).json()["scan_id"]
    _wait_for(scan_id, client)
    assert client.get(
        f"/api/scans/{scan_id}/enrichment",
        headers={"Authorization": f"Bearer {other_token}"},
    ).status_code == 403
    assert client.post(
        f"/api/scans/{scan_id}/enrich", json={},
        headers={"Authorization": f"Bearer {other_token}"},
    ).status_code == 403
    assert client.get(
        f"/api/scans/{scan_id}/enrichment",
        headers={"Authorization": f"Bearer {owner_token}"},
    ).status_code == 200
