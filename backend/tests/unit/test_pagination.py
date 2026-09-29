"""Pagination + dashboard-summary contract tests (scalability read path)."""

import time

from fastapi.testclient import TestClient

from ecdat.api import app as app_module
from ecdat.api.app import app
from ecdat.persistence.store import ScanStore


def _fresh_store(tmp_path, monkeypatch) -> ScanStore:
    db_path = tmp_path / "paged.sqlite3"
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
        last = client.get(f"/api/scans/{scan_id}").json()
        if last["status"] in {"complete", "failed"}:
            return last
        time.sleep(0.5)
    raise AssertionError(f"Scan {scan_id} did not finish: {last}")


def _demo_scan_id(client: TestClient) -> str:
    created = client.post("/api/scans", json={"source_kind": "demo"})
    assert created.status_code == 202
    finished = _wait_for(created.json()["scan_id"], client)
    assert finished["status"] == "complete"
    return finished["scan_id"]


def test_assets_pagination_contract(tmp_path, monkeypatch) -> None:
    _fresh_store(tmp_path, monkeypatch)
    client = TestClient(app)
    scan_id = _demo_scan_id(client)

    first = client.get("/api/assets", params={"scan_id": scan_id, "limit": 5, "offset": 0})
    assert first.status_code == 200
    body = first.json()
    assert body["page"]["total"] >= len(body["items"])
    assert body["page"]["limit"] == 5
    assert body["page"]["offset"] == 0
    assert len(body["items"]) == 5

    second = client.get("/api/assets", params={"scan_id": scan_id, "limit": 5, "offset": 5})
    assert second.status_code == 200
    first_ids = {a["asset_id"] for a in body["items"]}
    second_ids = {a["asset_id"] for a in second.json()["items"]}
    assert not first_ids & second_ids
    assert second.json()["page"]["total"] == body["page"]["total"]


def test_filters_apply_across_full_dataset_not_page(tmp_path, monkeypatch) -> None:
    _fresh_store(tmp_path, monkeypatch)
    client = TestClient(app)
    scan_id = _demo_scan_id(client)

    unfiltered = client.get("/api/assets", params={"scan_id": scan_id, "limit": 500})
    total = unfiltered.json()["page"]["total"]

    p1 = client.get(
        "/api/assets",
        params={"scan_id": scan_id, "priority": "P1", "limit": 500},
    ).json()
    assert p1["page"]["total"] <= total
    assert all((a.get("risk") or {}).get("priority") == "P1" for a in p1["items"])
    # Every P1 in the scan appears even though the default page is 50:
    assert p1["page"]["total"] == len(p1["items"])

    rsa_page1 = client.get(
        "/api/assets",
        params={"scan_id": scan_id, "algorithm": "RSA", "limit": 2, "offset": 0},
    ).json()
    rsa_page2 = client.get(
        "/api/assets",
        params={"scan_id": scan_id, "algorithm": "RSA", "limit": 2, "offset": 2},
    ).json()
    assert rsa_page1["page"]["total"] == rsa_page2["page"]["total"]
    assert all("RSA" in a["algorithm"] for a in rsa_page1["items"] + rsa_page2["items"])

    certs = client.get(
        "/api/certificates", params={"scan_id": scan_id, "limit": 500}).json()
    assert all(a["source_surface"] == "certificate" for a in certs["items"])


def test_dashboard_summary_matches_full_scan_counts(tmp_path, monkeypatch) -> None:
    _fresh_store(tmp_path, monkeypatch)
    client = TestClient(app)
    scan_id = _demo_scan_id(client)

    summary = client.get("/api/dashboard", params={"scan_id": scan_id}).json()
    full = client.get("/api/assets", params={"scan_id": scan_id, "limit": 500}).json()

    assert summary["metrics"]["total_assets"] == full["page"]["total"]
    assert summary["metrics"]["total_assets"] == len(full["items"])
    assert summary["priority_counts"]["P1"] == summary["metrics"]["p1_count"]
    assert len(summary["top_critical_findings"]) <= 10
    assert all(
        (a.get("risk") or {}).get("priority") == "P1"
        for a in summary["top_critical_findings"]
    )
    assert "classification_counts" in summary


def test_risk_and_reachability_paginate(tmp_path, monkeypatch) -> None:
    _fresh_store(tmp_path, monkeypatch)
    client = TestClient(app)
    scan_id = _demo_scan_id(client)

    risk = client.get(
        "/api/risk-priorities", params={"scan_id": scan_id, "limit": 5}).json()
    assert risk["page"]["limit"] == 5
    assert len(risk["items"]) <= 5

    reach = client.get(
        "/api/reachability", params={"scan_id": scan_id, "limit": 5}).json()
    assert reach["summary"] is not None
    assert reach["page"]["total"] >= len(reach["items"])


def test_cbom_and_reports_still_serve_complete_dataset(
    tmp_path, monkeypatch
) -> None:
    _fresh_store(tmp_path, monkeypatch)
    client = TestClient(app)
    scan_id = _demo_scan_id(client)

    total = client.get(
        "/api/assets", params={"scan_id": scan_id, "limit": 1}).json()["page"]["total"]
    assert total > 1

    download = client.get(f"/api/scans/{scan_id}/cbom/download")
    assert download.status_code == 200
    assert len(download.json()["components"]) == total

    cbom = client.get("/api/cbom", params={"scan_id": scan_id}).json()
    assert cbom["component_count"] == total
    assert len(cbom["export"]["assets"]) == total

    migration = client.get(f"/api/scans/{scan_id}/reports/migration.txt")
    assert migration.status_code == 200
    certificates = client.get(f"/api/scans/{scan_id}/reports/certificates.txt")
    assert certificates.status_code == 200


def test_backfill_populates_classification_on_old_rows(
    tmp_path, monkeypatch
) -> None:
    store = _fresh_store(tmp_path, monkeypatch)
    client = TestClient(app)
    scan_id = _demo_scan_id(client)

    from ecdat.persistence import database
    from ecdat.persistence.models import AssetRecord

    with database.session() as session:
        session.query(AssetRecord).filter(
            AssetRecord.scan_id == scan_id).update(
            {AssetRecord.classification: None})
        session.commit()

    assert store.backfill_asset_columns(scan_id) > 0

    filtered = client.get(
        "/api/assets",
        params={"scan_id": scan_id, "classification": "application", "limit": 500},
    ).json()
    assert filtered["page"]["total"] > 0
    assert all(a["classification"] == "application" for a in filtered["items"])
