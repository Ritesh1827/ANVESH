"""Tests for real authentication, ownership rules, and the startup reaper."""

import time

from fastapi.testclient import TestClient

from ecdat.api import app as app_module
from ecdat.api.app import app
from ecdat.persistence.auth import AuthStore
from ecdat.persistence.store import ScanStore


def _fresh(tmp_path, monkeypatch):
    db_path = tmp_path / "task2.sqlite3"
    fresh = ScanStore(database_url=f"sqlite:///{db_path}")
    monkeypatch.setattr(app_module, "store", fresh)
    monkeypatch.setattr(app_module, "auth_store", AuthStore())
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
    raise AssertionError(f"Scan {scan_id} did not finish: {last}")


def test_register_login_me_logout_roundtrip(tmp_path, monkeypatch) -> None:
    _fresh(tmp_path, monkeypatch)
    client = TestClient(app)

    created = client.post(
        "/api/auth/register",
        json={"email": "Ada@Example.COM", "password": "correct-horse-1"},
    )
    assert created.status_code == 201

    duplicate = client.post(
        "/api/auth/register",
        json={"email": "ada@example.com", "password": "another-pass-2"},
    )
    assert duplicate.status_code == 409

    bad_login = client.post(
        "/api/auth/login",
        json={"email": "ada@example.com", "password": "wrong-password"},
    )
    assert bad_login.status_code == 401

    logged_in = client.post(
        "/api/auth/login",
        json={"email": "ada@example.com", "password": "correct-horse-1"},
    )
    assert logged_in.status_code == 200
    token = logged_in.json()["token"]
    assert len(token) >= 32

    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "ada@example.com"

    assert client.get("/api/auth/me").status_code == 401

    assert client.post(
        "/api/auth/logout", headers={"Authorization": f"Bearer {token}"}
    ).status_code == 200
    assert client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {token}"}
    ).status_code == 401


def test_passwords_are_bcrypt_hashes_not_plaintext(tmp_path, monkeypatch) -> None:
    store = _fresh(tmp_path, monkeypatch)
    client = TestClient(app)
    client.post(
        "/api/auth/register",
        json={"email": "hash@example.com", "password": "super-secret-9"},
    )
    from ecdat.persistence import database
    from ecdat.persistence.models import UserRecord

    with database.session() as session:
        user = session.query(UserRecord).filter(
            UserRecord.email == "hash@example.com").one()
        assert user.password_hash != "super-secret-9"
        assert user.password_hash.startswith("$2b$")
    assert store is not None


def test_scans_are_attributed_to_users(tmp_path, monkeypatch) -> None:
    _fresh(tmp_path, monkeypatch)
    client = TestClient(app)
    client.post(
        "/api/auth/register",
        json={"email": "owner@example.com", "password": "password-123"},
    )
    token = client.post(
        "/api/auth/login",
        json={"email": "owner@example.com", "password": "password-123"},
    ).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    created = client.post("/api/scans", json={"source_kind": "demo"}, headers=headers)
    assert created.status_code == 202
    detail = client.get(f"/api/scans/{created.json()['scan_id']}", headers=headers).json()
    assert detail["user_id"] is not None


def test_ownership_rules_assign_owners(tmp_path, monkeypatch) -> None:
    _fresh(tmp_path, monkeypatch)
    client = TestClient(app)

    listed = client.get("/api/ownership/rules").json()
    assert listed["items"] == []

    created = client.post(
        "/api/ownership/rules",
        json={"owner": "Platform Team", "priority": 10, "surface": "certificate"},
    )
    assert created.status_code == 201

    bad = client.post("/api/ownership/rules", json={"owner": "  "})
    assert bad.status_code == 400

    scan_id = client.post("/api/scans", json={"source_kind": "demo"}).json()["scan_id"]
    finished = _wait_for(scan_id, client)
    assert finished["status"] == "complete"
    _, assets = client.get("/api/assets", params={"scan_id": scan_id}).json(), None
    assets = client.get("/api/assets", params={"scan_id": scan_id}).json()["items"]
    cert_assets = [a for a in assets if a["source_surface"] == "certificate"]
    assert cert_assets
    assert all(a["owner"] == "Platform Team" for a in cert_assets)

    rule_id = created.json()["id"]
    assert client.delete(f"/api/ownership/rules/{rule_id}").status_code == 200
    assert client.get("/api/ownership/rules").json()["items"] == []


def test_startup_reaper_fails_stale_jobs(tmp_path, monkeypatch) -> None:
    store = _fresh(tmp_path, monkeypatch)
    store._ensure_init()
    from datetime import datetime, timedelta, timezone

    from ecdat.persistence import database
    from ecdat.persistence.models import ScanRecord

    with database.session() as session:
        session.add(ScanRecord(
            id="stale-job-1",
            status="running",
            stage="scanning",
            source_kind="demo",
            target_label="stale",
            include_certificates=False,
            created_at=datetime.now(timezone.utc) - timedelta(hours=2),
            started_at=datetime.now(timezone.utc) - timedelta(hours=2),
        ))
        session.add(ScanRecord(
            id="fresh-job-1",
            status="running",
            stage="scanning",
            source_kind="demo",
            target_label="fresh",
            include_certificates=False,
            created_at=datetime.now(timezone.utc),
            started_at=datetime.now(timezone.utc),
        ))
        session.commit()

    reaped = store.reap_stale_jobs(timeout_s=30 * 60)
    assert reaped == 1
    assert store.get_scan("stale-job-1")["status"] == "failed"
    assert "restarted" in (store.get_scan("stale-job-1")["error"] or "")
    assert store.get_scan("fresh-job-1")["status"] == "running"
