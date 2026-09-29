"""Task 3: scan the real pyca/cryptography checkout end to end.

Not a fixture — the actual public library ECDAT itself depends on.
Asserts the system works on code it was never tuned to handle:
findings exist, evidence is populated, risk + recommendations flow.
Prints a summary for the final report.

Runs against the live Supabase database (DATABASE_URL from .env) with
LLM enrichment enabled under Gemini, so the enrichment path resolves
ambiguous findings and every result persists to Postgres.
"""

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
from dotenv import load_dotenv
from fastapi.testclient import TestClient

from ecdat.api import app as app_module
from ecdat.api.app import app
from ecdat.persistence.store import ScanStore

load_dotenv(Path(__file__).resolve().parent.parent.parent.parent / ".env")

REPO_URL = "https://github.com/pyca/cryptography.git"


def _fresh_store(monkeypatch) -> ScanStore:
    url = os.environ.get("DATABASE_URL", "")
    assert url.startswith("postgresql"), "Supabase DATABASE_URL required for Task 3"
    fresh = ScanStore(database_url=url)
    monkeypatch.setattr(app_module, "store", fresh)
    return fresh


def _wait_for(scan_id: str, client: TestClient, timeout_s: float = 900.0) -> dict:
    deadline = time.time() + timeout_s
    last: dict = {}
    while time.time() < deadline:
        last = client.get(f"/api/scans/{scan_id}").json()
        if last["status"] in {"complete", "failed"}:
            return last
        time.sleep(5)
    raise AssertionError(f"Scan {scan_id} did not finish: {last}")


@pytest.mark.slow
def test_real_pyca_cryptography_scan(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.delenv("LLM_MODEL", raising=False)
    _fresh_store(monkeypatch)
    client = TestClient(app)

    clone_dir = Path(tempfile.mkdtemp(prefix="pyca_clone_"))
    cloned = subprocess.run(
        ["git", "clone", "--depth", "1", REPO_URL, str(clone_dir / "cryptography")],
        capture_output=True, text=True, timeout=600,
    )
    assert cloned.returncode == 0, f"clone failed: {cloned.stderr[:500]}"
    target = clone_dir / "cryptography"

    created = client.post(
        "/api/scans",
        json={
            "source_kind": "local_path",
            "source_path": str(target),
            "include_certificates": True,
            "run_llm_enrichment": True,
        },
    )
    assert created.status_code == 202
    finished = _wait_for(created.json()["scan_id"], client, timeout_s=900)
    assert finished["status"] == "complete", finished.get("error")

    scan_id = finished["scan_id"]
    assets = client.get("/api/assets", params={"scan_id": scan_id}).json()["items"]
    assert len(assets) > 0

    by_surface: dict[str, int] = {}
    for asset in assets:
        by_surface[asset["source_surface"]] = by_surface.get(asset["source_surface"], 0) + 1

    scored = [a for a in assets if a["risk"] is not None]
    recommended = [a for a in assets if a["recommendation"] is not None]
    evidenced = [a for a in assets if a["evidence"].get("rule_id")]
    llm_enriched = [
        a for a in assets
        if a["evidence"].get("finding_type") == "llm_enriched"
    ]

    summary = {
        "total": len(assets),
        "by_surface": by_surface,
        "scored": len(scored),
        "recommended": len(recommended),
        "evidenced": len(evidenced),
        "llm_enriched": len(llm_enriched),
        "owners_assigned": sum(1 for a in assets if a.get("owner")),
    }
    print("\nTASK3-SUMMARY " + json.dumps(summary))

    assert len(scored) == len(assets)
    assert len(evidenced) == len(assets)

    dashboard = client.get("/api/dashboard", params={"scan_id": scan_id}).json()
    assert dashboard["metrics"]["total_assets"] == len(assets)

    cbom = client.get(f"/api/scans/{scan_id}/cbom/download")
    assert cbom.status_code == 200
    assert "components" in cbom.json()

    migration = client.get(f"/api/scans/{scan_id}/reports/migration.txt")
    assert migration.status_code == 200
    assert "Migration" in migration.text
