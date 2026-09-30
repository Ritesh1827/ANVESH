"""HTTP API for running and inspecting persistent ECDAT scan jobs.

Every scan is a background job persisted in the database (pending →
running → complete/failed) with its full result set keyed by scan ID.
All responses are derived from stored scan records — nothing is held only
in memory, and nothing is recomputed per request.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal, Optional

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[3] / ".env")

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field

from ecdat import __version__
from ecdat.persistence.auth import AuthError, AuthStore
from ecdat.schemas import CBOMExport
from ecdat.persistence.store import (
    MAX_UPLOAD_BYTES,
    ScanInputError,
    ScanStore,
    stage_upload_tree,
    write_upload_file,
)

import logging

logger = logging.getLogger("uvicorn.error")

DATABASE_URL = os.environ.get("DATABASE_URL")

store = ScanStore(database_url=DATABASE_URL)
auth_store = AuthStore()

app = FastAPI(
    title="ECDAT API",
    version=__version__,
    description="Read-only advisory API backed by persistent ECDAT scan jobs.",
)

# CORS: allow Vercel deployment origin(s), explicit ALLOWED_ORIGINS env var, and local dev.
_vercel_url = os.environ.get("VERCEL_URL", "").strip().rstrip("/")
_allowed_origins_env = os.environ.get("ALLOWED_ORIGINS", "").strip()

_origins: list[str] = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
if _vercel_url:
    _url = _vercel_url if _vercel_url.startswith("http") else f"https://{_vercel_url}"
    if _url not in _origins:
        _origins.append(_url)

if _allowed_origins_env:
    for raw in _allowed_origins_env.split(","):
        item = raw.strip().rstrip("/")
        if not item:
            continue
        if not item.startswith("http://") and not item.startswith("https://"):
            item = f"https://{item}"
        if item not in _origins:
            _origins.append(item)

# Allow any Vercel project deployment subdomain:
# e.g. anvesh-iota.vercel.app, anvesh-h9h4pvvuu-ritesh1827s-projects.vercel.app, anvesh.vercel.app
CORS_ALLOW_ORIGIN_REGEX = r"https://anvesh(-[a-zA-Z0-9-]+)?\.vercel\.app"

logger.info(f"CORS allowed origins: {_origins}")
logger.info(f"CORS allow origin regex: {CORS_ALLOW_ORIGIN_REGEX}")
print(f"CORS allowed origins: {_origins}", flush=True)
print(f"CORS allow origin regex: {CORS_ALLOW_ORIGIN_REGEX}", flush=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_origin_regex=CORS_ALLOW_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/cors-info")
def get_cors_info() -> dict[str, Any]:
    """Returns active CORS configuration for verification."""
    return {
        "allowed_origins": _origins,
        "allow_origin_regex": CORS_ALLOW_ORIGIN_REGEX,
        "allowed_origins_env": os.environ.get("ALLOWED_ORIGINS", ""),
        "vercel_url_env": os.environ.get("VERCEL_URL", ""),
    }



class RunScanRequest(BaseModel):
    """User-supplied scan input. At least one input surface is required."""

    source_kind: Literal["demo", "local_path", "repo_url", "upload_tree"] = "demo"
    source_path: Optional[str] = None
    repo_url: Optional[str] = None
    upload_id: Optional[str] = None
    include_certificates: bool = True
    certificate_paths: list[str] = Field(default_factory=list)
    certificate_upload_id: Optional[str] = None
    binary_refs: list[str] = Field(default_factory=list)
    container_refs: list[str] = Field(default_factory=list)
    infrastructure_endpoints: list[str] = Field(default_factory=list)
    run_llm_enrichment: bool = False


def _not_found(scan_id: str) -> HTTPException:
    return HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")


def _get_scan_or_404(scan_id: str) -> dict:
    try:
        return store.get_scan(scan_id)
    except KeyError:
        raise _not_found(scan_id) from None


def _require_complete(scan: dict) -> dict:
    if scan["status"] == "failed":
        raise HTTPException(
            status_code=500,
            detail=f"Scan {scan['scan_id']} failed: {scan.get('error') or 'unknown error'}",
        )
    if scan["status"] not in ("complete", "partial"):
        raise HTTPException(
            status_code=409,
            detail=f"Scan {scan['scan_id']} is {scan['status']}: {scan.get('stage') or ''}",
        )
    return scan


def _partial_note(scan: dict) -> Optional[str]:
    if scan["status"] == "partial":
        return (
            f"Partial results: enrichment stopped before completion "
            f"({scan.get('error') or 'stage failure'}). "
            f"Findings below are complete through the last finished stage."
        )
    return None


def _assets_to_cbom_export(scan_id: str, assets: list[Any]) -> CBOMExport:
    """Wrap persisted assets in a minimal CBOMExport for version-diffing."""
    from ecdat import __version__ as ecdat_version
    from ecdat.schemas import CBOMMetadata

    return CBOMExport(
        metadata=CBOMMetadata(
            ecdat_version=ecdat_version,
            scan_id=scan_id,
            scanned_targets=[],
        ),
        assets=assets,
    )


def _scan_summary(scan: dict) -> dict:
    return {
        "scan_id": scan["scan_id"],
        "target": scan["target"],
        "status": scan["status"],
        "stage": scan.get("stage"),
        "source_kind": scan.get("source_kind"),
        "completed_at": scan["completed_at"],
        "asset_count": scan["asset_count"],
        "certificate_asset_count": scan["certificate_asset_count"],
    }


def _priority_counts(scan: dict) -> dict[str, int]:
    counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    counts.update(scan.get("priority_counts") or {})
    return counts


# ── Authentication ─────────────────────────────────────────────────────────

AUTH_ENABLED = os.environ.get("ECDAT_AUTH", "optional").lower()


def _bearer_token(request: Request) -> Optional[str]:
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip() or None
    return None


def _current_user(request: Request) -> Optional[dict]:
    return auth_store.get_user_by_token(_bearer_token(request))


def _require_user(request: Request) -> dict:
    user = _current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


def _maybe_user(request: Request) -> Optional[dict]:
    """Attach the user when a valid token is present; enforce when required."""
    user = _current_user(request)
    if user is None and AUTH_ENABLED == "required":
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


class RegisterRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/api/auth/register", status_code=201)
def register(request: RegisterRequest) -> dict:
    """Create a real user account backed by the database."""
    try:
        return auth_store.register(request.email, request.password)
    except AuthError as exc:
        status = 409 if "already exists" in str(exc) else 400
        raise HTTPException(status_code=status, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Register endpoint error: %s", exc)
        print(f"Register endpoint error: {exc}", flush=True)
        raise HTTPException(status_code=500, detail=f"Internal auth error: {exc}") from exc


@app.post("/api/auth/login")
def login(request: LoginRequest) -> dict:
    """Verify credentials and issue a bearer session token."""
    try:
        return auth_store.login(request.email, request.password)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Login endpoint error: %s", exc)
        print(f"Login endpoint error: {exc}", flush=True)
        raise HTTPException(status_code=500, detail=f"Internal auth error: {exc}") from exc


@app.post("/api/auth/logout")
def logout(request: Request) -> dict:
    """Revoke the caller's session token."""
    token = _bearer_token(request)
    if token:
        auth_store.logout(token)
    return {"ok": True}


@app.get("/api/auth/me")
def me(request: Request) -> dict:
    """Return the account bound to the caller's bearer token."""
    return _require_user(request)


@app.get("/api/health")
def health() -> dict:
    """Return service liveness; no scan is started for this check."""
    return {"status": "ok", "service": "ecdat", "version": __version__}


@app.post("/api/uploads", status_code=201)
def create_upload() -> dict:
    """Create a staging area for source-tree or certificate file uploads."""
    upload_id = stage_upload_tree()
    return {"upload_id": upload_id}


@app.post("/api/uploads/{upload_id}/files")
async def upload_file(
    upload_id: str,
    file: UploadFile = File(...),
    path: Optional[str] = Form(default=None),
) -> dict:
    """Stage one uploaded file under a previously created upload id."""
    relative = path or (file.filename or "")
    data = await file.read()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Uploaded file exceeds the size limit.")
    try:
        stored = write_upload_file(upload_id, relative, data)
    except ScanInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Unknown upload_id: {upload_id}") from None
    return {"upload_id": upload_id, "path": stored, "size_bytes": len(data)}


@app.post("/api/scans", status_code=202)
def run_scan(request: RunScanRequest, http_request: Request) -> dict:
    """Accept user-supplied scan input and start a background scan job."""
    user = _maybe_user(http_request)
    if request.source_kind == "demo":
        pass
    elif request.source_kind == "local_path" and not request.source_path:
        raise HTTPException(status_code=400, detail="source_path is required for local_path scans.")
    elif request.source_kind == "repo_url" and not request.repo_url:
        raise HTTPException(status_code=400, detail="repo_url is required for repo_url scans.")
    elif request.source_kind == "upload_tree" and not request.upload_id:
        raise HTTPException(status_code=400, detail="upload_id is required for upload_tree scans.")
    try:
        scan = store.create_scan(
            source_kind=request.source_kind,
            source_path=request.source_path,
            repo_url=request.repo_url,
            upload_id=request.upload_id,
            include_certificates=request.include_certificates,
            certificate_paths=request.certificate_paths,
            certificate_upload_id=request.certificate_upload_id,
            binary_refs=request.binary_refs,
            container_refs=request.container_refs,
            infrastructure_endpoints=request.infrastructure_endpoints,
            user_id=user["user_id"] if user else None,
            run_llm_enrichment=request.run_llm_enrichment,
        )
    except ScanInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover - defensive HTTP translation
        raise HTTPException(status_code=500, detail=f"Could not start scan: {exc}") from exc
    return _scan_summary(scan)


@app.get("/api/scans")
def list_scans(request: Request, limit: int = 50) -> dict:
    """List scan jobs, most recent first (scoped to the caller when signed in)."""
    user = _maybe_user(request)
    scans = store.list_scans(
        limit=limit, user_id=user["user_id"] if user else None)
    return {"items": [_scan_summary(scan) for scan in scans]}


@app.get("/api/scans/current")
def current_scan() -> dict:
    """Return the most recent scan job (starts a demo scan when none exists)."""
    scans = store.list_scans(limit=1)
    if not scans:
        try:
            scan = store.create_scan(source_kind="demo", include_certificates=True)
        except Exception as exc:  # pragma: no cover - defensive HTTP translation
            raise HTTPException(status_code=500, detail=f"Could not start scan: {exc}") from exc
        return _scan_summary(scan)
    return _scan_summary(scans[0])


@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: str) -> dict:
    """Return status, inputs, and summary for one scan job."""
    return _get_scan_or_404(scan_id)


@app.get("/api/dashboard")
def dashboard(scan_id: Optional[str] = None) -> dict:
    """Return overview metrics, priority counts, findings, and completeness.

    Lightweight: counts come from SQL aggregates over indexed columns and
    only the top critical findings are hydrated — O(top_n) regardless of
    inventory size. Paginated asset reads live on /api/assets.
    """
    if scan_id is not None:
        scan = _require_complete(_get_scan_or_404(scan_id))
    else:
        scan = _require_complete(_get_scan_or_404(current_scan()["scan_id"]))
    _, summary = store.get_dashboard_summary(scan["scan_id"])
    response = {"scan": _scan_summary(scan), **summary}
    note = _partial_note(scan)
    if note is not None:
        response["partial_note"] = note
    return response


@app.get("/api/assets")
def assets(
    scan_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    algorithm: Optional[str] = None,
    purpose: Optional[str] = None,
    classification: Optional[str] = None,
    priority: Optional[str] = None,
    source_surface: Optional[str] = None,
    sort: str = "location",
) -> dict:
    """Page through enriched ``CryptoAsset`` records with server-side filters.

    Filters apply in SQL across the FULL dataset — never just the loaded
    page. Full unpaginated reads remain available to CBOM/report downloads,
    which always serve the complete dataset.
    """
    if scan_id is not None:
        scan = _require_complete(_get_scan_or_404(scan_id))
    else:
        scan = _require_complete(_get_scan_or_404(current_scan()["scan_id"]))
    _, items, page = store.query_assets(
        scan["scan_id"],
        limit=limit,
        offset=offset,
        algorithm=algorithm,
        purpose=purpose,
        classification=classification,
        priority=priority,
        source_surface=source_surface,
        sort=sort,
    )
    response: dict = {"scan": _scan_summary(scan), "items": items, "page": page}
    note = _partial_note(scan)
    if note is not None:
        response["partial_note"] = note
    return response


@app.get("/api/risk-priorities")
def risk_priorities(
    scan_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    priority: Optional[str] = None,
) -> dict:
    """Page through asset records ordered by real Mosca priority (P1–P4)."""
    if scan_id is not None:
        scan = _require_complete(_get_scan_or_404(scan_id))
    else:
        scan = _require_complete(_get_scan_or_404(current_scan()["scan_id"]))
    order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    _, items, page = store.query_assets(
        scan["scan_id"],
        limit=limit,
        offset=offset,
        priority=priority,
        sort="priority",
    )
    items = sorted(
        items,
        key=lambda asset: (
            order.get((asset.get("risk") or {}).get("priority", "P4"), 4),
            asset.get("location", ""),
        ),
    )
    return {"scan": _scan_summary(scan), "items": items, "page": page}


@app.get("/api/reachability")
def reachability(
    scan_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Return the persisted reachability summary plus one page of assets."""
    if scan_id is not None:
        scan = _require_complete(_get_scan_or_404(scan_id))
    else:
        scan = _require_complete(_get_scan_or_404(current_scan()["scan_id"]))
    summary = scan.get("reachability")
    _, items, page = store.query_assets(
        scan["scan_id"], limit=limit, offset=offset, sort="location")
    if summary is None:
        summary = {
            "total_assets": page["total"],
            "reachable_count": 0,
            "unreachable_count": 0,
            "unknown_count": page["total"],
            "entry_points_found": [],
            "graph_node_count": 0,
            "graph_edge_count": 0,
            "reachability_rate": 0.0,
        }
    return {"scan": _scan_summary(scan), "summary": summary, "items": items,
            "page": page}


@app.get("/api/migration")
def migration(scan_id: Optional[str] = None) -> dict:
    """Return real persisted migration roadmaps paired with asset records."""
    if scan_id is not None:
        scan = _require_complete(_get_scan_or_404(scan_id))
    else:
        scan = _require_complete(_get_scan_or_404(current_scan()["scan_id"]))
    _, items = store.get_roadmaps(scan["scan_id"])
    return {"scan": _scan_summary(scan), "items": items}


@app.get("/api/certificates")
def certificates(
    scan_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Page through certificate-surface asset records only."""
    if scan_id is not None:
        scan = _require_complete(_get_scan_or_404(scan_id))
    else:
        scan = _require_complete(_get_scan_or_404(current_scan()["scan_id"]))
    _, items, page = store.query_assets(
        scan["scan_id"],
        limit=limit,
        offset=offset,
        source_surface="certificate",
        sort="location",
    )
    return {"scan": _scan_summary(scan), "items": items, "page": page}


@app.get("/api/cbom")
def cbom(scan_id: Optional[str] = None) -> dict:
    """Return CBOM metadata and quality fields from the persisted export."""
    if scan_id is not None:
        scan = _require_complete(_get_scan_or_404(scan_id))
    else:
        scan = _require_complete(_get_scan_or_404(current_scan()["scan_id"]))
    try:
        _, payload = store.get_cbom(scan["scan_id"])
    except LookupError:
        raise HTTPException(
            status_code=404, detail="No CBOM has been generated for this scan."
        ) from None
    return payload


@app.post("/api/scans/{scan_id}/cbom/export")
def regenerate_cbom_export(scan_id: str) -> dict:
    """Re-export the CBOM for a completed scan from its persisted assets."""
    from ecdat.engines.cbom_exporter import CBOMExporter
    from ecdat.schemas import CryptoAsset

    scan = _require_complete(_get_scan_or_404(scan_id))
    _, assets = store.get_assets(scan_id)
    _, roadmaps = store.get_roadmaps(scan_id)
    parsed = [CryptoAsset.model_validate(item) for item in assets]
    roadmap_lookup = {
        item["asset"]["asset_id"]: item["roadmap"] for item in roadmaps
    }
    exporter = CBOMExporter()
    result = exporter.export(
        assets=parsed,
        scan_id=scan_id,
        target_path=scan["target"],
        roadmaps=None,
        total_raw_findings=len(parsed),
        scanned_surfaces=scan.get("scanned_surfaces") or ["source_code"],
        completeness_pct=(
            scan["completeness"]["overall_completeness_pct"]
            if scan["completeness"] else None
        ),
    )
    del roadmap_lookup
    from ecdat.persistence import database
    from ecdat.persistence.models import CBOMRecord

    quality_json = (
        result.cbom_export.quality_score.model_dump_json()
        if result.cbom_export.quality_score else None
    )
    with database.session() as session:
        session.query(CBOMRecord).filter(CBOMRecord.scan_id == scan_id).delete()
        session.add(CBOMRecord(
            scan_id=scan_id,
            format=result.format.value,
            document=result.document,
            component_count=result.component_count,
            quality_json=quality_json,
        ))
        session.commit()
    _, payload = store.get_cbom(scan_id)
    return payload


@app.post("/api/cbom/export")
def generate_cbom_export() -> dict:
    """Regenerate a CBOM for the current scan without writing a file."""
    return regenerate_cbom_export(current_scan()["scan_id"])


@app.get("/api/scans/{scan_id}/cbom/download")
def download_scan_cbom(scan_id: str) -> Response:
    """Download the persisted CycloneDX document for one scan."""
    _require_complete(_get_scan_or_404(scan_id))
    try:
        row, document, fmt = store.get_cbom_document(scan_id)
    except LookupError:
        raise HTTPException(
            status_code=404, detail="No CBOM has been generated for this scan."
        ) from None
    extension = "xml" if fmt == "xml" else "json"
    return Response(
        content=document,
        media_type="application/xml" if extension == "xml" else "application/json",
        headers={"Content-Disposition": f'attachment; filename="ecdat-{row["scan_id"]}.cbom.{extension}"'},
    )


@app.get("/api/cbom/download")
def download_cbom() -> Response:
    """Download the persisted CycloneDX JSON for the current scan."""
    return download_scan_cbom(current_scan()["scan_id"])


@app.get("/api/reports")
def reports(scan_id: Optional[str] = None) -> dict:
    """List the persisted artifacts available for a scan."""
    if scan_id is not None:
        scan = _get_scan_or_404(scan_id)
    else:
        scan = _get_scan_or_404(current_scan()["scan_id"])
    items = []
    if scan["status"] == "complete":
        items = [
            {
                "id": "pipeline-report",
                "name": "Pipeline report",
                "format": "txt",
                "download_url": f"/api/scans/{scan['scan_id']}/reports/pipeline.txt",
                "description": "Persisted pipeline summary for this scan.",
            },
            {
                "id": "cbom",
                "name": "CycloneDX CBOM",
                "format": "json",
                "download_url": f"/api/scans/{scan['scan_id']}/cbom/download",
                "description": "Persisted CBOM export for this scan.",
            },
            {
                "id": "migration-report",
                "name": "Migration report",
                "format": "txt",
                "download_url": f"/api/scans/{scan['scan_id']}/reports/migration.txt",
                "description": "Roadmap narratives for every asset with a recommendation.",
            },
            {
                "id": "certificate-report",
                "name": "Certificate report",
                "format": "txt",
                "download_url": f"/api/scans/{scan['scan_id']}/reports/certificates.txt",
                "description": "Lifecycle and risk summary for certificate-surface assets.",
            },
        ]
    return {
        "scan": _scan_summary(scan),
        "items": items,
        "history_supported": True,
    }


@app.get("/api/scans/{scan_id}/reports/pipeline.txt")
def download_scan_pipeline_report(scan_id: str) -> Response:
    """Download the persisted text report for one scan."""
    _require_complete(_get_scan_or_404(scan_id))
    row, report = store.get_pipeline_report(scan_id)
    return Response(
        content=report,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="ecdat-{row["scan_id"]}-report.txt"'},
    )


@app.get("/api/scans/{scan_id}/reports/migration.txt")
def download_scan_migration_report(scan_id: str) -> Response:
    """Download the persisted migration roadmap report for one scan."""
    _require_complete(_get_scan_or_404(scan_id))
    row, report = store.get_migration_report(scan_id)
    return Response(
        content=report,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="ecdat-{row["scan_id"]}-migration.txt"'},
    )


@app.get("/api/scans/{scan_id}/reports/certificates.txt")
def download_scan_certificate_report(scan_id: str) -> Response:
    """Download the persisted certificate report for one scan."""
    _require_complete(_get_scan_or_404(scan_id))
    row, report = store.get_certificate_report(scan_id)
    return Response(
        content=report,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="ecdat-{row["scan_id"]}-certificates.txt"'},
    )


@app.get("/api/scans/{scan_id}/cbom/diff")
def cbom_version_diff(scan_id: str, baseline_scan_id: str) -> dict:
    """Diff this scan's CBOM assets against a baseline scan's CBOM assets."""
    from ecdat.engines.cbom_exporter import compute_version_diff
    from ecdat.schemas import CryptoAsset

    _require_complete(_get_scan_or_404(scan_id))
    _require_complete(_get_scan_or_404(baseline_scan_id))
    _, current_assets = store.get_assets(scan_id)
    _, baseline_assets = store.get_assets(baseline_scan_id)
    current = [CryptoAsset.model_validate(item) for item in current_assets]
    baseline = [CryptoAsset.model_validate(item) for item in baseline_assets]
    diff = compute_version_diff(
        _assets_to_cbom_export(baseline_scan_id, baseline),
        _assets_to_cbom_export(scan_id, current),
    )
    return {
        "baseline_scan_id": diff.baseline_scan_id,
        "current_scan_id": diff.current_scan_id,
        "new_assets": diff.new_assets,
        "removed_assets": diff.removed_assets,
        "changed_assets": diff.changed_assets,
        "diff_timestamp": diff.diff_timestamp.isoformat(),
    }


@app.get("/api/reports/pipeline.txt")
def download_pipeline_report() -> Response:
    """Download the persisted text report for the current scan."""
    return download_scan_pipeline_report(current_scan()["scan_id"])


# ── Ownership rules ──────────────────────────────────────────────────────────

class OwnershipRuleRequest(BaseModel):
    owner: str
    priority: int = 0
    surface: Optional[str] = None
    purpose: Optional[str] = None
    algorithm_prefix: Optional[str] = None
    path_contains: Optional[str] = None


@app.get("/api/ownership/rules")
def list_ownership_rules() -> dict:
    """List the user-configured ownership mapping rules."""
    return {"items": store.list_ownership_rules()}


@app.post("/api/ownership/rules", status_code=201)
def create_ownership_rule(request: OwnershipRuleRequest) -> dict:
    """Add an ownership mapping rule applied to future scans."""
    try:
        return store.create_ownership_rule(
            owner=request.owner,
            priority=request.priority,
            surface=request.surface,
            purpose=request.purpose,
            algorithm_prefix=request.algorithm_prefix,
            path_contains=request.path_contains,
        )
    except ScanInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/api/ownership/rules/{rule_id}")
def delete_ownership_rule(rule_id: int) -> dict:
    """Delete an ownership mapping rule."""
    try:
        store.delete_ownership_rule(rule_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Rule not found: {rule_id}") from None
    return {"ok": True}
