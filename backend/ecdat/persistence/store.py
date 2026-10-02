"""ECDAT scan-job persistence — engine and background runner.

The store accepts arbitrary, user-supplied scan inputs, resolves them to
concrete local paths, and executes the real ECDAT pipeline in a background
thread. Every scan's status transitions are durable in the database:

  pending → running → complete
                    ↘ failed (with an error message)

PRD §6 (Read-only guarantee): uploads, clones, and certificate files live
in ECDAT-owned job directories. Scanned targets are never modified.

Supported source kinds:
  demo         — the curated bundled fixtures (onboarding path)
  local_path   — a server-local filesystem path supplied in the request
  repo_url     — a public git repository cloned read-only into a job dir
  upload_tree  — a previously uploaded file tree staged into a job dir
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[3] / ".env")

from ecdat.pipeline import PipelineResult
from ecdat.persistence import database
from ecdat.persistence.models import AssetRecord, CBOMRecord, RoadmapRecord, ScanRecord

logger = logging.getLogger(__name__)

WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
DEMO_REPOSITORY = WORKSPACE_ROOT / "test_repos" / "demo_app"
DEMO_CERTIFICATES = WORKSPACE_ROOT / "test_repos" / "demo_certs"

JOB_ROOT = WORKSPACE_ROOT / "backend" / ".ecdat_jobs"
UPLOAD_ROOT = WORKSPACE_ROOT / "backend" / ".ecdat_uploads"

MAX_UPLOAD_BYTES = 100 * 1024 * 1024

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ecdat-scan")

_CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der"}

SOURCE_KIND_DEMO = "demo"
SOURCE_KIND_LOCAL_PATH = "local_path"
SOURCE_KIND_REPO_URL = "repo_url"
SOURCE_KIND_UPLOAD_TREE = "upload_tree"

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_COMPLETE = "complete"
STATUS_FAILED = "failed"
STATUS_PARTIAL = "partial"

STALE_RUNNING_TIMEOUT_S = 30 * 60


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _resolve_database_url(configured: Optional[str] = None) -> str:
    if configured:
        return configured
    env_url = os.environ.get("DATABASE_URL")
    if env_url:
        return env_url
    return f"sqlite:///{(WORKSPACE_ROOT / 'backend' / 'ecdat.sqlite3')}"


class ScanInputError(ValueError):
    """Raised when a user-supplied scan input is invalid or unsafe."""


class _PartialResult(Exception):
    """Carries a partially-enriched PipelineResult out of a failed stage.

    Raised by the pipeline's stage guard (run_pipeline) when a stage
    fails but findings exist up to that point. The store catches it,
    persists what exists, and marks the scan partial — never discards.
    """

    def __init__(self, result, surfaces: list[str]) -> None:
        super().__init__(result.failure_error or "stage failed")
        self.result = result
        self.surfaces = surfaces


def validate_repo_url(url: str) -> str:
    """Accept https:// or git@ repository references and nothing else."""
    cleaned = url.strip()
    lowered = cleaned.lower()
    if lowered.startswith(("https://", "http://")):
        return cleaned
    if cleaned.startswith("git@") and ":" in cleaned:
        return cleaned
    raise ScanInputError(
        "repo_url must be an https:// URL or a git@host:path reference."
    )


def _ensure_within(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    root_resolved = root.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise ScanInputError("Upload file path escapes the upload staging area.")
    return resolved


def stage_upload_tree() -> str:
    """Create a fresh upload staging area and return its upload id."""
    upload_id = uuid.uuid4().hex
    dest = UPLOAD_ROOT / upload_id
    dest.mkdir(parents=True, exist_ok=False)
    return upload_id


def write_upload_file(upload_id: str, relative_path: str, data: bytes) -> str:
    """Write one uploaded file into the staging area, path-confined."""
    if not relative_path or relative_path.strip() in {"", ".", "/"}:
        raise ScanInputError("Upload file path must be non-empty.")
    clean = relative_path.replace("\\", "/").lstrip("/")
    parts = [p for p in clean.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        raise ScanInputError("Upload file path is not allowed.")
    dest = _ensure_within(UPLOAD_ROOT / upload_id / Path(*parts), UPLOAD_ROOT / upload_id)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as handle:
        handle.write(data)
    return str(dest.relative_to(UPLOAD_ROOT / upload_id))


def _remove_tree_quietly(path: Path) -> None:
    """Best-effort recursive delete; never raises (cleanup path only)."""
    try:
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
            return
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass


def _clone_repo(job_dir: Path, url: str) -> Path:
    """Clone a repo into a fresh, unique directory inside job_dir.

    Robustness (Task 1): git fails with "could not write config file
    .git/config: Permission denied" when the destination already exists
    as a stale/partial clone — git creates .git/ but cannot overwrite
    the locked config inside it. So the destination is ALWAYS fresh:
      - a unique repo-<n> name per attempt (no collision with a previous
        failed attempt in the same job dir),
      - any stale repo/ or repo-<n>/ dir is removed first (best-effort),
      - a failed clone's partial directory is removed so the next retry
        starts clean.
    Read-only behaviour is unchanged: shallow, no tags, no submodules,
    no writes outside the ECDAT-owned job dir. Path security is unchanged:
    dest is always job_dir / a fixed name (never derived from user input),
    so traversal via the URL is impossible.
    """
    job_dir.mkdir(parents=True, exist_ok=True)
    dest = job_dir / "repo"
    if dest.exists() or dest.is_symlink():
        _remove_tree_quietly(dest)
    if dest.exists() or dest.is_symlink():
        # Removal failed (locked handles) — fall back to a unique name so
        # git never clones into a stale directory.
        attempt = 0
        while (job_dir / f"repo-{attempt}").exists():
            attempt += 1
            if attempt > 100:
                raise ScanInputError("Could not allocate a fresh clone directory.")
        dest = job_dir / f"repo-{attempt}"
    command = [
        "git", "clone", "--depth", "1", "--no-tags",
        "--no-recurse-submodules", url, str(dest),
    ]
    completed = subprocess.run(
        command, capture_output=True, text=True, timeout=300
    )
    if completed.returncode != 0:
        _remove_tree_quietly(dest)
        detail = (completed.stderr or completed.stdout or "git clone failed").strip()
        raise ScanInputError(f"Could not clone repository: {detail[:500]}")
    (job_dir / "repo_url.txt").write_text(url, encoding="utf-8")
    return dest


class ScanStore:
    """Persistent, asynchronous scan-job store backed by a database."""

    def __init__(self, database_url: Optional[str] = None) -> None:
        self._database_url = _resolve_database_url(database_url or None)
        database.configure(self._database_url)
        self._init_lock = threading.Lock()
        self._initialised = False
        self._timers: dict[str, threading.Timer] = {}

    def _ensure_init_without_reap(self) -> None:
        if self._initialised:
            return
        with self._init_lock:
            if not self._initialised:
                database.init_db_sync(self._database_url)
                self._initialised = True

    def _ensure_init(self) -> None:
        was_initialised = self._initialised
        self._ensure_init_without_reap()
        if not was_initialised:
            self.reap_stale_jobs()

    def _session_no_reap(self):
        self._ensure_init_without_reap()
        return database.session()

    def _session(self):
        self._ensure_init()
        return database.session()

    def reap_stale_jobs(self, timeout_s: int = STALE_RUNNING_TIMEOUT_S) -> int:
        """Fail jobs stuck in running/pending past the timeout (startup reaper)."""
        self._ensure_init_without_reap()
        cutoff = _now() - timedelta(seconds=timeout_s)
        count = 0
        with self._session_no_reap() as session:
            stale = (
                session.query(ScanRecord)
                .filter(ScanRecord.status.in_([STATUS_PENDING, STATUS_RUNNING]))
                .all()
            )
            for record in stale:
                moment = record.started_at or record.created_at
                if moment is not None:
                    aware = moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
                    if aware > cutoff:
                        continue
                record.status = STATUS_FAILED
                record.stage = "failed"
                record.error = (
                    "Scan did not complete before the service restarted; "
                    "it was marked failed on startup. Please re-run the scan."
                )[:2000]
                record.completed_at = _now()
                count += 1
            session.commit()
        if count:
            logger.warning("Reaped %d stale scan job(s) on startup", count)
        return count


    # ── Scan lifecycle ─────────────────────────────────────────────────────

    def create_scan(
        self,
        *,
        source_kind: str = SOURCE_KIND_DEMO,
        source_path: Optional[str] = None,
        repo_url: Optional[str] = None,
        upload_id: Optional[str] = None,
        include_certificates: bool = True,
        certificate_paths: Optional[list[str]] = None,
        certificate_upload_id: Optional[str] = None,
        binary_refs: Optional[list[str]] = None,
        container_refs: Optional[list[str]] = None,
        infrastructure_endpoints: Optional[list[str]] = None,
        user_id: Optional[str] = None,
        run_llm_enrichment: bool = False,
    ) -> dict:
        """Validate inputs, persist a pending job, and schedule its run."""
        scan_id = uuid.uuid4().hex
        source_ref: Optional[str] = None
        target_label = "Bundled demo application"

        if source_kind == SOURCE_KIND_DEMO:
            source_ref = None
            target_label = "Bundled demo application"
        elif source_kind == SOURCE_KIND_LOCAL_PATH:
            if not source_path:
                raise ScanInputError("source_path is required for local_path scans.")
            candidate = Path(source_path)
            if not candidate.exists():
                raise ScanInputError(f"source_path does not exist: {source_path}")
            source_ref = str(candidate.resolve())
            target_label = source_ref
        elif source_kind == SOURCE_KIND_REPO_URL:
            if not repo_url:
                raise ScanInputError("repo_url is required for repo_url scans.")
            source_ref = validate_repo_url(repo_url)
            target_label = source_ref
        elif source_kind == SOURCE_KIND_UPLOAD_TREE:
            if not upload_id:
                raise ScanInputError("upload_id is required for upload_tree scans.")
            staged = UPLOAD_ROOT / upload_id
            if not staged.is_dir():
                raise ScanInputError("Unknown or expired upload_id.")
            source_ref = upload_id
            target_label = f"Uploaded file tree ({upload_id[:8]})"
        else:
            raise ScanInputError(
                "source_kind must be one of: demo, local_path, repo_url, upload_tree."
            )

        cert_refs = list(certificate_paths or [])
        if certificate_upload_id:
            staged = UPLOAD_ROOT / certificate_upload_id
            if not staged.is_dir():
                raise ScanInputError("Unknown or expired certificate_upload_id.")
            cert_refs.append(f"upload:{certificate_upload_id}")
        if include_certificates and source_kind == SOURCE_KIND_DEMO and not cert_refs:
            cert_refs.append(str(DEMO_CERTIFICATES))

        now = _now()
        with self._session() as session:
            session.add(ScanRecord(
                id=scan_id,
                status=STATUS_PENDING,
                stage="queued",
                user_id=user_id,
                source_kind=source_kind,
                source_ref=source_ref,
                target_label=target_label,
                include_certificates=include_certificates,
                cert_refs=cert_refs,
                binary_refs=list(binary_refs or []),
                container_refs=list(container_refs or []),
                infra_endpoints=list(infrastructure_endpoints or []),
                recorded_only_surfaces=_recorded_only_surfaces(
                    binary_refs, container_refs, infrastructure_endpoints
                ),
                priority_counts={"P1": 0, "P2": 0, "P3": 0, "P4": 0},
                llm_enrichment_requested=run_llm_enrichment,
                created_at=now,
            ))
            session.commit()
        self._schedule(scan_id)
        return self.get_scan(scan_id)

    def _schedule(self, scan_id: str) -> None:
        timer = threading.Timer(0.05, lambda: _executor.submit(self._execute, scan_id))
        timer.daemon = True
        self._timers[scan_id] = timer
        timer.start()

    def _execute(self, scan_id: str) -> None:
        self._ensure_init()
        from ecdat.pipeline import PipelineResult, run_pipeline

        job_dir = JOB_ROOT / scan_id
        job_dir.mkdir(parents=True, exist_ok=True)
        try:
            self._transition(scan_id, STATUS_RUNNING, "resolving inputs", started=True)
            target_path, cert_paths, surfaces, extra = _resolve_inputs(
                scan_id, job_dir, self._session)
            llm_requested = extra.get("run_llm_enrichment", False)
            if llm_requested:
                self._transition(scan_id, STATUS_RUNNING, "LLM enrichment enabled")
            self._transition(scan_id, STATUS_RUNNING, "scanning all input surfaces")
            result = run_pipeline(
                target_path=target_path,
                cert_paths=cert_paths or None,
                binary_paths=extra["binary_paths"] or None,
                container_refs=extra["container_refs"] or None,
                container_contexts=extra["container_contexts"] or None,
                infra_endpoints=extra["infra_endpoints"] or None,
                scan_id=scan_id,
                run_classification=True,
                run_reachability=True,
                run_completeness=True,
                run_mosca=True,
                run_recommendations=True,
                run_llm_enrichment=llm_requested,
                run_migration=True,
                run_cbom_export=True,
                scanned_surfaces=surfaces or None,
            )
            self._transition(scan_id, STATUS_RUNNING, "persisting results")
            self._persist_result(scan_id, result, surfaces)
            self._transition(scan_id, STATUS_COMPLETE, "complete", finished=True)
        except _PartialResult as partial:
            # A pipeline stage failed but findings exist up to that point.
            # Persist them with partial status rather than discarding.
            logger.warning(
                "Scan %s partially complete at stage %s: %s",
                scan_id, partial.result.failure_stage, partial.result.failure_error,
            )
            self._transition(scan_id, STATUS_RUNNING, "persisting partial results")
            self._persist_result(
                scan_id, partial.result, partial.surfaces, partial=True)
            self._fail(
                scan_id,
                f"Partial results through stage "
                f"'{partial.result.failure_stage}': "
                f"{partial.result.failure_error}",
                status=STATUS_PARTIAL,
            )
        except ScanInputError as exc:
            logger.warning("Scan %s rejected: %s", scan_id, exc)
            self._fail(scan_id, str(exc))
        except Exception as exc:  # noqa: BLE001 — surfaced via the status endpoint
            logger.exception("Scan %s failed", scan_id)
            self._fail(scan_id, f"Pipeline execution failed: {exc}")

    def _transition(
        self, scan_id: str, status: str, stage: str,
        started: bool = False, finished: bool = False,
    ) -> None:
        with self._session() as session:
            record = session.get(ScanRecord, scan_id)
            if record is None:
                return
            record.status = status
            record.stage = stage
            if started and record.started_at is None:
                record.started_at = _now()
            if finished:
                record.completed_at = _now()
            session.commit()

    def _fail(self, scan_id: str, message: str, status: str = STATUS_FAILED) -> None:
        with self._session() as session:
            record = session.get(ScanRecord, scan_id)
            if record is None:
                return
            record.status = status
            record.stage = status
            record.error = message[:2000]
            record.completed_at = _now()
            session.commit()

    def enrich_scan_ambiguous(
        self, scan_id: str, *, user_id: Optional[str] = None
    ) -> dict:
        """Enrich a completed scan's ambiguous findings via the LLM pipeline.

        Only assets with purpose=UNKNOWN, finding_type=DETERMINISTIC, and a
        snippet are sent to the LLM (the engine's own gate). Deterministic
        findings are never touched. Enriched assets flow back through the
        same downstream stages as a fresh scan (classification → ownership →
        reachability → completeness → mosca → recommendations → migration →
        CBOM) so risk/priority/recommendation stay consistent with the new
        purpose. Originals are preserved on any failure; the scan only
        transitions back to complete/partial, never to failed.
        """
        from ecdat.engines.classification_engine import ClassificationEngine
        from ecdat.engines.completeness_engine import DiscoveryCompletenessEngine
        from ecdat.engines.migration_impact import MigrationImpactEngine
        from ecdat.engines.mosca_engine import MoscaEngine
        from ecdat.engines.ownership_engine import apply_ownership
        from ecdat.engines.recommendation_engine import RecommendationEngine
        from ecdat.llm.llm_enrichment import LLMEnrichmentEngine, _is_ambiguous
        from ecdat.schemas import CryptoAsset

        with self._session() as session:
            record = session.get(ScanRecord, scan_id)
            if record is None:
                raise KeyError(scan_id)
            if user_id is not None and record.user_id not in (None, user_id):
                raise PermissionError(scan_id)
            if record.status not in (STATUS_COMPLETE, STATUS_PARTIAL):
                raise ScanInputError(
                    f"Scan {scan_id} is {record.status}; enrichment needs a "
                    "completed scan."
                )
            surfaces = list(record.scanned_surfaces or ["source_code"])
        self._transition(scan_id, STATUS_RUNNING, "LLM enrichment", started=False)

        try:
            _, stored = self.get_assets(scan_id)
            assets = [CryptoAsset.model_validate(item) for item in stored]
            eligible = [a for a in assets if _is_ambiguous(a)]
            already = sum(
                1 for a in assets
                if a.evidence.finding_type.value == "llm_enriched"
            )
            if not eligible:
                self._transition(scan_id, STATUS_COMPLETE, "complete", finished=True)
                return {
                    "scan_id": scan_id,
                    "eligible": 0,
                    "attempted": 0,
                    "enriched": 0,
                    "still_ambiguous": 0,
                    "already_enriched": already,
                    "failed": 0,
                    "errors": [],
                }
            engine = LLMEnrichmentEngine.from_env()
            if not engine._client._config.is_configured:
                self._transition(scan_id, STATUS_COMPLETE, "complete", finished=True)
                return {
                    "scan_id": scan_id,
                    "eligible": len(eligible),
                    "attempted": 0,
                    "enriched": 0,
                    "still_ambiguous": len(eligible),
                    "already_enriched": already,
                    "failed": len(eligible),
                    "errors": ["LLM provider is not configured on the server."],
                }
            enriched_assets = engine.process(assets)
            stats = engine.stats

            # Re-run the deterministic downstream stages so the enriched
            # purposes feed classification, risk, and recommendations.
            # Reachability is NOT recomputed here: rebuilding a call graph
            # needs the original source files, and recomputing from nothing
            # would wipe real reachable True/False values to None. Assets
            # keep the reachable values persisted from the original scan.
            enriched_assets = ClassificationEngine().process(enriched_assets)
            enriched_assets = apply_ownership(enriched_assets)
            reach_report = None
            with self._session() as session:
                rec = session.get(ScanRecord, scan_id)
                if rec is not None and rec.reachability:
                    reach_report = rec.reachability
            with self._session() as session:
                rec = session.get(ScanRecord, scan_id)
                prior = rec.completeness if rec is not None else None
            completeness = DiscoveryCompletenessEngine(
                scan_result=_prior_scan_result(prior, len(enriched_assets)),
                assets=enriched_assets,
                scanned_surfaces=surfaces,
            ).compute()
            enriched_assets = MoscaEngine().process(enriched_assets)
            enriched_assets = RecommendationEngine().process(enriched_assets)
            _, migration_roadmaps = MigrationImpactEngine().process(enriched_assets)

            from ecdat.pipeline import PipelineResult
            from ecdat.engines.inventory import CryptoAssetInventory

            partial = PipelineResult(
                scan_id=scan_id,
                target_path=Path("."),
                scan_result=_prior_scan_result(prior, len(enriched_assets)),
                inventory=CryptoAssetInventory(scan_id=scan_id),
                rules_loaded=0,
                scored_assets=enriched_assets,
                reachability_report=None,
                completeness=completeness,
                migration_roadmaps=dict(migration_roadmaps),
                completed_stages=["llm_enrichment", "re_enrichment"],
            )
            self._persist_result(scan_id, partial, surfaces)
            if reach_report is not None:
                with self._session() as session:
                    rec = session.get(ScanRecord, scan_id)
                    if rec is not None:
                        rec.reachability = reach_report
                        session.commit()
            self._transition(scan_id, STATUS_COMPLETE, "complete", finished=True)
            errors: list[str] = []
            if stats.failed:
                errors.append(
                    f"{stats.failed} ambiguous finding(s) could not be enriched; "
                    "originals preserved."
                )
            still = sum(1 for a in enriched_assets if _is_ambiguous(a))
            return {
                "scan_id": scan_id,
                "eligible": len(eligible),
                "attempted": stats.ambiguous_attempted,
                "enriched": stats.enriched,
                "still_ambiguous": still,
                "already_enriched": already,
                "failed": stats.failed,
                "errors": errors,
            }
        except ScanInputError:
            raise
        except (KeyError, PermissionError):
            raise
        except Exception as exc:  # noqa: BLE001 — originals already persisted
            logger.exception("Scan %s enrichment failed", scan_id)
            self._transition(scan_id, STATUS_COMPLETE, "complete", finished=True)
            return {
                "scan_id": scan_id,
                "eligible": 0,
                "attempted": 0,
                "enriched": 0,
                "still_ambiguous": 0,
                "already_enriched": 0,
                "failed": 0,
                "errors": [f"Enrichment failed: {exc}".strip()[:500]],
            }

    def _persist_result(
        self, scan_id: str, result: PipelineResult, surfaces: list[str],
        partial: bool = False,
    ) -> None:
        assets = result.scored_assets
        counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for asset in assets:
            if asset.risk:
                counts[asset.risk.priority.value] += 1
        hndl = sum(1 for a in assets if a.risk and a.risk.hndl_flag)
        cert_count = sum(1 for a in assets if a.source_surface == "certificate")
        binary_count = sum(1 for a in assets if a.source_surface == "binary")
        container_count = sum(1 for a in assets if a.source_surface == "container")
        infra_count = sum(1 for a in assets if a.source_surface == "infrastructure")
        summary = result.completeness.summary() if result.completeness else None
        reachability_summary = None
        if result.reachability_report is not None:
            report = result.reachability_report
            reachability_summary = {
                "total_assets": report.total_assets,
                "reachable_count": report.reachable_count,
                "unreachable_count": report.unreachable_count,
                "unknown_count": report.unknown_count,
                "entry_points_found": report.entry_points_found,
                "graph_node_count": report.graph_node_count,
                "graph_edge_count": report.graph_edge_count,
                "reachability_rate": report.reachability_rate,
            }
        quality = (
            result.cbom_export_result.cbom_export.quality_score.model_dump(mode="json")
            if result.cbom_export_result
            and result.cbom_export_result.cbom_export.quality_score
            else None
        )
        with self._session() as session:
            record = session.get(ScanRecord, scan_id)
            if record is None:  # pragma: no cover - defensive
                return
            record.asset_count = len(assets)
            record.certificate_asset_count = cert_count
            record.priority_counts = counts
            record.hndl_count = hndl
            record.completeness = summary
            record.scanned_surfaces = surfaces
            record.reachability = reachability_summary
            record.cbom_component_count = (
                result.cbom_export_result.component_count
                if result.cbom_export_result else 0
            )
            record.cbom_quality = quality
            record.surface_counts = {
                "source_code": sum(1 for a in assets if a.source_surface == "source_code"),
                "binary": binary_count,
                "container": container_count,
                "certificate": cert_count,
                "infrastructure": infra_count,
            }
            # New rows carry indexed filter columns at insert time. Older
            # rows (written before the classification column existed) are
            # backfilled from their stored JSON — classification is a
            # deterministic function of that JSON, so this is exact.
            session.query(AssetRecord).filter(
                AssetRecord.scan_id == scan_id).delete()
            session.query(RoadmapRecord).filter(
                RoadmapRecord.scan_id == scan_id).delete()
            session.query(CBOMRecord).filter(
                CBOMRecord.scan_id == scan_id).delete()
            for asset in assets:
                session.add(AssetRecord(
                    asset_id=asset.asset_id,
                    scan_id=scan_id,
                    algorithm=asset.algorithm,
                    purpose=asset.purpose.value,
                    priority=asset.risk.priority.value if asset.risk else None,
                    classification=asset.classification.value,
                    source_surface=asset.source_surface,
                    location=asset.location,
                    asset_json=asset.model_dump_json(),
                ))
            for asset_id, roadmap in result.migration_roadmaps.items():
                session.add(RoadmapRecord(
                    scan_id=scan_id,
                    asset_id=asset_id,
                    roadmap_json=json.dumps(roadmap.summary()),
                ))
            if result.cbom_export_result is not None:
                export = result.cbom_export_result
                session.add(CBOMRecord(
                    scan_id=scan_id,
                    format=export.format.value,
                    document=export.document,
                    component_count=export.component_count,
                    quality_json=(
                        export.cbom_export.quality_score.model_dump_json()
                        if export.cbom_export.quality_score else None
                    ),
                ))
            session.commit()

    @staticmethod
    def _backfill_asset_columns(session, scan_id: Optional[str] = None) -> int:
        """Fill NULL classification columns from stored asset JSON.

        One UPDATE per scan (or per row when the JSON varies) — runs inside
        the caller's transaction. Scoped to scan_id when given so a large
        multi-scan database backfills incrementally, not in one giant write.
        Idempotent: rows already populated are skipped by the NULL filter.
        """
        query = session.query(AssetRecord).filter(
            AssetRecord.classification.is_(None))
        if scan_id is not None:
            query = query.filter(AssetRecord.scan_id == scan_id)
        rows = query.all()
        for item in rows:
            try:
                item.classification = json.loads(item.asset_json).get("classification")
            except Exception:
                continue
        return len(rows)

    def backfill_asset_columns(self, scan_id: Optional[str] = None) -> int:
        """Public entry point: backfill then commit (used by tests/ops)."""
        with self._session() as session:
            count = self._backfill_asset_columns(session, scan_id)
            session.commit()
            return count

    # ── Ownership rules ────────────────────────────────────────────────────

    def list_ownership_rules(self) -> list[dict]:
        from ecdat.persistence.models import OwnershipRuleRecord

        with self._session() as session:
            rows = (
                session.query(OwnershipRuleRecord)
                .order_by(
                    OwnershipRuleRecord.priority.desc(),
                    OwnershipRuleRecord.id.asc(),
                )
                .all()
            )
            return [
                {
                    "id": row.id,
                    "owner": row.owner,
                    "priority": row.priority,
                    "surface": row.surface,
                    "purpose": row.purpose,
                    "algorithm_prefix": row.algorithm_prefix,
                    "path_contains": row.path_contains,
                }
                for row in rows
            ]

    def create_ownership_rule(
        self,
        *,
        owner: str,
        priority: int = 0,
        surface: Optional[str] = None,
        purpose: Optional[str] = None,
        algorithm_prefix: Optional[str] = None,
        path_contains: Optional[str] = None,
    ) -> dict:
        from ecdat.persistence.models import OwnershipRuleRecord

        cleaned = (owner or "").strip()
        if not cleaned:
            raise ScanInputError("owner must be a non-empty team or owner name.")
        if surface is not None and surface not in (
            "source_code", "binary", "container", "certificate", "infrastructure",
        ):
            raise ScanInputError(f"Unknown surface: {surface}")
        now = _now()
        with self._session() as session:
            row = OwnershipRuleRecord(
                owner=cleaned,
                priority=int(priority),
                surface=surface,
                purpose=purpose,
                algorithm_prefix=algorithm_prefix,
                path_contains=path_contains,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return {
                "id": row.id,
                "owner": row.owner,
                "priority": row.priority,
                "surface": row.surface,
                "purpose": row.purpose,
                "algorithm_prefix": row.algorithm_prefix,
                "path_contains": row.path_contains,
            }

    def delete_ownership_rule(self, rule_id: int) -> None:
        from ecdat.persistence.models import OwnershipRuleRecord

        with self._session() as session:
            count = (
                session.query(OwnershipRuleRecord)
                .filter(OwnershipRuleRecord.id == rule_id)
                .delete()
            )
            session.commit()
            if count == 0:
                raise KeyError(rule_id)

    # ── Queries ────────────────────────────────────────────────────────────

    def get_scan(self, scan_id: str) -> dict:
        with self._session() as session:
            record = session.get(ScanRecord, scan_id)
            if record is None:
                raise KeyError(scan_id)
            row = _scan_to_dict(record)
        return row

    def list_scans(self, limit: int = 50, user_id: Optional[str] = None) -> list[dict]:
        with self._session() as session:
            query = session.query(ScanRecord)
            if user_id is not None:
                query = query.filter(
                    (ScanRecord.user_id == user_id) | (ScanRecord.user_id.is_(None))
                )
            records = (
                query
                .order_by(ScanRecord.created_at.desc(), ScanRecord.id.desc())
                .limit(max(1, min(limit, 200)))
                .all()
            )
            return [_scan_to_dict(record) for record in records]

    def get_assets(self, scan_id: str) -> tuple[dict, list[dict]]:
        with self._session() as session:
            record = session.get(ScanRecord, scan_id)
            if record is None:
                raise KeyError(scan_id)
            row = _scan_to_dict(record)
            rows = (
                session.query(AssetRecord)
                .filter(AssetRecord.scan_id == scan_id)
                .order_by(AssetRecord.location)
                .all()
            )
            return row, [json.loads(item.asset_json) for item in rows]

    # ── Paginated, server-filtered reads (scalability path) ──────────────────

    #: Allowed sort keys for paginated asset queries (column names only —
    #: never raw user input, so ORDER BY cannot be injected).
    _ASSET_SORT_COLUMNS = {
        "location": "location",
        "algorithm": "algorithm",
        "priority": "priority",
        "purpose": "purpose",
    }

    def query_assets(
        self,
        scan_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
        algorithm: Optional[str] = None,
        purpose: Optional[str] = None,
        classification: Optional[str] = None,
        priority: Optional[str] = None,
        source_surface: Optional[str] = None,
        sort: str = "location",
    ) -> tuple[dict, list[dict], dict]:
        """Page through one scan's assets with server-side filtering.

        Every filter applies in SQL across the FULL dataset (COUNT + page
        share the same WHERE clause) — a filter never misses rows outside
        the current page. Limit is clamped to [1, 500]; offset to >= 0.
        Returns (scan_dict, items, page_dict with total/limit/offset).
        """
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))
        sort_col = self._ASSET_SORT_COLUMNS.get(sort, "location")
        with self._session() as session:
            record = session.get(ScanRecord, scan_id)
            if record is None:
                raise KeyError(scan_id)
            row = _scan_to_dict(record)
            query = session.query(AssetRecord).filter(
                AssetRecord.scan_id == scan_id)
            if algorithm:
                query = query.filter(
                    AssetRecord.algorithm.ilike(f"%{algorithm}%"))
            if purpose:
                query = query.filter(AssetRecord.purpose == purpose)
            if classification:
                query = query.filter(
                    AssetRecord.classification == classification)
            if priority:
                query = query.filter(AssetRecord.priority == priority)
            if source_surface:
                query = query.filter(
                    AssetRecord.source_surface == source_surface)
            total = query.count()
            order_column = getattr(AssetRecord, sort_col)
            page_rows = (
                query.order_by(order_column, AssetRecord.asset_id)
                .offset(offset)
                .limit(limit)
                .all()
            )
            items = [json.loads(item.asset_json) for item in page_rows]
            page = {
                "total": total,
                "limit": limit,
                "offset": offset,
                "count": len(items),
            }
            return row, items, page

    def get_dashboard_summary(
        self, scan_id: str, *, top_n: int = 10
    ) -> tuple[dict, dict]:
        """Dashboard data without hydrating full asset_json blobs.

        Counts come from SQL aggregates over indexed columns; only the top
        N critical findings are deserialised. Cost is O(top_n) regardless
        of total inventory size. Returns (scan_dict, summary_dict).
        """
        from sqlalchemy import func

        top_n = max(1, min(int(top_n), 100))
        with self._session() as session:
            record = session.get(ScanRecord, scan_id)
            if record is None:
                raise KeyError(scan_id)
            row = _scan_to_dict(record)
            counts = _priority_counts_dict(row)
            by_priority = dict(
                session.query(AssetRecord.priority, func.count())
                .filter(AssetRecord.scan_id == scan_id)
                .group_by(AssetRecord.priority)
                .all()
            )
            by_classification = dict(
                session.query(AssetRecord.classification, func.count())
                .filter(AssetRecord.scan_id == scan_id)
                .group_by(AssetRecord.classification)
                .all()
            )
            top_rows = (
                session.query(AssetRecord)
                .filter(
                    AssetRecord.scan_id == scan_id,
                    AssetRecord.priority == "P1",
                )
                .order_by(AssetRecord.location, AssetRecord.asset_id)
                .limit(top_n)
                .all()
            )
            top_critical = [json.loads(item.asset_json) for item in top_rows]
            summary = {
                "metrics": {
                    "total_assets": row["asset_count"],
                    "quantum_vulnerable_count": (
                        row["asset_count"]
                        - by_priority.get("P4", 0)
                        - by_priority.get(None, 0)
                        if row["asset_count"] else 0
                    ),
                    "p1_count": counts["P1"],
                    "hndl_flagged_count": row["hndl_flagged_count"],
                    "discovery_coverage_pct": (
                        row["completeness"]["overall_completeness_pct"]
                        if row["completeness"] else None
                    ),
                },
                "priority_counts": counts,
                "classification_counts": {
                    key or "unknown": value
                    for key, value in by_classification.items()
                },
                "top_critical_findings": top_critical,
                "completeness": row["completeness"],
            }
            return row, summary

    def get_roadmaps(self, scan_id: str) -> tuple[dict, list[dict]]:
        with self._session() as session:
            record = session.get(ScanRecord, scan_id)
            if record is None:
                raise KeyError(scan_id)
            row = _scan_to_dict(record)
            assets = {
                item.asset_id: json.loads(item.asset_json)
                for item in session.query(AssetRecord).filter(
                    AssetRecord.scan_id == scan_id).all()
            }
            roadmaps = {
                item.asset_id: json.loads(item.roadmap_json)
                for item in session.query(RoadmapRecord).filter(
                    RoadmapRecord.scan_id == scan_id).all()
            }
            items = [
                {"asset": assets[asset_id], "roadmap": roadmap}
                for asset_id, roadmap in roadmaps.items()
                if asset_id in assets
            ]
            return row, items

    def get_cbom(self, scan_id: str) -> tuple[dict, dict]:
        with self._session() as session:
            record = session.get(ScanRecord, scan_id)
            if record is None:
                raise KeyError(scan_id)
            row = _scan_to_dict(record)
            cbom = (
                session.query(CBOMRecord)
                .filter(CBOMRecord.scan_id == scan_id)
                .one_or_none()
            )
            if cbom is None:
                raise LookupError(scan_id)
            assets = [
                json.loads(item.asset_json)
                for item in session.query(AssetRecord).filter(
                    AssetRecord.scan_id == scan_id).all()
            ]
            payload = {
                "scan": _scan_summary(row),
                "component_count": cbom.component_count,
                "format": cbom.format,
                "export": {
                    "export_format": cbom.format,
                    "metadata": {
                        "scan_timestamp": row["completed_at"],
                        "scanned_targets": [row["target"]],
                        "input_surfaces": row["scanned_surfaces"],
                    },
                    "quality_score": (
                        json.loads(cbom.quality_json)
                        if cbom.quality_json else None
                    ),
                    "discovery_completeness_pct": (
                        row["completeness"]["overall_completeness_pct"]
                        if row["completeness"] else None
                    ),
                    "assets": assets,
                },
                "download_url": f"/api/scans/{scan_id}/cbom/download",
            }
            return row, payload

    def get_cbom_document(self, scan_id: str) -> tuple[dict, str, str]:
        with self._session() as session:
            record = session.get(ScanRecord, scan_id)
            if record is None:
                raise KeyError(scan_id)
            row = _scan_to_dict(record)
            cbom = (
                session.query(CBOMRecord)
                .filter(CBOMRecord.scan_id == scan_id)
                .one_or_none()
            )
            if cbom is None:
                raise LookupError(scan_id)
            return row, cbom.document, cbom.format

    def get_pipeline_report(self, scan_id: str) -> tuple[dict, str]:
        row, assets = self.get_assets(scan_id)
        lines = [
            "ECDAT Pipeline Report",
            "=" * 60,
            f"Scan ID      : {row['scan_id']}",
            f"Target       : {row['target']}",
            f"Status       : {row['status']}",
            "",
            f"Assets       : {row['asset_count']}",
            f"P1 / P2 / P3 / P4: "
            f"{row['priority_counts'].get('P1', 0)} / "
            f"{row['priority_counts'].get('P2', 0)} / "
            f"{row['priority_counts'].get('P3', 0)} / "
            f"{row['priority_counts'].get('P4', 0)}",
            f"HNDL flagged : {row['hndl_flagged_count']}",
            "",
            "Assets (by location):",
        ]
        for item in assets:
            lines.append(f"  {item.get('location')} {item.get('algorithm')}")
        return row, "\n".join(lines)

    def get_migration_report(self, scan_id: str) -> tuple[dict, str]:
        """Render the persisted migration roadmaps as a text report."""
        row, items = self.get_roadmaps(scan_id)
        lines = [
            "ECDAT Migration Report",
            "=" * 60,
            f"Scan ID      : {row['scan_id']}",
            f"Target       : {row['target']}",
            "",
        ]
        if not items:
            lines.append("No migration roadmaps for this scan.")
            return row, "\n".join(lines)
        for entry in sorted(
            items,
            key=lambda e: (
                {"P1": 0, "P2": 1, "P3": 2, "P4": 3}.get(
                    (e['asset'].get('risk') or {}).get('priority', 'P4'), 4),
                e['asset'].get('location', ''),
            ),
        ):
            asset = entry["asset"]
            roadmap = entry["roadmap"]
            risk = asset.get("risk") or {}
            lines += [
                f"{asset.get('algorithm')} [{risk.get('priority', 'Unscored')}]",
                f"  Location : {asset.get('location')}",
                f"  Current  : {roadmap.get('current_state')}",
                f"  Risk     : {roadmap.get('risk_context')}",
                f"  Action   : {roadmap.get('recommendation_action')}",
                f"  Priority : {roadmap.get('migration_priority')}",
                f"  Impact   : {roadmap.get('composite_impact_score')} "
                f"({roadmap.get('impact_level')})",
                f"  Affected : {', '.join(roadmap.get('affected_components') or [])}",
                "  Validate :",
            ]
            for step in roadmap.get("validation_steps") or []:
                lines.append(f"    - {step}")
            lines.append("")
        return row, "\n".join(lines)

    def get_certificate_report(self, scan_id: str) -> tuple[dict, str]:
        """Render certificate-surface assets as a lifecycle/risk text report."""
        row, assets = self.get_assets(scan_id)
        certs = [a for a in assets if a.get("source_surface") == "certificate"]
        lines = [
            "ECDAT Certificate Report",
            "=" * 60,
            f"Scan ID      : {row['scan_id']}",
            f"Target       : {row['target']}",
            f"Certificates : {len(certs)}",
            "",
        ]
        if not certs:
            lines.append("No certificate-surface assets in this scan.")
            return row, "\n".join(lines)
        for asset in sorted(certs, key=lambda a: a.get("location", "")):
            risk = asset.get("risk") or {}
            lines += [
                f"{asset.get('algorithm')} [{risk.get('priority', 'Unscored')}]",
                f"  Location : {asset.get('location')}",
                f"  Subject  : {asset.get('certificate_subject')}",
                f"  Issuer   : {asset.get('certificate_issuer')}",
                f"  Expiry   : {asset.get('certificate_expiry')}",
                f"  Lifecycle: {asset.get('lifecycle_stage')}",
                f"  Owner    : {asset.get('owner') or 'unassigned'}",
            ]
            lines.append("")
        return row, "\n".join(lines)


def _prior_scan_result(prior: Optional[dict], asset_count: int):
    """Completeness input for post-scan re-enrichment.

    Completeness only reads files_scanned/files_skipped/total_lines/
    total_matches/missing_grammars/file_results from the scan result.
    The original scan's persisted completeness summary already carries
    the true counters, so replay them instead of zeroing them (which
    would corrupt the pipeline report and completeness notes).
    """
    from dataclasses import dataclass as _dataclass
    from dataclasses import field as _field

    @_dataclass
    class _Prior:
        files_scanned: int = 0
        files_skipped: int = 0
        total_lines: int = 0
        total_matches: int = 0
        missing_grammars: list = _field(default_factory=list)
        file_results: list = _field(default_factory=list)
        root_path: Path = Path(".")

    if not prior:
        return _Prior()
    detail = None
    for entry in prior.get("surface_detail") or []:
        if entry.get("surface") == "source_code":
            detail = entry
            break
    if detail is None:
        return _Prior()
    return _Prior(
        files_scanned=int(detail.get("files_scanned") or 0),
        files_skipped=0,
        total_lines=0,
        total_matches=int(prior.get("total_raw_findings") or asset_count),
        missing_grammars=[],
        file_results=[],
    )


def _resolve_inputs(
    scan_id: str, job_dir: Path, session_factory
) -> tuple[Path, list[Path], list[str], dict]:
    """Resolve a persisted scan's inputs to concrete local paths.

    Returns (target_path, cert_paths, surfaces, extra) where extra carries
    the binary paths, container refs/contexts, and infra endpoints for the
    pipeline's new surface arguments.
    """
    with session_factory() as session:
        record = session.get(ScanRecord, scan_id)
        if record is None:  # pragma: no cover - defensive
            raise ScanInputError("Scan job no longer exists.")
        source_kind = record.source_kind
        source_ref = record.source_ref
        include_certificates = record.include_certificates
        cert_refs = list(record.cert_refs or [])
        binary_refs = list(record.binary_refs or [])
        container_refs = list(record.container_refs or [])
        infra_endpoints = list(record.infra_endpoints or [])
        recorded = list(record.recorded_only_surfaces or [])
        llm_requested = bool(getattr(record, "llm_enrichment_requested", False))

    surfaces = ["source_code"]
    extra: dict = {
        "binary_paths": [],
        "container_refs": [],
        "container_contexts": {},
        "infra_endpoints": [],
        "run_llm_enrichment": llm_requested,
    }
    if source_kind == SOURCE_KIND_DEMO:
        extra["binary_paths"] = [Path(p) for p in binary_refs if Path(p).exists()]
        extra["container_refs"] = list(container_refs)
        extra["infra_endpoints"] = []
        return DEMO_REPOSITORY, [Path(p) for p in cert_refs], surfaces + (
            ["certificate"] if cert_refs else []
        ) + (["binary"] if extra["binary_paths"] else []), extra
    if source_kind == SOURCE_KIND_LOCAL_PATH:
        assert source_ref is not None
        target = Path(source_ref)
        if not target.exists():
            raise ScanInputError(f"source_path no longer exists: {source_ref}")
        if not target.is_dir():
            raise ScanInputError("source_path must be a directory to scan.")
        target_path, cert_paths, surfaces = _with_certs(
            target, cert_refs, include_certificates, surfaces)
        _attach_surface_inputs(target_path, extra, binary_refs, container_refs,
                               infra_endpoints, surfaces)
        return target_path, cert_paths, surfaces, extra
    if source_kind == SOURCE_KIND_REPO_URL:
        assert source_ref is not None
        target = _clone_repo(job_dir, source_ref)
        target_path, cert_paths, surfaces = _with_certs(
            target, cert_refs, include_certificates, surfaces)
        _attach_surface_inputs(target_path, extra, binary_refs, container_refs,
                               infra_endpoints, surfaces)
        return target_path, cert_paths, surfaces, extra
    if source_kind == SOURCE_KIND_UPLOAD_TREE:
        assert source_ref is not None
        staged = UPLOAD_ROOT / source_ref
        if not staged.is_dir():
            raise ScanInputError("Uploaded file tree expired before the scan ran.")
        target = job_dir / "upload"
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(staged, target)
        target_path, cert_paths, surfaces = _with_certs(
            target, cert_refs, include_certificates, surfaces)
        _attach_surface_inputs(target_path, extra, binary_refs, container_refs,
                               infra_endpoints, surfaces)
        return target_path, cert_paths, surfaces, extra
    raise ScanInputError(f"Unsupported source_kind: {source_kind}")  # pragma: no cover


def _with_certs(
    target: Path, cert_refs: list[str], include: bool, surfaces: list[str]
) -> tuple[Path, list[Path], list[str]]:
    """Resolve certificate inputs; a bare source tree also scans itself for certs."""
    resolved: list[Path] = []
    for ref in cert_refs:
        if ref.startswith("upload:"):
            staged = UPLOAD_ROOT / ref.split(":", 1)[1]
            if not staged.is_dir():
                raise ScanInputError("Uploaded certificates expired before the scan ran.")
            resolved.append(staged)
            continue
        candidate = Path(ref)
        if not candidate.exists():
            raise ScanInputError(f"certificate path does not exist: {ref}")
        resolved.append(candidate)
    surfaces = list(surfaces)
    if include:
        resolved.append(target)
    if resolved:
        surfaces.append("certificate")
    return target, resolved, surfaces


def _attach_surface_inputs(
    target_path: Path,
    extra: dict,
    binary_refs: list[str],
    container_refs: list[str],
    infra_endpoints: list[str],
    surfaces: list[str],
) -> None:
    """Resolve binary/container/infra refs against the scanned tree."""
    resolved_binary: list[Path] = []
    for ref in binary_refs:
        candidate = Path(ref)
        if not candidate.is_absolute():
            candidate = target_path / ref
        if candidate.exists():
            resolved_binary.append(candidate)
    if resolved_binary:
        surfaces.append("binary")
    extra["binary_paths"] = resolved_binary

    contexts: dict[str, Path] = {}
    for ref in container_refs:
        candidate = Path(ref)
        if not candidate.is_absolute():
            candidate = target_path / ref
        if candidate.is_dir():
            contexts[ref] = candidate
    if container_refs:
        surfaces.append("container")
    extra["container_refs"] = list(container_refs)
    extra["container_contexts"] = contexts

    valid_endpoints = [ep.strip() for ep in infra_endpoints if ep.strip()]
    if valid_endpoints:
        surfaces.append("infrastructure")
    extra["infra_endpoints"] = valid_endpoints


def _recorded_only_surfaces(
    binary_refs: Optional[list[str]],
    container_refs: Optional[list[str]],
    infra_endpoints: Optional[list[str]],
) -> list[str]:
    """Surfaces accepted as references (kept for backward compatibility)."""
    return []


def _scan_to_dict(record: ScanRecord) -> dict:
    return {
        "scan_id": record.id,
        "target": record.target_label,
        "status": record.status,
        "stage": record.stage,
        "user_id": record.user_id,
        "source_kind": record.source_kind,
        "source_ref": record.source_ref,
        "include_certificates": record.include_certificates,
        "llm_enrichment_requested": bool(
            getattr(record, "llm_enrichment_requested", False)),
        "cert_refs": list(record.cert_refs or []),
        "binary_refs": list(record.binary_refs or []),
        "container_refs": list(record.container_refs or []),
        "infrastructure_endpoints": list(record.infra_endpoints or []),
        "recorded_only_surfaces": list(record.recorded_only_surfaces or []),
        "error": record.error,
        "asset_count": record.asset_count,
        "certificate_asset_count": record.certificate_asset_count,
        "surface_counts": dict(getattr(record, "surface_counts", None) or {}),
        "priority_counts": dict(record.priority_counts or {}),
        "hndl_flagged_count": record.hndl_count,
        "completeness": record.completeness,
        "scanned_surfaces": list(record.scanned_surfaces or []),
        "reachability": record.reachability,
        "cbom_component_count": record.cbom_component_count,
        "cbom_quality": record.cbom_quality,
        "created_at": _iso(record.created_at),
        "started_at": _iso(record.started_at),
        "completed_at": _iso(record.completed_at),
    }


def _priority_counts_dict(row: dict) -> dict[str, int]:
    counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    counts.update(row.get("priority_counts") or {})
    return counts


def _scan_summary(row: dict) -> dict:
    return {
        "scan_id": row["scan_id"],
        "target": row["target"],
        "status": row["status"],
        "stage": row["stage"],
        "completed_at": row["completed_at"],
        "asset_count": row["asset_count"],
        "certificate_asset_count": row["certificate_asset_count"],
    }


def _iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.isoformat()
    return str(value)
