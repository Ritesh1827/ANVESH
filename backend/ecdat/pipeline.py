"""
ECDAT Pipeline — top-level orchestrator.

Implements the full pipeline as defined in PRD §5 and §7:

  Stage 2:  Source Discovery              (discovery/source_scanner.py)
  Stage 4:  Evidence Engine               (engines/evidence_engine.py)
  Stage 5:  Crypto Asset Inventory        (engines/inventory.py)
  Stage 6:  Classification & Business     (engines/classification_engine.py) ← new
  Stage 7:  Reachability & Context        (engines/reachability_engine.py)
  Stage 8:  Discovery Completeness        (engines/completeness_engine.py)
  Stage 9:  Mosca Risk Engine             (engines/mosca_engine.py)
              ↑ receives classified + reachability-annotated assets so that
                both _classification_weight() and _reachability_weight()
                reflect real values, not staging defaults
  Stage 10: PQC Recommendation            (engines/recommendation_engine.py)

Pipeline ordering follows PRD §7 architecture diagram exactly:
  Inventory → Classification → Reachability → Completeness →
  Mosca Risk → PQC Recommendation → CBOM / Reports / Dashboard

Reference: PRD §5 (pipeline stages), §7 (architecture diagram),
           §6 (Read-only guarantee), §8 (editable config data).
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import NoReturn, Optional

from ecdat.discovery.rule_loader import load_rules, DetectionRule
from ecdat.discovery.source_scanner import scan_directory, DirectoryScanResult
from ecdat.engines.inventory import (
    CryptoAssetInventory,
    build_inventory_from_scan,
    ingest_cert_scan_into_inventory,
)
from ecdat.engines.classification_engine import ClassificationEngine
from ecdat.engines.ownership_engine import apply_ownership
from ecdat.engines.reachability_engine import ReachabilityEngine, ReachabilityReport
from ecdat.engines.completeness_engine import (
    DiscoveryCompletenessEngine,
    DiscoveryCompletenessResult,
    DEFAULT_EXPECTED_CATEGORIES,
)
from ecdat.engines.mosca_engine import MoscaEngine
from ecdat.engines.recommendation_engine import RecommendationEngine
from ecdat.discovery.cert_scanner import (
    scan_certificate_file,
    scan_certificate_directory,
    CertDirectoryScanResult,
    CERT_EXTENSIONS,
)
from ecdat.discovery.binary_scanner import (
    load_fingerprint_rules as load_binary_fingerprint_rules,
    scan_binary_paths,
    BinaryDirectoryScanResult,
)
from ecdat.discovery.container_scanner import (
    load_container_rules,
    scan_container_refs,
    ContainerScanResults,
)
from ecdat.discovery.infra_scanner import (
    load_infra_rules,
    probe_endpoints,
    InfraScanResults,
)
from ecdat.llm.llm_enrichment import LLMEnrichmentEngine
from ecdat.engines.migration_impact import MigrationImpactEngine, MigrationRoadmap
from ecdat.engines.cbom_exporter import CBOMExporter, ExportResult
from ecdat.schemas import CryptoAsset, RiskPriority

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """
    Result of running the ECDAT pipeline on a target directory.

    Contains raw scan statistics, the enriched inventory (with reachability,
    risk, and recommendations), and the scan_id linking all records in this run.
    """
    scan_id: str
    target_path: Path
    scan_result: DirectoryScanResult
    inventory: CryptoAssetInventory
    rules_loaded: int

    # Enriched assets — progressively annotated by each engine:
    #   inventory assets  (staging classification defaults from Evidence Engine)
    #   → classification annotations  (stage 6 — definitive values)
    #   → reachability annotations    (stage 7)
    #   → risk scores                 (stage 9, after classification + reachability)
    #   → PQC recommendations         (stage 10)
    scored_assets: list[CryptoAsset] = field(default_factory=list)

    # Stage 7: Reachability report
    reachability_report: Optional[ReachabilityReport] = None

    # Stage 8: Discovery completeness
    completeness: Optional[DiscoveryCompletenessResult] = None

    # Certificate scan results (None if no cert paths provided)
    cert_scan_result: Optional[CertDirectoryScanResult] = None

    # Binary scan results (None if no binary paths provided)
    binary_scan_result: Optional[BinaryDirectoryScanResult] = None

    # Container scan results (None if no container refs provided)
    container_scan_result: Optional[ContainerScanResults] = None

    # Infrastructure probe results (None if no endpoints provided)
    infra_scan_result: Optional[InfraScanResults] = None

    # Stage 11: Migration Impact Analysis roadmaps (asset_id → MigrationRoadmap)
    migration_roadmaps: dict = field(default_factory=dict)

    # Stage 12: CBOM export result (None if not run)
    cbom_export_result: Optional[ExportResult] = None

    # Partial-run bookkeeping: when the pipeline is interrupted partway
    # (stage failure), completed_stages records how far enrichment got and
    # failure_stage/failure_error record where it stopped. scored_assets
    # then holds whatever was found before the failure point — never
    # discarded. A fully successful run has failure_stage=None.
    completed_stages: list[str] = field(default_factory=list)
    failure_stage: Optional[str] = None
    failure_error: Optional[str] = None

    def report(self) -> str:
        """Return a human-readable pipeline summary."""
        inv = self.inventory
        s = inv.stats

        assets = self.scored_assets if self.scored_assets else inv.assets

        # Risk priority breakdown
        priority_counts: dict[str, int] = {}
        hndl_count = 0
        for a in assets:
            if a.risk:
                p = a.risk.priority.value
                priority_counts[p] = priority_counts.get(p, 0) + 1
                if a.risk.hndl_flag:
                    hndl_count += 1

        # Reachability breakdown
        reachable_count = sum(1 for a in assets if a.reachable is True)
        unreachable_count = sum(1 for a in assets if a.reachable is False)
        unknown_reach = sum(1 for a in assets if a.reachable is None)

        lines = [
            "ECDAT Pipeline Report",
            "=" * 60,
            f"Scan ID      : {self.scan_id}",
            f"Target       : {self.target_path}",
            f"Rules loaded : {self.rules_loaded}",
            "",
            "Scan Statistics",
            f"  Files scanned   : {self.scan_result.files_scanned}",
            f"  Files skipped   : {self.scan_result.files_skipped}",
            f"  Lines scanned   : {self.scan_result.total_lines:,}",
            f"  Raw matches     : {self.scan_result.total_matches}",
            *([
                "  WARNING         : missing tree-sitter grammar(s): "
                f"{', '.join(getattr(self.scan_result, 'missing_grammars', []) or [])}. "
                "Install the tree-sitter-* package(s) and re-run the scan."
            ] if getattr(self.scan_result, "missing_grammars", None) else []),
            "",
            "Inventory",
            f"  Unique assets   : {s.unique_assets}",
            f"  Duplicates      : {s.duplicates_removed}",
            f"  Duplicate rate  : {s.duplicate_rate:.1%}",
            "",
        ]

        # Classification section (always shown — stage 6 always runs)
        infra_count = sum(1 for a in assets if a.classification.value == "infrastructure")
        app_count = len(assets) - infra_count
        legacy_count = sum(1 for a in assets if a.lifecycle_stage.value == "legacy")
        expired_count = sum(1 for a in assets if a.lifecycle_stage.value == "expired")
        rotation_count = sum(1 for a in assets if a.lifecycle_stage.value == "rotation_pending")
        cert_count = sum(1 for a in assets if a.source_surface == "certificate")
        lines += [
            "Classification (Stage 6)",
            f"  Application     : {app_count}",
            f"  Infrastructure  : {infra_count}",
            f"  Legacy lifecycle: {legacy_count}",
        ]
        if cert_count:
            lines += [
                f"  Certificate assets: {cert_count}",
                f"  Expired certs   : {expired_count}",
                f"  Rotation pending: {rotation_count}",
            ]
        lines.append("")

        if self.reachability_report is not None:
            rr = self.reachability_report
            lines += [
                "Reachability (Stage 7)",
                f"  Reachable       : {reachable_count}",
                f"  Unreachable     : {unreachable_count}",
                f"  Unknown         : {unknown_reach}",
                f"  Entry points    : {len(rr.entry_points_found)}",
                f"  Call-graph nodes: {rr.graph_node_count}",
                f"  Call-graph edges: {rr.graph_edge_count}",
                "",
            ]

        # Discovery completeness section (only if computed)
        if self.completeness is not None:
            c = self.completeness
            lines += [
                "Discovery Completeness (Stage 8)",
                f"  Overall         : {c.overall_completeness_pct:.0f}%",
                f"  Surface coverage: {c.surface_completeness_pct:.0f}% "
                f"({c.surfaces_scanned}/{c.surfaces_total} surfaces)",
                f"  Category coverage: {c.category_completeness_pct:.0f}% "
                f"({c.categories_found}/{c.categories_expected} expected categories)",
            ]
            if c.missing_expected_categories:
                lines.append(
                    f"  Missing categories: {', '.join(c.missing_expected_categories)}"
                )
            if c.unscanned_surfaces:
                lines.append(
                    f"  Unscanned surfaces: {', '.join(c.unscanned_surfaces)}"
                )
            lines.append("")

        if priority_counts:
            lines += [
                "Risk Summary (Stage 9)",
                f"  P1 (Critical)   : {priority_counts.get('P1', 0)}",
                f"  P2 (High)       : {priority_counts.get('P2', 0)}",
                f"  P3 (Medium)     : {priority_counts.get('P3', 0)}",
                f"  P4 (Low)        : {priority_counts.get('P4', 0)}",
                f"  HNDL flagged    : {hndl_count}",
                "",
            ]

        # Migration Impact section (only if computed)
        if self.migration_roadmaps:
            priorities = [r.migration_priority
                          for r in self.migration_roadmaps.values()]
            lines += [
                "Migration Impact (Stage 11)",
                f"  Immediate       : {priorities.count('immediate')}",
                f"  Near-term       : {priorities.count('near-term')}",
                f"  Planned         : {priorities.count('planned')}",
                f"  Monitor         : {priorities.count('monitor')}",
                "",
            ]

        # CBOM export section (only if exported)
        if self.cbom_export_result is not None:
            ce = self.cbom_export_result
            q = ce.cbom_export.quality_score
            lines += [
                "CBOM Export (Stage 12)",
                f"  Components      : {ce.component_count}",
                f"  Format          : {ce.format.value}",
            ]
            if q:
                lines += [
                    f"  Quality score   : {q.overall_quality:.2f}",
                    f"  Evidence cov.   : {q.evidence_coverage:.2f}",
                    f"  Risk coverage   : {q.risk_coverage:.2f}",
                    f"  Rec. coverage   : {q.recommendation_coverage:.2f}",
                ]
            lines.append("")

        lines.append("Assets (by location):")
        for asset in sorted(assets, key=lambda a: (
            a.evidence.location.file_path,
            a.evidence.location.line_number or 0,
        )):
            risk_str = ""
            hndl_str = ""
            rec_str = ""
            reach_str = ""
            if asset.reachable is True:
                reach_str = " [REACH]"
            elif asset.reachable is False:
                reach_str = " [UNREACH]"
            if asset.risk:
                risk_str = f" [{asset.risk.priority.value}]"
                hndl_str = " HNDL" if asset.risk.hndl_flag else ""
            if asset.recommendation:
                rec_str = f" → {asset.recommendation.standardized_replacement}"

            lines.append(
                f"  {asset.location:<45} "
                f"{asset.algorithm:<20} "
                f"{asset.purpose.value:<22}"
                f"{reach_str}{risk_str}{hndl_str}{rec_str}"
            )
        return "\n".join(lines)


def run_pipeline(
    target_path: Path,
    rules_path: Optional[Path] = None,
    classification_rules_path: Optional[Path] = None,
    mosca_profiles_path: Optional[Path] = None,
    pqc_mappings_path: Optional[Path] = None,
    scan_id: Optional[str] = None,
    exclude_dirs: Optional[set[str]] = None,
    run_classification: bool = True,
    run_reachability: bool = True,
    run_completeness: bool = True,
    run_mosca: bool = True,
    run_recommendations: bool = True,
    scanned_surfaces: Optional[list[str]] = None,
    expected_categories: Optional[set[str]] = None,
    cert_paths: Optional[list[Path]] = None,
    binary_paths: Optional[list[Path]] = None,
    binary_fingerprints_path: Optional[Path] = None,
    container_refs: Optional[list[str]] = None,
    container_rules_path: Optional[Path] = None,
    container_contexts: Optional[dict[str, Path]] = None,
    infra_endpoints: Optional[list[str]] = None,
    infra_rules_path: Optional[Path] = None,
    infra_timeout_s: float = 10.0,
    run_llm_enrichment: bool = False,
    llm_redis_client=None,
    run_migration: bool = False,
    run_cbom_export: bool = False,
    migration_weights_path: Optional[Path] = None,
    cbom_export_format: str = "json",
) -> PipelineResult:
    """
    Run the full ECDAT pipeline on a target directory.

    Stage order (per PRD §7 architecture diagram):
      2.  Source discovery (tree-sitter AST analysis)
      2b. Certificate discovery (X.509 parsing)   [if cert_paths provided]
      2c. Binary fingerprinting (ELF/PE symbols)  [if binary_paths provided]
      2d. Container layer inspection (manifests)  [if container_refs provided]
      2e. Infrastructure TLS probe (handshakes)   [if infra_endpoints provided]
      4.  Evidence Engine  (location, confidence, finding assembly)
          → assets carry STAGING classification defaults (APPLICATION/INTERNAL/LOW)
      5.  Crypto Asset Inventory (deduplication, correlation)
          → cert/binary/container/infra assets ingested into the same inventory
      6.  Classification & Business Context                   [if run_classification]
          → overwrites staging defaults with config-driven values
          → runs on ALL assets from every surface
      6b. Ownership (user-configured mapping)     [if run_classification]
      7.  Reachability & Context (call-graph, NetworkX)       [if run_reachability]
          → non-source assets receive reachable=None (no call graph),
            except infra TLS-probe assets which are reachable=True by
            construction (the handshake itself is the exposure proof)
      8.  Discovery Completeness                              [if run_completeness]
      9.  Mosca Risk Engine (X+Y>Z, HNDL, priority)          [if run_mosca]
      10. PQC Recommendation Engine                           [if run_recommendations]

    Args:
        target_path:                Root directory to scan for source code.
        rules_path:                 Path to detection_rules.yaml.
        classification_rules_path:  Path to classification_rules.yaml.
        mosca_profiles_path:        Path to mosca_profiles.yaml.
        pqc_mappings_path:          Path to pqc_mappings.yaml.
        scan_id:                    Optional scan run identifier.
        exclude_dirs:               Directories to skip.
        run_classification:         Whether to run the Classification engine.
        run_reachability:           Whether to run the Reachability engine.
        run_completeness:           Whether to compute Discovery Completeness.
        run_mosca:                  Whether to run the Mosca Risk Engine.
        run_recommendations:        Whether to run the Recommendation Engine.
        scanned_surfaces:           Explicit input surfaces for completeness reporting.
                                    Auto-populated from cert_paths when None.
        expected_categories:        Expected algorithm categories for completeness.
        cert_paths:                 List of paths (files or directories) to scan
                                    for X.509 certificate files.
                                    None = no certificate scanning.
        binary_paths:               List of paths (binary files or directories) to
                                    fingerprint for crypto symbols.
                                    None = no binary scanning.
        binary_fingerprints_path:   Path to binary_fingerprints.yaml.
        container_refs:             List of container image references or local
                                    unpacked-context directories.
                                    None = no container inspection.
        container_rules_path:       Path to container_rules.yaml.
        container_contexts:         Optional ref → local directory mapping for
                                    layer inspection of image references.
        infra_endpoints:            List of host or host:port endpoints for the
                                    read-only TLS probe.
                                    None = no infrastructure probing.
        infra_rules_path:           Path to infra_rules.yaml.
        infra_timeout_s:            Per-endpoint TLS handshake timeout.
        run_llm_enrichment:         Whether to run LLM enrichment on ambiguous
                                    findings (purpose=UNKNOWN). Default False.
                                    Requires LLM_PROVIDER and API key in env.
        llm_redis_client:           Optional Redis client for LLM result caching.
                                    None = LLM enrichment runs without cache.
        run_migration:              Whether to run Migration Impact Analysis (stage 11).
                                    Requires recommendations to be present.
        run_cbom_export:            Whether to produce a CycloneDX CBOM export (stage 12).
        migration_weights_path:     Path to migration_weights.yaml.
        cbom_export_format:         "json" (default) or "xml".

    Returns:
        PipelineResult with fully enriched inventory and all stage outputs.
    """
    target_path = Path(target_path)
    if not target_path.exists():
        raise FileNotFoundError(f"Target path not found: {target_path}")

    if scan_id is None:
        scan_id = str(uuid.uuid4())

    logger.info("Starting ECDAT pipeline [%s] on: %s", scan_id, target_path)

    # ── Stage 2: Load rules + Source Discovery ────────────────────────────────
    rules: list[DetectionRule] = load_rules(rules_path)
    logger.info("Loaded %d detection rules", len(rules))

    scan_result = scan_directory(
        root_path=target_path,
        rules=rules,
        exclude_dirs=exclude_dirs,
    )

    # ── Stage 2b: Certificate Discovery ──────────────────────────────────────
    # Scan any provided certificate paths (files or directories).
    # Certificate scanning runs alongside source discovery at stage 2.
    # Certificate assets are ingested into the same inventory at stage 5.
    combined_cert_scan: Optional[CertDirectoryScanResult] = None
    if cert_paths:
        all_cert_results = []
        total_cert_skipped = 0
        for cert_path in cert_paths:
            cert_p = Path(cert_path)
            if not cert_p.exists():
                logger.warning("Certificate path not found: %s — skipping", cert_p)
                continue
            if cert_p.is_file():
                # Single certificate file — scan_certificate_file returns None
                # only for unsupported extensions; anything else is recorded.
                result = scan_certificate_file(
                    cert_p,
                    scan_id=scan_id,
                    relative_to=cert_p.parent,
                )
                if result is not None:
                    all_cert_results.append(result)
                else:
                    total_cert_skipped += 1
            else:
                # Directory — recurse
                dir_result = scan_certificate_directory(
                    cert_p,
                    scan_id=scan_id,
                    relative_to=cert_p,
                    exclude_dirs=exclude_dirs,
                )
                all_cert_results.extend(dir_result.cert_results)
                total_cert_skipped += dir_result.files_skipped

        if all_cert_results:
            # Consolidate into a single CertDirectoryScanResult for PipelineResult
            combined_cert_scan = CertDirectoryScanResult(
                root_path=Path(cert_paths[0]) if cert_paths else target_path,
                cert_results=all_cert_results,
                files_scanned=len(all_cert_results),
                files_skipped=total_cert_skipped,
            )
            logger.info(
                "Certificate scan: %d files, %d assets extracted",
                combined_cert_scan.files_scanned,
                combined_cert_scan.total_assets,
            )

    # ── Stage 2c: Binary fingerprinting ─────────────────────────────────────
    # Symbol/import fingerprinting via pyelftools (+ raw-string fallback).
    # Assets are fully formed and ingested into the same inventory at stage 5.
    combined_binary_scan: Optional[BinaryDirectoryScanResult] = None
    if binary_paths:
        resolved_binary = [Path(p) for p in binary_paths]
        combined_binary_scan = scan_binary_paths(
            resolved_binary,
            scan_id=scan_id,
            exclude_dirs=exclude_dirs,
        )
        logger.info(
            "Binary scan: %d files, %d assets extracted",
            combined_binary_scan.files_scanned,
            combined_binary_scan.total_assets,
        )

    # ── Stage 2d: Container layer inspection ─────────────────────────────────
    # Manifest-level inspection of unpacked contexts; bare image references
    # are recorded with zero assets (no registry pulls — PRD §11).
    combined_container_scan: Optional[ContainerScanResults] = None
    if container_refs:
        contexts = (
            {k: Path(v) for k, v in container_contexts.items()}
            if container_contexts else None
        )
        combined_container_scan = scan_container_refs(
            list(container_refs),
            scan_id=scan_id,
            local_contexts=contexts,
        )
        logger.info(
            "Container scan: %d refs, %d assets extracted",
            combined_container_scan.refs_scanned,
            combined_container_scan.total_assets,
        )

    # ── Stage 2e: Infrastructure TLS probe ───────────────────────────────────
    # Read-only handshakes against explicit endpoints (PRD §11: defined set,
    # not a network sweep). Failures are recorded, never findings.
    combined_infra_scan: Optional[InfraScanResults] = None
    if infra_endpoints:
        combined_infra_scan = probe_endpoints(
            list(infra_endpoints),
            scan_id=scan_id,
            timeout_s=infra_timeout_s,
        )
        logger.info(
            "Infrastructure probe: %d endpoints, %d assets extracted",
            combined_infra_scan.endpoints_probed,
            combined_infra_scan.total_assets,
        )

    # ── Stages 4 + 5: Evidence Engine → Inventory ────────────────────────────
    inventory = build_inventory_from_scan(
        scan_result=scan_result,
        scan_id=scan_id,
        relative_to=target_path,
    )
    logger.info("Source inventory built: %d unique assets", inventory.stats.unique_assets)

    # ── Stage 5 (continued): Certificate assets → same inventory ─────────────
    # Certificate assets bypass the Evidence Engine (already fully formed by
    # cert_scanner.py) and are added directly to the inventory for unified
    # deduplication and correlation.
    if combined_cert_scan is not None:
        ingest_cert_scan_into_inventory(inventory, combined_cert_scan)
        logger.info(
            "Inventory after certificate ingestion: %d unique assets",
            inventory.stats.unique_assets,
        )

    # ── Stage 5 (continued): Binary/container/infra assets → same inventory ──
    # Same discipline as certificates: fully formed assets with staging
    # classification defaults, deduplicated and correlated together in the
    # one inventory. No parallel path for any surface.
    if combined_binary_scan is not None:
        for binary_result in combined_binary_scan.binary_results:
            for asset in binary_result.assets:
                inventory.add_asset(asset)
            inventory.stats.files_processed += 1
        logger.info(
            "Inventory after binary ingestion: %d unique assets",
            inventory.stats.unique_assets,
        )
    if combined_container_scan is not None:
        for container_result in combined_container_scan.results:
            for asset in container_result.assets:
                inventory.add_asset(asset)
        logger.info(
            "Inventory after container ingestion: %d unique assets",
            inventory.stats.unique_assets,
        )
    if combined_infra_scan is not None:
        for endpoint_result in combined_infra_scan.results:
            for asset in endpoint_result.assets:
                inventory.add_asset(asset)
        logger.info(
            "Inventory after infrastructure ingestion: %d unique assets",
            inventory.stats.unique_assets,
        )

    # Determine surfaces for completeness reporting
    # Auto-populate from what was actually scanned
    if scanned_surfaces is None:
        _surfaces = ["source_code"]
        if combined_cert_scan is not None and combined_cert_scan.total_assets > 0:
            _surfaces.append("certificate")
        if combined_binary_scan is not None and combined_binary_scan.files_scanned > 0:
            _surfaces.append("binary")
        if combined_container_scan is not None and combined_container_scan.refs_scanned > 0:
            _surfaces.append("container")
        if combined_infra_scan is not None and combined_infra_scan.endpoints_probed > 0:
            _surfaces.append("infrastructure")
    else:
        _surfaces = scanned_surfaces

    # Start with inventory assets — each engine hands off to the next.
    # Every enrichment stage below is guarded: if a stage raises, the
    # pipeline raises _PartialResult carrying everything found so far
    # (stages are ordered, so earlier results are always valid). The
    # store persists those and marks the scan partial instead of failed.
    assets = list(inventory.assets)
    completed: list[str] = ["source_discovery"]
    for _surface_stage, _present in (
        ("certificate_discovery", combined_cert_scan is not None),
        ("binary_discovery", combined_binary_scan is not None),
        ("container_discovery", combined_container_scan is not None),
        ("infrastructure_discovery", combined_infra_scan is not None),
    ):
        if _present:
            completed.append(_surface_stage)
    completed.append("inventory")

    # Success-path stage list, rebuilt at the end from the live `completed`
    # tracker (guards append as they succeed). Kept as a closure so the
    # happy-path return below reports exactly what ran.
    def _final_stages() -> list[str]:
        return list(completed)

    def _fail_partial(stage: str, error: Exception) -> "NoReturn":
        # Local import: store.py imports run_pipeline at call time, so a
        # module-level import here would be circular.
        from ecdat.persistence.store import _PartialResult

        # Late-bound stage outputs live in locals() only after their stage
        # ran — read defensively so a failure in an early stage (before
        # later names are assigned) still builds a valid partial result.
        frame_locals = locals()
        partial = PipelineResult(
            scan_id=scan_id,
            target_path=target_path,
            scan_result=scan_result,
            inventory=inventory,
            rules_loaded=len(rules),
            scored_assets=list(assets),
            reachability_report=frame_locals.get("reachability_report"),
            completeness=frame_locals.get("completeness"),
            cert_scan_result=combined_cert_scan,
            binary_scan_result=combined_binary_scan,
            container_scan_result=combined_container_scan,
            infra_scan_result=combined_infra_scan,
            migration_roadmaps=dict(frame_locals.get("migration_roadmaps") or {}),
            cbom_export_result=frame_locals.get("cbom_export_result"),
            completed_stages=list(completed),
            failure_stage=stage,
            failure_error=f"{type(error).__name__}: {error}"[:2000],
        )
        raise _PartialResult(partial, list(_surfaces)) from error

    # ── Stage 3b: LLM Enrichment (ambiguous findings only) ───────────────────
    # PRD §5 stage 3b: runs AFTER inventory (so assets are deduplicated) and
    # BEFORE classification (so enriched purpose feeds classification rules).
    # Only assets with purpose=UNKNOWN and a code snippet are processed.
    # Deterministic findings (known purpose) bypass this stage entirely.
    # LLM is DISABLED by default — requires explicit opt-in via run_llm_enrichment=True.
    if run_llm_enrichment and assets:
        try:
            llm_engine = LLMEnrichmentEngine.from_env(redis_client=llm_redis_client)
            assets = llm_engine.process(assets)
            stats = llm_engine.stats
            logger.info(
                "LLM enrichment: %d ambiguous attempted, %d enriched, "
                "%d cache hits, %d failed",
                stats.ambiguous_attempted, stats.enriched,
                stats.cache_hits, stats.failed,
            )
            completed.append("llm_enrichment")
        except Exception as exc:
            _fail_partial("llm_enrichment", exc)

    # ── Stage 6: Classification & Business Context ────────────────────────────
    # MUST run before Reachability and Mosca so that:
    #   - _classification_weight() in Mosca sees real values, not staging defaults
    #   - Completeness category counts reflect classified assets
    if run_classification and assets:
        try:
            cls_engine = ClassificationEngine(rules_path=classification_rules_path)
            assets = cls_engine.process(assets)
            logger.info("Classification complete: %d assets classified", len(assets))
            completed.append("classification")
        except Exception as exc:
            _fail_partial("classification", exc)

    # ── Stage 6b: Ownership (user-configured mapping) ─────────────────────────
    # Applies the organisation's own ownership rules AFTER classification
    # (rules can condition on surface/purpose) and BEFORE Mosca/roadmaps so
    # every downstream stage sees the real owner.
    if run_classification and assets:
        try:
            assets = apply_ownership(assets)
            logger.info("Ownership complete")
            completed.append("ownership")
        except Exception as exc:
            _fail_partial("ownership", exc)

    # ── Stage 7: Reachability & Context ──────────────────────────────────────
    # MUST run before Mosca so that asset.reachable feeds _reachability_weight()
    reachability_report: Optional[ReachabilityReport] = None
    if run_reachability and assets:
        try:
            file_paths = [
                fr.file_path for fr in scan_result.file_results
            ]
            reach_engine = ReachabilityEngine(
                file_paths=file_paths,
                relative_to=target_path,
            )
            assets = reach_engine.process(assets)
            reachability_report = reach_engine.report
            logger.info(
                "Reachability complete: %d reachable, %d unreachable, %d unknown",
                reachability_report.reachable_count,
                reachability_report.unreachable_count,
                reachability_report.unknown_count,
            )
            completed.append("reachability")
        except Exception as exc:
            _fail_partial("reachability", exc)

    # ── Stage 8: Discovery Completeness ───────────────────────────────────────
    completeness: Optional[DiscoveryCompletenessResult] = None
    if run_completeness:
        try:
            comp_engine = DiscoveryCompletenessEngine(
                scan_result=scan_result,
                assets=assets,
                scanned_surfaces=_surfaces,
                expected_categories=expected_categories,
            )
            completeness = comp_engine.compute()
            logger.info(
                "Completeness: %.0f%% overall (%d/%d surfaces, %d/%d categories)",
                completeness.overall_completeness_pct,
                completeness.surfaces_scanned, completeness.surfaces_total,
                completeness.categories_found, completeness.categories_expected,
            )
            completed.append("completeness")
        except Exception as exc:
            _fail_partial("completeness", exc)

    # ── Stage 9: Mosca Risk Engine ────────────────────────────────────────────
    # Receives reachability-annotated assets — asset.reachable is now set,
    # so _reachability_weight() returns the correct weight (1.0/0.5/0.8).
    if run_mosca and assets:
        try:
            mosca = MoscaEngine(
                mosca_profiles_path=mosca_profiles_path,
                pqc_mappings_path=pqc_mappings_path,
            )
            assets = mosca.process(assets)
            logger.info("Mosca engine complete: %d assets scored", len(assets))
            completed.append("mosca")
        except Exception as exc:
            _fail_partial("mosca", exc)

    # ── Stage 10: PQC Recommendation Engine ──────────────────────────────────
    if run_recommendations and assets:
        try:
            rec_engine = RecommendationEngine(pqc_mappings_path=pqc_mappings_path)
            assets = rec_engine.process(assets)
            logger.info("Recommendation engine complete: %d assets annotated", len(assets))
            completed.append("recommendations")
        except Exception as exc:
            _fail_partial("recommendations", exc)

    # ── Stage 11: Migration Impact Analysis ───────────────────────────────────
    # Produces roadmap-style narratives for every asset with a recommendation.
    # Roadmaps are kept in a separate dict (not stored on CryptoAsset) so the
    # CryptoAsset schema does not need to change.
    migration_roadmaps: dict = {}
    if run_migration and assets:
        try:
            migration_engine = MigrationImpactEngine(weights_path=migration_weights_path)
            _, migration_roadmaps = migration_engine.process(assets)
            logger.info(
                "Migration impact: %d roadmaps computed (%d immediate, %d near-term)",
                len(migration_roadmaps),
                migration_engine.stats.immediate,
                migration_engine.stats.near_term,
            )
            completed.append("migration")
        except Exception as exc:
            _fail_partial("migration", exc)

    # ── Stage 12: CBOM Export ─────────────────────────────────────────────────
    # Produces a schema-valid CycloneDX document via cyclonedx-python-lib.
    # Relationships (Phase 7) are computed from the final asset list just
    # before export and passed through — never invented by the exporter.
    cbom_export_result: Optional[ExportResult] = None
    asset_relationships: list[dict] = []
    if run_cbom_export and assets:
        try:
            from ecdat.engines.relationships import build_relationships

            asset_relationships = build_relationships(assets)
            logger.info(
                "Relationships built: %d evidence-backed edges", len(asset_relationships))
        except Exception as exc:
            logger.warning("Relationship building failed (non-fatal): %s", exc)
            asset_relationships = []
    if run_cbom_export and assets:
        try:
            from ecdat.schemas import CBOMFormat
            fmt = CBOMFormat.XML if cbom_export_format.lower() == "xml" else CBOMFormat.JSON
            exporter = CBOMExporter()
            cbom_export_result = exporter.export(
                assets=assets,
                scan_id=scan_id,
                target_path=str(target_path),
                roadmaps=migration_roadmaps or None,
                total_raw_findings=inventory.stats.total_findings,
                scanned_surfaces=_surfaces,
                export_format=fmt,
                completeness_pct=(
                    completeness.overall_completeness_pct if completeness else None
                ),
                relationships=asset_relationships or None,
            )
            logger.info(
                "CBOM export complete: %d components, format=%s, "
                "quality=%.2f",
                cbom_export_result.component_count,
                cbom_export_result.format.value,
                cbom_export_result.cbom_export.quality_score.overall_quality
                if cbom_export_result.cbom_export.quality_score else 0.0,
            )
            completed.append("cbom_export")
        except Exception as exc:
            _fail_partial("cbom_export", exc)

    logger.info("Pipeline complete [%s]", scan_id)

    return PipelineResult(
        scan_id=scan_id,
        target_path=target_path,
        scan_result=scan_result,
        inventory=inventory,
        rules_loaded=len(rules),
        scored_assets=assets,
        reachability_report=reachability_report,
        completeness=completeness,
        cert_scan_result=combined_cert_scan,
        binary_scan_result=combined_binary_scan,
        container_scan_result=combined_container_scan,
        infra_scan_result=combined_infra_scan,
        migration_roadmaps=migration_roadmaps,
        cbom_export_result=cbom_export_result,
        completed_stages=_final_stages(),
    )


# ── Backwards-compatible wrappers ─────────────────────────────────────────────

def run_source_discovery(
    target_path: Path,
    rules_path: Optional[Path] = None,
    scan_id: Optional[str] = None,
    exclude_dirs: Optional[set[str]] = None,
) -> PipelineResult:
    """
    Run source discovery only (stages 2, 4, 5) — no classification, reachability,
    or risk. Backwards-compatible wrapper used by Day 2–3 tests.
    Assets carry staging classification defaults; reachable remains None.
    """
    return run_pipeline(
        target_path=target_path,
        rules_path=rules_path,
        scan_id=scan_id,
        exclude_dirs=exclude_dirs,
        run_classification=False,
        run_reachability=False,
        run_completeness=False,
        run_mosca=False,
        run_recommendations=False,
    )
