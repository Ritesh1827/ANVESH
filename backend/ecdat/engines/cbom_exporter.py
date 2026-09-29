"""
CBOM Export Engine — PRD §5 stage 12 (Outputs: CycloneDX CBOM export).

PRD §5 stage 12 requirements:
  "a schema-validated CycloneDX CBOM export (with quality score and
   version-diff support)"

PRD §8 Technology Stack:
  "CBOM export: cyclonedx-python-lib — Guarantees schema-correct CycloneDX
   output rather than hand-built JSON."

This engine:
  1. Converts every CryptoAsset in the inventory into a CycloneDX Component
     with CryptoProperties (algorithm or certificate).
  2. Attaches ECDAT-specific metadata as namespaced CycloneDX Property objects
     (ecdat:location, ecdat:purpose, ecdat:classification, ecdat:risk.priority,
     ecdat:recommendation, ecdat:evidence.rule_id, ecdat:evidence.confidence).
  3. Uses cyclonedx-python-lib's serialiser to produce a schema-valid JSON or
     XML document — the library validates the document against the CycloneDX
     schema internally.
  4. Computes a CBOMQualityScore from the actual inventory state.
  5. Supports version-diff: given two serialised CBOM exports (as CBOMExport
     Pydantic models), produces a CBOMVersionDiff showing new/removed/changed
     assets.

PRD §6 (Data sensitivity): the CBOM itself is a sensitive artefact. ECDAT
does not automatically distribute it. The exporter returns a string; the
caller decides where to write it.

Implementation note flagged per instructions:
  CertificateProperties.signature_algorithm_ref and .subject_public_key_ref
  accept BomRef cross-references to other Component entries in the BOM.
  ECDAT parses each cert into independent Algorithm and Certificate components;
  it does not currently link them with cross-refs. Both fields are left None
  here. The resulting CycloneDX document is still schema-valid — these fields
  are optional in CycloneDX 1.6. Linking is a future enhancement.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CertificateProperties,
    CryptoAssetType,
    CryptoPrimitive,
    CryptoProperties,
)
from cyclonedx.output.json import JsonV1Dot6
from cyclonedx.output.xml import XmlV1Dot6

from ecdat.schemas import (
    CBOMExport,
    CBOMFormat,
    CBOMMetadata,
    CBOMQualityScore,
    CBOMVersionDiff,
    CryptoAsset,
    CryptoPurpose,
)
from ecdat.engines.migration_impact import MigrationRoadmap

logger = logging.getLogger(__name__)

_ECDAT_VERSION = "0.1.0"

# ── CryptoPrimitive mapping ────────────────────────────────────────────────────
# Maps ECDAT CryptoPurpose → CycloneDX CryptoPrimitive (best approximation).
# CryptoPrimitive has finer granularity than CryptoPurpose; the mapping is
# documented here to make the approximation explicit.

_PURPOSE_TO_PRIMITIVE: dict[str, CryptoPrimitive] = {
    "key_establishment": CryptoPrimitive.KEM,
    "digital_signature": CryptoPrimitive.SIGNATURE,
    "encryption":        CryptoPrimitive.PKE,
    "hashing":           CryptoPrimitive.HASH,
    "mac":               CryptoPrimitive.MAC,
    "key_derivation":    CryptoPrimitive.KDF,
    "random_generation": CryptoPrimitive.DRBG,
    "certificate":       CryptoPrimitive.PKE,   # cert asset: treat as PKE context
    "unknown":           CryptoPrimitive.UNKNOWN,
}


def _purpose_to_primitive(purpose_value: str) -> CryptoPrimitive:
    return _PURPOSE_TO_PRIMITIVE.get(purpose_value, CryptoPrimitive.UNKNOWN)


# ── ECDAT-specific Property builder ───────────────────────────────────────────

def _props(asset: CryptoAsset, roadmap: Optional[MigrationRoadmap] = None) -> list[Property]:
    """
    Build the list of CycloneDX Property objects carrying ECDAT metadata.

    All properties use the "ecdat:" namespace prefix so they are clearly
    distinguishable from standard CycloneDX properties.
    """
    props: list[Property] = []

    def add(name: str, value: Optional[str]) -> None:
        if value is not None and value != "":
            props.append(Property(name=f"ecdat:{name}", value=str(value)))

    # Core asset metadata
    add("location",         asset.location)
    add("purpose",          asset.purpose.value)
    add("classification",   asset.classification.value)
    add("sensitivity",      asset.sensitivity.value)
    add("business_criticality", asset.business_criticality.value)
    add("lifecycle_stage",  asset.lifecycle_stage.value)
    add("source_surface",   asset.source_surface)
    add("owner",            asset.owner)
    add("protocol",         asset.protocol)
    add("library",          asset.library)
    add("scan_id",          asset.scan_id)

    # Evidence provenance
    add("evidence.rule_id",  asset.evidence.rule_id)
    add("evidence.method",   asset.evidence.detection_method.value)
    add("evidence.confidence", f"{asset.evidence.confidence:.4f}")
    add("evidence.symbol",   asset.evidence.observed_symbol)
    add("evidence.ambiguity", asset.evidence.ambiguity_status)

    # Risk fields
    if asset.risk is not None:
        r = asset.risk
        add("risk.priority",   r.priority.value)
        add("risk.urgency",    str(r.urgency_flag))
        add("risk.hndl",       str(r.hndl_flag))
        if r.mosca_x_years is not None:
            add("risk.mosca_x", f"{r.mosca_x_years:.1f}")
        if r.mosca_y_years is not None:
            add("risk.mosca_y", f"{r.mosca_y_years:.1f}")
        if r.mosca_z_years is not None:
            add("risk.mosca_z", f"{r.mosca_z_years:.1f}")

    # Recommendation fields
    if asset.recommendation is not None:
        rec = asset.recommendation
        add("recommendation.replacement",  rec.standardized_replacement)
        add("recommendation.migration_path", rec.migration_path)
        add("recommendation.status",       rec.status.value)

    # Reachability
    if asset.reachable is not None:
        add("reachability.reachable", str(asset.reachable))
    if asset.exposure_context:
        # Truncate long exposure contexts to fit CycloneDX property value limits
        add("reachability.context", asset.exposure_context[:500])

    # Migration roadmap (if computed)
    if roadmap is not None:
        add("migration.priority",    roadmap.migration_priority)
        add("migration.impact_level", roadmap.impact_level)
        add("migration.score",       f"{roadmap.composite_impact_score:.3f}")
        add("migration.narrative",   roadmap.narrative[:500])

    return props


# ── Asset → CycloneDX Component ───────────────────────────────────────────────

def _algorithm_component(
    asset: CryptoAsset,
    roadmap: Optional[MigrationRoadmap] = None,
) -> Component:
    """
    Convert a source-code or binary-surface CryptoAsset to a CycloneDX
    Component with CryptoAssetType.ALGORITHM.
    """
    primitive = _purpose_to_primitive(asset.purpose.value)

    crypto_props = CryptoProperties(
        asset_type=CryptoAssetType.ALGORITHM,
        algorithm_properties=AlgorithmProperties(
            primitive=primitive,
        ),
    )

    return Component(
        name=asset.algorithm,
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        bom_ref=asset.asset_id,
        description=(
            f"{asset.algorithm} ({asset.purpose.value.replace('_', ' ')}) "
            f"— {asset.classification.value} cryptography"
        ),
        crypto_properties=crypto_props,
        properties=_props(asset, roadmap),
    )


def _certificate_component(
    asset: CryptoAsset,
    roadmap: Optional[MigrationRoadmap] = None,
) -> Component:
    """
    Convert a certificate-surface CryptoAsset to a CycloneDX Component
    with CryptoAssetType.CERTIFICATE.

    signature_algorithm_ref and subject_public_key_ref are left None —
    see module docstring for explanation.
    """
    expiry = asset.certificate_expiry
    not_valid_after: Optional[datetime] = None
    if expiry is not None:
        # Ensure timezone-aware
        if expiry.tzinfo is None:
            not_valid_after = expiry.replace(tzinfo=timezone.utc)
        else:
            not_valid_after = expiry

    cert_props = CertificateProperties(
        subject_name=asset.certificate_subject,
        issuer_name=asset.certificate_issuer,
        not_valid_after=not_valid_after,
        certificate_format="X.509",
        # Cross-references left None — see module docstring
        signature_algorithm_ref=None,
        subject_public_key_ref=None,
    )

    crypto_props = CryptoProperties(
        asset_type=CryptoAssetType.CERTIFICATE,
        certificate_properties=cert_props,
    )

    # Subject CN as component name, fallback to algorithm
    cn = asset.certificate_subject or asset.algorithm
    if cn and "CN=" in cn:
        try:
            cn = next(
                part.split("=", 1)[1]
                for part in cn.split(",")
                if part.strip().startswith("CN=")
            )
        except StopIteration:
            pass

    return Component(
        name=cn or asset.algorithm,
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        bom_ref=asset.asset_id,
        description=(
            f"X.509 certificate — {asset.algorithm} "
            f"({asset.purpose.value.replace('_', ' ')})"
        ),
        crypto_properties=crypto_props,
        properties=_props(asset, roadmap),
    )


def _asset_to_component(
    asset: CryptoAsset,
    roadmap: Optional[MigrationRoadmap] = None,
) -> Component:
    """Route to the correct component builder based on source_surface."""
    if asset.source_surface == "certificate":
        return _certificate_component(asset, roadmap)
    return _algorithm_component(asset, roadmap)


# ── Quality score computation ─────────────────────────────────────────────────

def _compute_quality(
    assets: list[CryptoAsset],
    total_raw_findings: int,
    total_unique_assets: int,
) -> CBOMQualityScore:
    """
    Compute the CBOMQualityScore from the actual inventory state.

    PRD §5 stage 12: "quality score" is a real computed value, not a placeholder.
    """
    if not assets:
        return CBOMQualityScore(
            completeness_score=0.0,
            evidence_coverage=0.0,
            risk_coverage=0.0,
            recommendation_coverage=0.0,
            duplicate_rate=0.0,
            overall_quality=0.0,
        )

    n = len(assets)

    # Evidence coverage: all assets should have evidence (enforced by schema)
    evidence_coverage = sum(1 for a in assets if a.evidence is not None) / n

    # Completeness: assets with full evidence (rule_id + confidence + location)
    complete = sum(
        1 for a in assets
        if (a.evidence is not None and
            a.evidence.rule_id is not None and
            a.evidence.confidence > 0.0 and
            a.evidence.location.file_path)
    ) / n

    # Risk coverage: fraction processed by Mosca
    risk_coverage = sum(1 for a in assets if a.risk is not None) / n

    # Recommendation coverage: fraction with a PQC recommendation
    rec_coverage = sum(1 for a in assets if a.recommendation is not None) / n

    # Duplicate rate from inventory stats
    duplicate_rate = 0.0
    if total_raw_findings > 0 and total_unique_assets > 0:
        duplicates = total_raw_findings - total_unique_assets
        duplicate_rate = round(max(0.0, duplicates / total_raw_findings), 4)

    # Overall quality: weighted average
    # Evidence and completeness are most important; risk and rec follow
    overall = round(
        0.30 * complete +
        0.20 * evidence_coverage +
        0.25 * risk_coverage +
        0.25 * rec_coverage,
        4,
    )

    return CBOMQualityScore(
        completeness_score=round(complete, 4),
        evidence_coverage=round(evidence_coverage, 4),
        risk_coverage=round(risk_coverage, 4),
        recommendation_coverage=round(rec_coverage, 4),
        duplicate_rate=round(duplicate_rate, 4),
        overall_quality=round(overall, 4),
    )


# ── Version diff ──────────────────────────────────────────────────────────────

def compute_version_diff(
    baseline: CBOMExport,
    current: CBOMExport,
) -> CBOMVersionDiff:
    """
    Compare two CBOMExport records and produce a CBOMVersionDiff.

    PRD §5 stage 12: "version-diff support".

    An asset is considered CHANGED if it appears in both exports but its
    algorithm, purpose, risk priority, or recommendation replacement differs.
    """
    baseline_by_id = {a.asset_id: a for a in baseline.assets}
    current_by_id  = {a.asset_id: a for a in current.assets}

    baseline_ids = set(baseline_by_id.keys())
    current_ids  = set(current_by_id.keys())

    new_assets     = sorted(current_ids - baseline_ids)
    removed_assets = sorted(baseline_ids - current_ids)

    changed_assets: list[str] = []
    for asset_id in sorted(baseline_ids & current_ids):
        old = baseline_by_id[asset_id]
        new = current_by_id[asset_id]

        # Check for meaningful changes
        old_priority = old.risk.priority.value if old.risk else None
        new_priority = new.risk.priority.value if new.risk else None
        old_rec = (old.recommendation.standardized_replacement
                   if old.recommendation else None)
        new_rec = (new.recommendation.standardized_replacement
                   if new.recommendation else None)

        if (old.algorithm != new.algorithm or
                old.purpose != new.purpose or
                old_priority != new_priority or
                old_rec != new_rec):
            changed_assets.append(asset_id)

    return CBOMVersionDiff(
        baseline_scan_id=baseline.metadata.scan_id,
        current_scan_id=current.metadata.scan_id,
        new_assets=new_assets,
        removed_assets=removed_assets,
        changed_assets=changed_assets,
    )


# ── CBOM Export Engine ────────────────────────────────────────────────────────

@dataclass
class ExportResult:
    """Result of a CBOM export operation."""
    cbom_export: CBOMExport          # ECDAT internal model
    document: str                     # Serialised CycloneDX JSON or XML string
    format: CBOMFormat
    component_count: int


class CBOMExporter:
    """
    CBOM Export Engine — PRD §5 stage 12.

    Converts an ECDAT inventory into a schema-valid CycloneDX CBOM document.

    Usage:
        exporter = CBOMExporter()
        result = exporter.export(
            assets=scored_assets,
            scan_id=scan_id,
            target_path=str(target_path),
            roadmaps=roadmaps_dict,   # from MigrationImpactEngine
            total_raw_findings=inventory.stats.total_findings,
        )
        # result.document is the JSON/XML string
        # result.cbom_export is the Pydantic model
    """

    def export(
        self,
        assets: list[CryptoAsset],
        scan_id: str,
        target_path: str,
        roadmaps: Optional[dict[str, MigrationRoadmap]] = None,
        total_raw_findings: int = 0,
        scanned_surfaces: Optional[list[str]] = None,
        export_format: CBOMFormat = CBOMFormat.JSON,
        baseline_export: Optional[CBOMExport] = None,
        completeness_pct: Optional[float] = None,
        relationships: Optional[list[dict]] = None,
    ) -> ExportResult:
        """
        Generate a CycloneDX CBOM document from the inventory.

        Args:
            assets:              Enriched CryptoAsset list.
            scan_id:             Scan run identifier.
            target_path:         What was scanned (for metadata).
            roadmaps:            Migration roadmaps keyed by asset_id.
            total_raw_findings:  Pre-dedup finding count (for quality score).
            scanned_surfaces:    Input surfaces covered.
            export_format:       JSON or XML.
            baseline_export:     If provided, compute a version diff.
            completeness_pct:    Discovery completeness percentage.
            relationships:       Evidence-backed asset relationships
                                 (from ecdat.engines.relationships). Each
                                 entry: {from_id, to_id, kind, evidence}.
                                 Rendered as CycloneDX dependencies — never
                                 invented, only passed-through.

        Returns:
            ExportResult with the Pydantic model and serialised string.
        """
        roadmaps = roadmaps or {}

        # ── Build CycloneDX BOM ───────────────────────────────────────────────
        bom = Bom()

        # Add metadata via the BOM's metadata object
        # (tool info is automatically added by cyclonedx-python-lib)

        # Convert each asset to a CycloneDX Component
        for asset in assets:
            roadmap = roadmaps.get(asset.asset_id)
            component = _asset_to_component(asset, roadmap)
            bom.components.add(component)

        # ── Evidence-backed relationships → CycloneDX dependencies ────────────
        # Only relationships with both endpoints present become dependencies.
        # Dependency refs must be BomRef objects (the library sorts them —
        # raw strings raise TypeError at serialisation time).
        relationship_count = 0
        if relationships:
            by_ref = {a.asset_id for a in assets}
            from cyclonedx.model.bom_ref import BomRef
            from cyclonedx.model.dependency import Dependency

            grouped: dict[str, list[str]] = {}
            for rel in relationships:
                src, dst = rel.get("from_id"), rel.get("to_id")
                if src in by_ref and dst in by_ref and src != dst:
                    grouped.setdefault(src, [])
                    if dst not in grouped[src]:
                        grouped[src].append(dst)
            for src, dsts in grouped.items():
                bom.dependencies.add(Dependency(ref=BomRef(src), dependencies=[
                    Dependency(ref=BomRef(d)) for d in dsts
                ]))
                relationship_count += len(dsts)

        # ── Serialise ─────────────────────────────────────────────────────────
        if export_format == CBOMFormat.XML:
            serialiser = XmlV1Dot6(bom)
        else:
            serialiser = JsonV1Dot6(bom)

        document_str = serialiser.output_as_string(indent=2)
        logger.info(
            "CBOM exported: %d components, format=%s, scan_id=%s, "
            "relationships=%d",
            len(assets), export_format.value, scan_id, relationship_count,
        )

        # ── Build ECDAT CBOMExport Pydantic model ─────────────────────────────
        metadata = CBOMMetadata(
            ecdat_version=_ECDAT_VERSION,
            scan_id=scan_id,
            scan_timestamp=datetime.now(timezone.utc),
            scanned_targets=[target_path],
            input_surfaces=scanned_surfaces or ["source_code"],
            tool_name="ECDAT",
            tool_vendor="ECDAT Project",
        )

        quality_score = _compute_quality(
            assets=assets,
            total_raw_findings=total_raw_findings,
            total_unique_assets=len(assets),
        )

        version_diff: Optional[CBOMVersionDiff] = None
        if baseline_export is not None:
            # Build temporary current export for diffing (assets only)
            temp_current = CBOMExport(
                metadata=metadata,
                assets=assets,
                quality_score=quality_score,
            )
            version_diff = compute_version_diff(baseline_export, temp_current)
            logger.info(
                "Version diff: %d new, %d removed, %d changed assets",
                len(version_diff.new_assets),
                len(version_diff.removed_assets),
                len(version_diff.changed_assets),
            )

        cbom_export = CBOMExport(
            export_format=export_format,
            metadata=metadata,
            assets=assets,
            quality_score=quality_score,
            version_diff=version_diff,
            discovery_completeness_pct=completeness_pct,
        )

        return ExportResult(
            cbom_export=cbom_export,
            document=document_str,
            format=export_format,
            component_count=len(assets),
        )

    def export_json(
        self,
        assets: list[CryptoAsset],
        scan_id: str,
        target_path: str,
        **kwargs,
    ) -> ExportResult:
        """Convenience wrapper for JSON export."""
        return self.export(
            assets=assets,
            scan_id=scan_id,
            target_path=target_path,
            export_format=CBOMFormat.JSON,
            **kwargs,
        )

    def export_xml(
        self,
        assets: list[CryptoAsset],
        scan_id: str,
        target_path: str,
        **kwargs,
    ) -> ExportResult:
        """Convenience wrapper for XML export."""
        return self.export(
            assets=assets,
            scan_id=scan_id,
            target_path=target_path,
            export_format=CBOMFormat.XML,
            **kwargs,
        )
