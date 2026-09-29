"""
Crypto Asset Inventory — PRD §5 stage 5.

Deduplicates and correlates findings into a single asset record per unique
cryptographic asset. Maintains the authoritative in-memory inventory for
a scan run.

Deduplication key: (algorithm, purpose, file_path, line_number)
  — Two findings for the same call at the same location are the same asset.
  — Two findings for the same algorithm in *different* locations are
    different assets (each occurrence is tracked separately, because
    each may have different reachability, owner, and risk context).

Normalization (Phase 5): every ingested observation is ALSO recorded in
an observation log keyed by normalized asset family
(algorithm-family + purpose + surface). Observations are never deleted:
each keeps its own evidence/location. The normalized view groups them
(RSA → RSA-1024/2048/3072 with occurrence counts + locations) without
destroying per-observation evidence. Deduplication still applies at the
inventory layer; normalization correlates above it.

Correlation:
  — When a duplicate is found, the higher-confidence evidence is kept.
  — Other fields (owner, protocol, library) can be merged in future stages.

The inventory is a read-only advisory store — it never modifies source systems.

Reference: PRD §5 stage 5, §13 (contextual information per asset).
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ecdat.schemas import CryptoAsset
from ecdat.engines.evidence_engine import EvidenceResult, process_file_result
from ecdat.discovery.source_scanner import DirectoryScanResult, FileScanResult
from ecdat.discovery import cert_scanner as _cert_scanner_module

logger = logging.getLogger(__name__)


# ── Deduplication key ─────────────────────────────────────────────────────────

def _dedup_key(asset: CryptoAsset) -> str:
    """
    Compute a stable deduplication key for a CryptoAsset.

    Two assets with the same key are considered the same finding.
    Key: SHA-256 of (algorithm + purpose + file_path + line_number).

    Using a hash keeps the key short and avoids special-character issues
    in dict keys from file paths.
    """
    raw = "|".join([
        asset.algorithm.upper(),
        asset.purpose.value,
        asset.evidence.location.file_path,
        str(asset.evidence.location.line_number or ""),
    ])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── Normalization (Phase 5) ────────────────────────────────────────────────────

def _normalize_family(algorithm: str) -> str:
    """Map a concrete algorithm name to its family for correlation.

    RSA-1024/2048/3072 → RSA; ECDSA-P256 → ECDSA; AES-256-GCM → AES;
    SHA-256 stays SHA-256 (hash output sizes are a meaningful distinction,
    unlike RSA key-size variants). Unknown names map to themselves —
    never silently merged.
    """
    upper = (algorithm or "").upper()
    for family in ("RSA", "ECDSA", "ECDH", "DSA", "DH", "AES", "HMAC",
                   "ML-KEM", "ML-DSA", "SLH-DSA", "FALCON",
                   "ED25519", "ED448", "X25519", "X448",
                   "CHACHA20", "DES", "RC4", "MD5"):
        if upper == family or upper.startswith(family + "-"):
            return family
    return algorithm


def _normalize_key(asset: CryptoAsset) -> str:
    """Family-level correlation key: family + purpose + surface."""
    return "|".join([
        _normalize_family(asset.algorithm),
        asset.purpose.value,
        asset.source_surface,
    ])


@dataclass
class ObservationRecord:
    """One raw observation: never deduplicated, always preserved."""
    algorithm: str
    purpose: str
    file_path: str
    line_number: Optional[int]
    rule_id: Optional[str]
    confidence: float
    observed_symbol: Optional[str] = None


@dataclass
class NormalizedAssetGroup:
    """One correlated family: variants + occurrence counts + locations."""
    family: str
    purpose: str
    source_surface: str
    observation_count: int = 0
    variants: dict = field(default_factory=dict)  # algorithm → count
    locations: list = field(default_factory=list)  # (file, line) tuples

    def summary(self) -> dict:
        return {
            "family": self.family,
            "purpose": self.purpose,
            "source_surface": self.source_surface,
            "observation_count": self.observation_count,
            "variants": dict(self.variants),
            "location_count": len(self.locations),
            "locations": [
                f"{fp}:{ln}" if ln else fp for fp, ln in self.locations[:50]
            ],
        }


# ── Inventory store ───────────────────────────────────────────────────────────

@dataclass
class InventoryStats:
    """Statistics about the inventory build process."""
    total_findings: int = 0          # Raw matches before deduplication
    unique_assets: int = 0           # Assets after deduplication
    duplicates_removed: int = 0      # Findings merged into existing records
    files_processed: int = 0
    algorithms_found: dict[str, int] = field(default_factory=dict)
    purposes_found: dict[str, int] = field(default_factory=dict)

    @property
    def duplicate_rate(self) -> float:
        if self.total_findings == 0:
            return 0.0
        return round(self.duplicates_removed / self.total_findings, 4)


class CryptoAssetInventory:
    """
    In-memory crypto asset inventory for a single scan run.

    Acts as the single source of truth for all discovered cryptographic
    assets after deduplication and correlation.

    PRD §5 stage 5: "Deduplicate and correlate findings into a single
    asset record per unique cryptographic asset."
    """

    def __init__(self, scan_id: Optional[str] = None) -> None:
        self.scan_id = scan_id
        self._assets: dict[str, CryptoAsset] = {}   # dedup_key → CryptoAsset
        self._stats = InventoryStats()
        self._observations: list[ObservationRecord] = []  # Phase 5: never deduped
        self._groups: dict[str, NormalizedAssetGroup] = {}  # norm key → group

    # ── Ingestion ─────────────────────────────────────────────────────────────

    def add_asset(self, asset: CryptoAsset) -> bool:
        """
        Add an asset to the inventory, deduplicating against existing records.

        Returns:
            True  — asset was new, added to inventory.
            False — asset was a duplicate; existing record was updated if the
                    new finding has higher confidence.
        """
        self._stats.total_findings += 1

        # Phase 5: record the observation BEFORE dedup — every occurrence
        # keeps its own evidence/location even when the asset dedups away.
        self._record_observation(asset)

        key = _dedup_key(asset)

        if key not in self._assets:
            # New unique asset
            self._assets[key] = asset
            self._stats.unique_assets += 1

            # Update algorithm/purpose counters
            alg = asset.algorithm
            self._stats.algorithms_found[alg] = (
                self._stats.algorithms_found.get(alg, 0) + 1
            )
            purp = asset.purpose.value
            self._stats.purposes_found[purp] = (
                self._stats.purposes_found.get(purp, 0) + 1
            )

            logger.debug("New asset: %s @ %s", asset.algorithm, asset.location)
            return True

        # Duplicate — keep the higher-confidence evidence
        existing = self._assets[key]
        self._stats.duplicates_removed += 1

        if asset.evidence.confidence > existing.evidence.confidence:
            # Replace with higher-confidence record, preserving enrichment
            # from any later pipeline stages that ran on the existing record.
            merged = _merge_assets(existing, asset)
            self._assets[key] = merged
            logger.debug(
                "Duplicate merged (higher confidence %.3f > %.3f): %s @ %s",
                asset.evidence.confidence,
                existing.evidence.confidence,
                asset.algorithm,
                asset.location,
            )

        return False

    def _record_observation(self, asset: CryptoAsset) -> None:
        """Append one observation + update its normalized family group."""
        loc = asset.evidence.location
        self._observations.append(ObservationRecord(
            algorithm=asset.algorithm,
            purpose=asset.purpose.value,
            file_path=loc.file_path,
            line_number=loc.line_number,
            rule_id=asset.evidence.rule_id,
            confidence=asset.evidence.confidence,
            observed_symbol=asset.evidence.observed_symbol,
        ))
        key = _normalize_key(asset)
        group = self._groups.get(key)
        if group is None:
            group = NormalizedAssetGroup(
                family=_normalize_family(asset.algorithm),
                purpose=asset.purpose.value,
                source_surface=asset.source_surface,
            )
            self._groups[key] = group
        group.observation_count += 1
        group.variants[asset.algorithm] = group.variants.get(asset.algorithm, 0) + 1
        group.locations.append((loc.file_path, loc.line_number))

    @property
    def observations(self) -> list[ObservationRecord]:
        """Every raw observation, in ingestion order — never deduplicated."""
        return list(self._observations)

    @property
    def observation_count(self) -> int:
        return len(self._observations)

    def normalized_groups(self) -> list[NormalizedAssetGroup]:
        """Family-level correlation groups, largest first."""
        return sorted(
            self._groups.values(),
            key=lambda g: g.observation_count,
            reverse=True,
        )

    def normalized_summary(self) -> dict:
        """Serialisable normalization report for reports/CBOM metadata."""
        groups = self.normalized_groups()
        return {
            "observation_count": len(self._observations),
            "unique_assets": self._stats.unique_assets,
            "normalized_group_count": len(groups),
            "groups": [g.summary() for g in groups],
        }

    def add_evidence_result(self, result: EvidenceResult) -> bool:
        """Convenience wrapper: add from an EvidenceResult."""
        return self.add_asset(result.asset)

    def add_evidence_results(self, results: list[EvidenceResult]) -> None:
        """Add a batch of EvidenceResult objects."""
        for result in results:
            self.add_evidence_result(result)

    # ── Query ─────────────────────────────────────────────────────────────────

    @property
    def assets(self) -> list[CryptoAsset]:
        """All unique assets in the inventory, ordered by location."""
        return sorted(
            self._assets.values(),
            key=lambda a: (
                a.evidence.location.file_path,
                a.evidence.location.line_number or 0,
            ),
        )

    @property
    def stats(self) -> InventoryStats:
        return self._stats

    def get_by_algorithm(self, algorithm: str) -> list[CryptoAsset]:
        """Return all assets with the given algorithm name (case-insensitive prefix)."""
        alg_upper = algorithm.upper()
        return [
            a for a in self._assets.values()
            if a.algorithm.upper().startswith(alg_upper)
        ]

    def get_by_purpose(self, purpose: str) -> list[CryptoAsset]:
        """Return all assets with the given purpose."""
        return [
            a for a in self._assets.values()
            if a.purpose.value == purpose
        ]

    def get_by_file(self, file_path: str) -> list[CryptoAsset]:
        """Return all assets found in a specific file."""
        norm = file_path.replace("\\", "/")
        return [
            a for a in self._assets.values()
            if a.evidence.location.file_path.replace("\\", "/") == norm
        ]

    def summary(self) -> dict:
        """Return a human-readable summary dict."""
        return {
            "scan_id": self.scan_id,
            "total_findings": self._stats.total_findings,
            "unique_assets": self._stats.unique_assets,
            "duplicates_removed": self._stats.duplicates_removed,
            "duplicate_rate": self._stats.duplicate_rate,
            "files_processed": self._stats.files_processed,
            "algorithms": self._stats.algorithms_found,
            "purposes": self._stats.purposes_found,
        }


def _merge_assets(existing: CryptoAsset, higher_conf: CryptoAsset) -> CryptoAsset:
    """
    Merge two asset records for the same deduplication key.

    Strategy: take the higher-confidence record as the base, but preserve
    any enrichment fields (risk, recommendation, owner, reachability)
    that have already been populated on the existing record by later engines.
    """
    # Start from the higher-confidence record
    updates: dict = {}

    # Preserve risk / recommendation if already set on the existing record
    if existing.risk is not None and higher_conf.risk is None:
        updates["risk"] = existing.risk
    if existing.recommendation is not None and higher_conf.recommendation is None:
        updates["recommendation"] = existing.recommendation
    if existing.owner is not None and higher_conf.owner is None:
        updates["owner"] = existing.owner
    if existing.reachable is not None and higher_conf.reachable is None:
        updates["reachable"] = existing.reachable
    if existing.reachability_path is not None and higher_conf.reachability_path is None:
        updates["reachability_path"] = existing.reachability_path

    if not updates:
        return higher_conf

    # Pydantic model_copy(update=...) creates a new instance with updates applied
    return higher_conf.model_copy(update=updates)


# ── Pipeline builder ──────────────────────────────────────────────────────────

def build_inventory_from_scan(
    scan_result: DirectoryScanResult,
    scan_id: Optional[str] = None,
    relative_to: Optional[Path] = None,
) -> CryptoAssetInventory:
    """
    Build a complete CryptoAssetInventory from a DirectoryScanResult.

    This is the top-level function that wires together:
      Source Scanner output → Evidence Engine → Inventory

    PRD pipeline: Source & Binary Discovery → Evidence Engine →
                  Crypto Asset Inventory (stages 2 → 4 → 5).

    Args:
        scan_result: Output of source_scanner.scan_directory().
        scan_id:     Optional scan run identifier for provenance.
        relative_to: Base path for relative file paths in asset records.

    Returns:
        Populated CryptoAssetInventory ready for Classification,
        Reachability, and Mosca engines.
    """
    inventory = CryptoAssetInventory(scan_id=scan_id)
    base_path = relative_to or scan_result.root_path

    for file_result in scan_result.file_results:
        evidence_results = process_file_result(
            file_result=file_result,
            scan_id=scan_id,
            relative_to=base_path,
        )
        inventory.add_evidence_results(evidence_results)
        inventory.stats.files_processed += 1

    logger.info(
        "Inventory built: %d unique assets from %d raw findings "
        "(%d duplicates removed, duplicate rate %.1f%%) across %d files",
        inventory.stats.unique_assets,
        inventory.stats.total_findings,
        inventory.stats.duplicates_removed,
        inventory.stats.duplicate_rate * 100,
        inventory.stats.files_processed,
    )

    return inventory


def build_inventory_from_file_results(
    file_results: list[FileScanResult],
    scan_id: Optional[str] = None,
    relative_to: Optional[Path] = None,
) -> CryptoAssetInventory:
    """
    Build inventory from a list of FileScanResult objects (without a root path).
    Useful for testing individual files or partial scans.
    """
    inventory = CryptoAssetInventory(scan_id=scan_id)

    for file_result in file_results:
        evidence_results = process_file_result(
            file_result=file_result,
            scan_id=scan_id,
            relative_to=relative_to,
        )
        inventory.add_evidence_results(evidence_results)
        inventory.stats.files_processed += 1

    return inventory


def ingest_cert_scan_into_inventory(
    inventory: CryptoAssetInventory,
    cert_scan_result: "_cert_scanner_module.CertDirectoryScanResult",
) -> None:
    """
    Ingest certificate-surface assets from a CertDirectoryScanResult
    directly into an existing CryptoAssetInventory.

    Certificate assets bypass the Evidence Engine because cert_scanner.py
    already constructs fully-formed Evidence and CryptoAsset objects.
    They are added directly to the inventory via add_asset().

    This preserves the single-inventory design: source-code and certificate
    assets are deduplicated and correlated together in one store.
    """
    for cert_result in cert_scan_result.cert_results:
        for asset in cert_result.assets:
            inventory.add_asset(asset)
        # Count each certificate file as one "file processed"
        inventory.stats.files_processed += 1

    logger.info(
        "Certificate assets ingested: %d cert files, %d assets",
        cert_scan_result.files_scanned,
        cert_scan_result.total_assets,
    )
