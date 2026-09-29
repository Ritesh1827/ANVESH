"""
Discovery Completeness Engine — PRD §5 stage 8.

PRD §5 stage 8 requirement:
  "Compute a coverage percentage: found asset categories vs. expected
   categories, across all source types."

Completeness tracks two orthogonal dimensions:

  1. SURFACE COVERAGE — which input surfaces were actually scanned:
       source_code, binary, container, certificate, infrastructure
     Each surface has three states:
       scanned:     actively scanned and contributed to the inventory
       skipped:     present but skipped (e.g. unsupported extension,
                    no grammar installed)
       unavailable: not provided as input at all

  2. ALGORITHM CATEGORY COVERAGE — which cryptographic categories were found
     vs. which are expected given the scanned codebase:
       found:    at least one asset of this category was discovered
       expected: algorithm categories that are commonly expected in the
                 type of codebase being scanned (configurable defaults)
       missing:  expected but not found

Completeness percentage:
  (found_categories / expected_categories) × 100
  Combined with surface coverage as a weighted average in the overall score.

This engine does NOT invent findings. It only reports on what was found
vs. what was expected given the scan inputs.

Reference: PRD §5 stage 8, §6 (Explainability).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ecdat.schemas import CryptoAsset
from ecdat.discovery.source_scanner import DirectoryScanResult

logger = logging.getLogger(__name__)


# ── Surface definitions ────────────────────────────────────────────────────────

# All five PRD-defined input surfaces
ALL_SURFACES: list[str] = [
    "source_code",
    "binary",
    "container",
    "certificate",
    "infrastructure",
]

# Algorithm categories (purpose-based groupings for completeness assessment)
ALGORITHM_CATEGORIES: list[str] = [
    "hashing",
    "key_establishment",
    "digital_signature",
    "encryption",
    "mac",
    "key_derivation",
    "certificate",
]

# Default expected categories for a typical source-code scan
# (not all categories are expected in every codebase — this is a default)
DEFAULT_EXPECTED_CATEGORIES: set[str] = {
    "hashing",
    "key_establishment",
    "encryption",
}


# ── Surface status enum ────────────────────────────────────────────────────────

class SurfaceStatus:
    SCANNED = "scanned"          # Was actively scanned
    SKIPPED = "skipped"          # Was attempted but partially skipped
    UNAVAILABLE = "unavailable"  # Not provided as input


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class SurfaceCoverage:
    """Coverage record for a single input surface."""
    surface: str
    status: str                    # SurfaceStatus value
    files_scanned: int = 0
    files_skipped: int = 0
    assets_found: int = 0
    notes: Optional[str] = None


@dataclass
class CategoryCoverage:
    """Coverage record for a single algorithm category."""
    category: str                  # CryptoPurpose value
    found: bool                    # At least one asset in this category
    expected: bool                 # Was this category expected?
    asset_count: int = 0
    algorithms_found: list[str] = field(default_factory=list)


@dataclass
class DiscoveryCompletenessResult:
    """
    Complete discovery completeness assessment for a scan.

    PRD §5 stage 8: "coverage percentage: found asset categories vs.
    expected categories, across all source types."
    """
    # ── Surface coverage ──────────────────────────────────────────────────────
    surface_coverage: list[SurfaceCoverage] = field(default_factory=list)

    # ── Algorithm category coverage ───────────────────────────────────────────
    category_coverage: list[CategoryCoverage] = field(default_factory=list)

    # ── Completeness metrics ──────────────────────────────────────────────────
    surfaces_scanned: int = 0           # Number of surfaces actively scanned
    surfaces_total: int = len(ALL_SURFACES)   # Total possible surfaces (5)
    categories_found: int = 0           # Number of expected categories found
    categories_expected: int = 0        # Total expected categories
    total_assets_discovered: int = 0
    total_raw_findings: int = 0         # Before deduplication

    # ── Computed completeness scores ─────────────────────────────────────────
    surface_completeness_pct: float = 0.0    # surfaces_scanned / 5 × 100
    category_completeness_pct: float = 0.0   # categories_found / expected × 100
    overall_completeness_pct: float = 0.0    # weighted average

    # ── Coverage gaps ─────────────────────────────────────────────────────────
    missing_expected_categories: list[str] = field(default_factory=list)
    unscanned_surfaces: list[str] = field(default_factory=list)

    # ── Notes ─────────────────────────────────────────────────────────────────
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        """Return a serialisable summary dict for reporting/dashboard."""
        return {
            "overall_completeness_pct": round(self.overall_completeness_pct, 1),
            "surface_completeness_pct": round(self.surface_completeness_pct, 1),
            "category_completeness_pct": round(self.category_completeness_pct, 1),
            "surfaces_scanned": self.surfaces_scanned,
            "surfaces_total": self.surfaces_total,
            "categories_found": self.categories_found,
            "categories_expected": self.categories_expected,
            "total_assets_discovered": self.total_assets_discovered,
            "total_raw_findings": self.total_raw_findings,
            "missing_expected_categories": self.missing_expected_categories,
            "unscanned_surfaces": self.unscanned_surfaces,
            "surface_detail": [
                {
                    "surface": sc.surface,
                    "status": sc.status,
                    "files_scanned": sc.files_scanned,
                    "assets_found": sc.assets_found,
                }
                for sc in self.surface_coverage
            ],
            "category_detail": [
                {
                    "category": cc.category,
                    "found": cc.found,
                    "expected": cc.expected,
                    "asset_count": cc.asset_count,
                }
                for cc in self.category_coverage
            ],
            "notes": self.notes,
        }


# ── Engine ─────────────────────────────────────────────────────────────────────

class DiscoveryCompletenessEngine:
    """
    Discovery Completeness Engine — PRD §5 stage 8.

    Computes a coverage percentage and identifies gaps in the discovery.

    Usage:
        engine = DiscoveryCompletenessEngine(
            scan_result=scan_result,
            assets=scored_assets,
            scanned_surfaces=["source_code"],
            expected_categories={"hashing", "key_establishment", "encryption"},
        )
        result = engine.compute()
    """

    def __init__(
        self,
        scan_result: DirectoryScanResult,
        assets: list[CryptoAsset],
        scanned_surfaces: Optional[list[str]] = None,
        expected_categories: Optional[set[str]] = None,
    ) -> None:
        """
        Args:
            scan_result:          DirectoryScanResult from the source scanner.
            assets:               Discovered CryptoAsset list (post-inventory).
            scanned_surfaces:     Which surfaces were included in this scan.
                                  Defaults to ["source_code"] for a source-only scan.
            expected_categories:  Algorithm categories expected to be found.
                                  Defaults to DEFAULT_EXPECTED_CATEGORIES.
        """
        self._scan_result = scan_result
        self._assets = assets
        self._scanned_surfaces: list[str] = scanned_surfaces or ["source_code"]
        self._expected_categories: set[str] = (
            expected_categories if expected_categories is not None
            else DEFAULT_EXPECTED_CATEGORIES
        )

    def compute(self) -> DiscoveryCompletenessResult:
        """
        Compute the discovery completeness assessment.

        Returns a DiscoveryCompletenessResult with all metrics populated.
        This method is pure — it does not modify any assets or scan data.
        """
        result = DiscoveryCompletenessResult()
        result.total_assets_discovered = len(self._assets)
        result.total_raw_findings = self._scan_result.total_matches

        # ── Surface coverage ──────────────────────────────────────────────────
        surface_coverage = self._compute_surface_coverage()
        result.surface_coverage = surface_coverage
        result.surfaces_scanned = sum(
            1 for sc in surface_coverage
            if sc.status == SurfaceStatus.SCANNED
        )
        result.unscanned_surfaces = [
            sc.surface for sc in surface_coverage
            if sc.status == SurfaceStatus.UNAVAILABLE
        ]

        # ── Category coverage ─────────────────────────────────────────────────
        category_coverage = self._compute_category_coverage()
        result.category_coverage = category_coverage
        result.categories_expected = len(self._expected_categories)
        result.categories_found = sum(
            1 for cc in category_coverage
            if cc.expected and cc.found
        )
        result.missing_expected_categories = [
            cc.category for cc in category_coverage
            if cc.expected and not cc.found
        ]

        # ── Completeness percentages ──────────────────────────────────────────
        result.surface_completeness_pct = (
            (result.surfaces_scanned / result.surfaces_total) * 100
            if result.surfaces_total > 0 else 0.0
        )
        result.category_completeness_pct = (
            (result.categories_found / result.categories_expected) * 100
            if result.categories_expected > 0 else 100.0
        )
        # Weighted average: surface coverage carries 30% weight,
        # category completeness 70% weight.
        # Surface coverage is low by design for the prototype (1 of 5 surfaces).
        result.overall_completeness_pct = (
            0.3 * result.surface_completeness_pct +
            0.7 * result.category_completeness_pct
        )

        # ── Notes ─────────────────────────────────────────────────────────────
        result.notes = self._generate_notes(result)

        logger.info(
            "Completeness: %.0f%% overall (surface %.0f%%, category %.0f%%) "
            "— %d/%d surfaces, %d/%d categories",
            result.overall_completeness_pct,
            result.surface_completeness_pct,
            result.category_completeness_pct,
            result.surfaces_scanned, result.surfaces_total,
            result.categories_found, result.categories_expected,
        )
        return result

    def _compute_surface_coverage(self) -> list[SurfaceCoverage]:
        """Build per-surface coverage records."""
        # Count assets per surface
        assets_by_surface: dict[str, int] = {}
        for asset in self._assets:
            s = asset.source_surface
            assets_by_surface[s] = assets_by_surface.get(s, 0) + 1

        coverages: list[SurfaceCoverage] = []
        for surface in ALL_SURFACES:
            if surface not in self._scanned_surfaces:
                coverages.append(SurfaceCoverage(
                    surface=surface,
                    status=SurfaceStatus.UNAVAILABLE,
                    notes="Not included in this scan.",
                ))
                continue

            if surface == "source_code":
                # Use DirectoryScanResult for detailed source metrics
                coverages.append(SurfaceCoverage(
                    surface=surface,
                    status=SurfaceStatus.SCANNED,
                    files_scanned=self._scan_result.files_scanned,
                    files_skipped=self._scan_result.files_skipped,
                    assets_found=assets_by_surface.get(surface, 0),
                    notes=(
                        f"{self._scan_result.total_lines:,} lines scanned, "
                        f"{self._scan_result.files_skipped} files skipped "
                        f"(unsupported extension or no grammar)."
                    ),
                ))
            else:
                coverages.append(SurfaceCoverage(
                    surface=surface,
                    status=SurfaceStatus.SCANNED,
                    files_scanned=0,
                    files_skipped=0,
                    assets_found=assets_by_surface.get(surface, 0),
                ))

        return coverages

    def _compute_category_coverage(self) -> list[CategoryCoverage]:
        """Build per-algorithm-category coverage records."""
        # Count assets and collect algorithm names per category
        found_categories: dict[str, list[str]] = {}
        for asset in self._assets:
            purp = asset.purpose.value
            if purp not in found_categories:
                found_categories[purp] = []
            if asset.algorithm not in found_categories[purp]:
                found_categories[purp].append(asset.algorithm)

        coverages: list[CategoryCoverage] = []
        for cat in ALGORITHM_CATEGORIES:
            algs = found_categories.get(cat, [])
            coverages.append(CategoryCoverage(
                category=cat,
                found=cat in found_categories,
                expected=cat in self._expected_categories,
                asset_count=len(self._assets)
                    if cat not in found_categories else
                    sum(1 for a in self._assets if a.purpose.value == cat),
                algorithms_found=algs,
            ))

        # Include any categories found but not in ALGORITHM_CATEGORIES list
        for cat, algs in found_categories.items():
            if cat not in ALGORITHM_CATEGORIES:
                coverages.append(CategoryCoverage(
                    category=cat,
                    found=True,
                    expected=cat in self._expected_categories,
                    asset_count=sum(1 for a in self._assets if a.purpose.value == cat),
                    algorithms_found=algs,
                ))

        return coverages

    def _generate_notes(self, result: DiscoveryCompletenessResult) -> list[str]:
        """Generate human-readable notes about completeness gaps."""
        notes: list[str] = []

        if result.missing_expected_categories:
            notes.append(
                f"Expected but not found: {', '.join(result.missing_expected_categories)}. "
                "Consider whether these algorithms are used in this codebase."
            )
        if result.unscanned_surfaces:
            notes.append(
                f"Unscanned surfaces: {', '.join(result.unscanned_surfaces)}. "
                "Extending the scan to these surfaces may reveal additional assets."
            )
        if self._scan_result.files_skipped > 0:
            notes.append(
                f"{self._scan_result.files_skipped} files were skipped during scanning "
                "(unsupported extension or grammar not installed). "
                "Results may be incomplete for those files."
            )
        if result.surfaces_scanned < 2:
            notes.append(
                "Only one input surface was scanned. "
                "This is expected for the prototype; "
                "a full scan would cover source, binaries, certificates, "
                "containers, and infrastructure."
            )
        if result.total_assets_discovered == 0:
            notes.append(
                "No cryptographic assets were discovered. "
                "Verify that the scanned codebase actually uses cryptographic libraries."
            )

        return notes
