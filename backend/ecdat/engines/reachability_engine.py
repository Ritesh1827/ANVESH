"""
Reachability Engine — PRD §5 stage 7 (Reachability & Context).

Determines whether each discovered crypto asset is reachable from an entry
point in the application call graph, and builds the exposure context that
explains HOW the asset is reached.

PRD §5 stage 7 requirement:
  "Trace each asset through application → function → protocol → data →
   execution path to determine actual exposure rather than raw presence."

PRD §11 (prototype scope):
  "Reachability analysis is call-graph-based (via NetworkX), not full
   inter-procedural data-flow analysis."

Design:
  1. Build a ProjectCallGraph from all source files in the scan.
  2. For each CryptoAsset, identify the function it lives in
     (from evidence.location.file_path + line_number).
  3. Check whether ANY registered entry point can reach that function
     via a directed path in the call graph.
  4. Annotate the asset with:
       - reachable: True / False / None
       - reachability_path: list of function names from entry → crypto call
       - exposure_context: human-readable narrative

Explicit None semantics:
  - reachable=None means the analysis could not determine reachability
    (e.g. function not found in call graph, no entry points registered,
     or the file was not Python). This is NOT the same as unreachable.
  - reachable=False means the call graph was built and no path exists.
  - reachable=True means at least one entry-to-asset path was found.

IMPORTANT: This engine is read-only. It annotates CryptoAsset records
only. It never modifies source systems.

Reference: PRD §5 stage 7, §6 (Read-only guarantee), §11.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ecdat.schemas import CryptoAsset
from ecdat.engines.call_graph import (
    ProjectCallGraph,
    build_project_call_graph,
    extract_file_call_graph,
)

logger = logging.getLogger(__name__)


# ── Finding → function resolution ─────────────────────────────────────────────

def _containing_function(
    project_graph: ProjectCallGraph,
    file_path: str,
    line_number: Optional[int],
) -> Optional[str]:
    """
    Find the qualified function name that contains a given file + line.

    Searches all function nodes in the call graph for the function whose
    definition range contains the target line. When multiple functions
    are in the same file, picks the one whose start line is closest to
    (and does not exceed) the target line.

    Returns the qualified_name of the containing function, or None if no
    function in the call graph contains this location.
    """
    if line_number is None:
        return None

    # Normalise path for comparison
    norm_target = file_path.replace("\\", "/").rstrip("/")

    candidates: list[tuple[int, str]] = []   # (def_line, qualified_name)

    for qname, node in project_graph.nodes.items():
        node_path = str(node.file_path).replace("\\", "/").rstrip("/")

        # Match on the final component (handles relative vs absolute mismatch)
        if not (node_path == norm_target or
                node_path.endswith("/" + norm_target) or
                norm_target.endswith("/" + node_path)):
            continue

        if node.line_number <= line_number:
            candidates.append((node.line_number, qname))

    if not candidates:
        return None

    # The function with the highest start line that's still <= target line
    # is the tightest enclosing scope
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


# ── Exposure context builder ──────────────────────────────────────────────────

def _build_exposure_context(
    asset: CryptoAsset,
    path: list[str],
    entry_point_name: str,
) -> str:
    """
    Build a human-readable exposure context string from a reachability path.

    Example output:
      "Reachable from entry point 'main.handle_login' via:
       main.handle_login → auth_service.create_session → auth_service.generate_key"
    """
    if not path:
        return (
            f"Directly reachable from entry point '{entry_point_name}' "
            f"— {asset.algorithm} ({asset.purpose.value}) at {asset.location}"
        )

    path_str = " → ".join(path)
    return (
        f"Reachable from entry point '{entry_point_name}' via: {path_str} "
        f"[{asset.algorithm} ({asset.purpose.value}) at {asset.location}]"
    )


def _build_unreachable_context(asset: CryptoAsset, graph_has_entries: bool) -> str:
    """Build an exposure context string for an unreachable asset."""
    if not graph_has_entries:
        return (
            f"No entry points detected in call graph — "
            f"reachability undetermined for {asset.algorithm} at {asset.location}"
        )
    return (
        f"No call-graph path found from any entry point to "
        f"{asset.algorithm} ({asset.purpose.value}) at {asset.location}. "
        f"Asset may be dead code or only reachable via reflection/dynamic dispatch."
    )


def _build_unknown_context(asset: CryptoAsset, reason: str) -> str:
    """Build an exposure context string when reachability cannot be determined."""
    return (
        f"Reachability undetermined for {asset.algorithm} at {asset.location}: "
        f"{reason}"
    )


# ── Reachability result ───────────────────────────────────────────────────────

@dataclass
class AssetReachabilityResult:
    """Reachability analysis result for a single asset."""
    asset_id: str
    reachable: Optional[bool]            # True / False / None
    reachability_path: Optional[list[str]]
    exposure_context: Optional[str]
    containing_function: Optional[str]   # qualified name of the function the asset lives in
    entry_point_used: Optional[str]      # entry point that reaches the asset


@dataclass
class ReachabilityReport:
    """Aggregate reachability report for a scan."""
    total_assets: int = 0
    reachable_count: int = 0
    unreachable_count: int = 0
    unknown_count: int = 0               # could not determine (not same as unreachable)
    entry_points_found: list[str] = field(default_factory=list)
    graph_node_count: int = 0
    graph_edge_count: int = 0

    @property
    def reachability_rate(self) -> float:
        """Fraction of assets that are reachable (excludes unknowns)."""
        assessed = self.reachable_count + self.unreachable_count
        if assessed == 0:
            return 0.0
        return round(self.reachable_count / assessed, 4)


# ── Core engine ───────────────────────────────────────────────────────────────

class ReachabilityEngine:
    """
    Reachability Engine — annotates CryptoAssets with call-graph reachability.

    PRD §5 stage 7: Determine actual exposure rather than raw presence.
    PRD §11: Call-graph based (NetworkX), not full data-flow analysis.

    Usage:
        engine = ReachabilityEngine(file_paths, relative_to=target_path)
        assets_with_reachability = engine.process(assets)
        report = engine.report
    """

    def __init__(
        self,
        file_paths: list[Path],
        relative_to: Optional[Path] = None,
    ) -> None:
        """
        Build the call graph from source files.

        Args:
            file_paths:  All source files to include in the call graph.
                         Non-Python files are currently skipped (prototype scope).
            relative_to: Base path used for module-name derivation and
                         path matching when locating asset functions.
        """
        self._relative_to = relative_to
        self._graph = build_project_call_graph(file_paths, relative_to=relative_to)
        self._report = ReachabilityReport(
            entry_points_found=list(self._graph.entry_points),
            graph_node_count=self._graph.node_count,
            graph_edge_count=self._graph.edge_count,
        )
        logger.info(
            "ReachabilityEngine ready: %d nodes, %d edges, %d entry points",
            self._graph.node_count,
            self._graph.edge_count,
            len(self._graph.entry_points),
        )

    @property
    def graph(self) -> ProjectCallGraph:
        return self._graph

    @property
    def report(self) -> ReachabilityReport:
        return self._report

    # ── Asset-level analysis ─────────────────────────────────────────────────

    def analyse_asset(self, asset: CryptoAsset) -> AssetReachabilityResult:
        """
        Determine reachability for a single CryptoAsset.

        Returns an AssetReachabilityResult — caller decides whether to
        annotate the asset with the result.
        """
        file_path = asset.evidence.location.file_path
        line_number = asset.evidence.location.line_number

        # ── Non-Python surfaces: unknown reachability ──────────────────────
        # The prototype call graph covers Python only. For other surfaces
        # (binaries, certificates, infrastructure) reachability is explicitly
        # marked unknown rather than silently assumed.
        if asset.source_surface != "source_code":
            return AssetReachabilityResult(
                asset_id=asset.asset_id,
                reachable=None,
                reachability_path=None,
                exposure_context=_build_unknown_context(
                    asset,
                    f"surface '{asset.source_surface}' not supported by "
                    "call-graph analysis (prototype scope: source_code only)"
                ),
                containing_function=None,
                entry_point_used=None,
            )

        # ── Source code: find the containing function ──────────────────────
        containing = _containing_function(self._graph, file_path, line_number)

        if containing is None:
            # Function not found in the call graph — could be a top-level
            # expression, a generated function, or a parse failure.
            return AssetReachabilityResult(
                asset_id=asset.asset_id,
                reachable=None,
                reachability_path=None,
                exposure_context=_build_unknown_context(
                    asset,
                    "containing function not found in call graph "
                    "(may be top-level code, dynamically generated, or parse error)"
                ),
                containing_function=None,
                entry_point_used=None,
            )

        # ── Check reachability from any entry point ────────────────────────
        if not self._graph.entry_points:
            return AssetReachabilityResult(
                asset_id=asset.asset_id,
                reachable=None,
                reachability_path=None,
                exposure_context=_build_unknown_context(
                    asset,
                    "no entry points detected in call graph — "
                    "add @route decorators or main() functions to enable "
                    "reachability analysis"
                ),
                containing_function=containing,
                entry_point_used=None,
            )

        path = self._graph.reachable_from_any_entry(containing)

        if path is not None:
            # Asset IS reachable — find which entry point the path starts from
            entry_used = path[0] if path else containing
            return AssetReachabilityResult(
                asset_id=asset.asset_id,
                reachable=True,
                reachability_path=path,
                exposure_context=_build_exposure_context(asset, path, entry_used),
                containing_function=containing,
                entry_point_used=entry_used,
            )

        # ── Not reachable from any entry point ─────────────────────────────
        # Also check the reverse: if containing IS an entry point itself
        node_data = self._graph.nodes.get(containing)
        if node_data and node_data.is_entry_point:
            # The function IS an entry point — trivially reachable
            return AssetReachabilityResult(
                asset_id=asset.asset_id,
                reachable=True,
                reachability_path=[containing],
                exposure_context=_build_exposure_context(
                    asset, [containing], containing
                ),
                containing_function=containing,
                entry_point_used=containing,
            )

        return AssetReachabilityResult(
            asset_id=asset.asset_id,
            reachable=False,
            reachability_path=None,
            exposure_context=_build_unreachable_context(
                asset, bool(self._graph.entry_points)
            ),
            containing_function=containing,
            entry_point_used=None,
        )

    # ── Batch processing ──────────────────────────────────────────────────────

    def process(self, assets: list[CryptoAsset]) -> list[CryptoAsset]:
        """
        Annotate all assets with reachability information.

        Returns new CryptoAsset instances with reachable, reachability_path,
        and exposure_context fields populated.

        The original assets are NOT mutated (model_copy pattern).
        Reachability results are applied BEFORE the Mosca engine so that
        reachability_weight in the Risk record reflects actual exposure.
        """
        self._report.total_assets = len(assets)
        enriched: list[CryptoAsset] = []

        for asset in assets:
            # Infrastructure TLS-probe assets arrive with reachable=True set by
            # the probe itself (the live handshake is the exposure proof).
            # The call graph cannot assess them, and must not overwrite the
            # probe's positive evidence with None — preserve it, count it.
            if asset.source_surface == "infrastructure" and asset.reachable is True:
                enriched.append(asset)
                self._report.reachable_count += 1
                continue
            result = self.analyse_asset(asset)

            updates: dict = {
                "reachable": result.reachable,
                "reachability_path": result.reachability_path,
                "exposure_context": result.exposure_context,
            }
            enriched.append(asset.model_copy(update=updates))

            # Update report counters
            if result.reachable is True:
                self._report.reachable_count += 1
            elif result.reachable is False:
                self._report.unreachable_count += 1
            else:
                self._report.unknown_count += 1

        logger.info(
            "Reachability analysis complete: %d assets — "
            "%d reachable, %d unreachable, %d unknown",
            len(assets),
            self._report.reachable_count,
            self._report.unreachable_count,
            self._report.unknown_count,
        )
        return enriched
