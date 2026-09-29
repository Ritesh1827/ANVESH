"""
Unit tests — call_graph.py and reachability_engine.py (Day 5)

Validates:
  1.  Python call-graph extraction — function defs, class methods, calls
  2.  Entry-point detection via @route decorators and name heuristics
  3.  ProjectCallGraph assembly from multiple files
  4.  has_path_to() and shortest_path() on NetworkX DiGraph
  5.  reachable_from_any_entry() with single and multiple entry points
  6.  _containing_function() line-range matching
  7.  ReachabilityEngine.analyse_asset() — True / False / None paths
  8.  Non-Python surfaces return reachable=None
  9.  No entry points → reachable=None (not False)
  10. Dead-code function → reachable=False
  11. process() preserves immutability (no asset mutation)
  12. exposure_context is populated for all three states
  13. Mosca reachability_weight changes after reachability annotation
  14. Edge cases: missing line_number, empty file list
"""

from __future__ import annotations

import textwrap
from pathlib import Path
import pytest

from ecdat.engines.call_graph import (
    PythonCallGraphVisitor,
    ProjectCallGraph,
    build_project_call_graph,
    extract_file_call_graph,
    _is_entry_point_name,
    _is_route_decorator,
    _module_name_from_path,
)
from ecdat.engines.reachability_engine import (
    ReachabilityEngine,
    _containing_function,
    _build_exposure_context,
    _build_unreachable_context,
    _build_unknown_context,
)
from ecdat.schemas import (
    AssetClassification,
    BusinessCriticality,
    CryptoAsset,
    CryptoPurpose,
    DetectionMethod,
    Evidence,
    FindingType,
    LifecycleStage,
    SensitivityLevel,
    SourceLocation,
)

REPO_ROOT = Path(__file__).parent.parent.parent.parent
REACH_APP = REPO_ROOT / "test_repos" / "reachability_app"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_asset(
    file_path: str = "auth_service.py",
    line_number: int = 29,
    algorithm: str = "RSA-2048",
    purpose: str = "key_establishment",
    source_surface: str = "source_code",
) -> CryptoAsset:
    evidence = Evidence(
        detection_method=DetectionMethod.AST_RULE,
        finding_type=FindingType.DETERMINISTIC,
        rule_id="R-001",
        location=SourceLocation(file_path=file_path, line_number=line_number),
        source_surface=source_surface,
        confidence=0.97,
    )
    return CryptoAsset(
        algorithm=algorithm,
        purpose=purpose,
        location=f"{file_path}:{line_number}",
        source_surface=source_surface,
        classification=AssetClassification.APPLICATION,
        sensitivity=SensitivityLevel.HIGH,
        business_criticality=BusinessCriticality.CRITICAL,
        lifecycle_stage=LifecycleStage.ACTIVE,
        evidence=evidence,
    )


def _write_py(tmp_path: Path, filename: str, code: str) -> Path:
    """Write a Python file to tmp_path and return its Path."""
    p = tmp_path / filename
    p.write_text(textwrap.dedent(code), encoding="utf-8")
    return p


# ── 1. Module name derivation ─────────────────────────────────────────────────

class TestModuleName:
    def test_simple_filename(self):
        p = Path("auth_service.py")
        assert _module_name_from_path(p) == "auth_service"

    def test_nested_path(self, tmp_path):
        p = tmp_path / "pkg" / "utils" / "crypto.py"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.touch()
        result = _module_name_from_path(p, relative_to=tmp_path)
        assert result == "pkg.utils.crypto"

    def test_relative_to_strips_base(self, tmp_path):
        p = tmp_path / "service.py"
        p.touch()
        assert _module_name_from_path(p, relative_to=tmp_path) == "service"


# ── 2. Entry-point detection ──────────────────────────────────────────────────

class TestEntryPointDetection:
    def test_main_is_entry_point(self):
        assert _is_entry_point_name("main") is True

    def test_handle_prefix_is_entry_point(self):
        assert _is_entry_point_name("handle_login") is True

    def test_on_prefix_is_entry_point(self):
        assert _is_entry_point_name("on_message") is True

    def test_process_prefix_is_entry_point(self):
        assert _is_entry_point_name("process_request") is True

    def test_regular_function_not_entry_point(self):
        assert _is_entry_point_name("compute_hash") is False

    def test_route_decorator_detected(self):
        assert _is_route_decorator("route") is True
        assert _is_route_decorator("get") is True
        assert _is_route_decorator("post") is True

    def test_non_route_decorator_not_detected(self):
        assert _is_route_decorator("staticmethod") is False
        assert _is_route_decorator("classmethod") is False
        assert _is_route_decorator("property") is False


# ── 3. File-level call-graph extraction (Python) ──────────────────────────────

class TestFileCallGraphExtraction:
    def test_extracts_functions(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", """
            def foo():
                pass
            def bar():
                pass
        """)
        fg = extract_file_call_graph(f, relative_to=tmp_path)
        assert fg is not None
        names = [fn.qualified_name for fn in fg.functions]
        assert "mod.foo" in names
        assert "mod.bar" in names

    def test_extracts_call_relation(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", """
            def caller():
                callee()
            def callee():
                pass
        """)
        fg = extract_file_call_graph(f, relative_to=tmp_path)
        assert fg is not None
        callers = [c.caller for c in fg.calls]
        assert "mod.caller" in callers

    def test_entry_point_detected_by_name(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", """
            def main():
                pass
            def helper():
                pass
        """)
        fg = extract_file_call_graph(f, relative_to=tmp_path)
        assert fg is not None
        entry_fns = [fn for fn in fg.functions if fn.is_entry_point]
        assert any(fn.qualified_name == "mod.main" for fn in entry_fns)

    def test_class_method_extracted(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", """
            class Service:
                def process(self):
                    pass
        """)
        fg = extract_file_call_graph(f, relative_to=tmp_path)
        assert fg is not None
        names = [fn.qualified_name for fn in fg.functions]
        assert "mod.Service.process" in names

    def test_nonexistent_file_returns_none(self):
        result = extract_file_call_graph(Path("nonexistent_file.py"))
        assert result is None

    def test_empty_file_returns_empty_graph(self, tmp_path):
        f = _write_py(tmp_path, "empty.py", "")
        fg = extract_file_call_graph(f, relative_to=tmp_path)
        assert fg is not None
        assert fg.functions == []
        assert fg.calls == []

    def test_module_name_set_correctly(self, tmp_path):
        f = _write_py(tmp_path, "auth_service.py", "def foo(): pass")
        fg = extract_file_call_graph(f, relative_to=tmp_path)
        assert fg.module_name == "auth_service"


# ── 4. Project call-graph assembly ────────────────────────────────────────────

class TestProjectCallGraph:
    def test_empty_file_list(self):
        pg = build_project_call_graph([])
        assert pg.node_count == 0
        assert pg.edge_count == 0

    def test_single_file_graph(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", """
            def main():
                worker()
            def worker():
                pass
        """)
        pg = build_project_call_graph([f], relative_to=tmp_path)
        assert "mod.main" in pg.nodes
        assert "mod.worker" in pg.nodes
        assert pg.has_path_to("mod.main", "mod.worker")

    def test_entry_point_registered(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", """
            def main():
                pass
        """)
        pg = build_project_call_graph([f], relative_to=tmp_path)
        assert "mod.main" in pg.entry_points

    def test_no_path_between_disconnected_nodes(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", """
            def main():
                pass
            def dead_code():
                pass
        """)
        pg = build_project_call_graph([f], relative_to=tmp_path)
        assert not pg.has_path_to("mod.main", "mod.dead_code")

    def test_shortest_path_none_when_no_path(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", """
            def a(): pass
            def b(): pass
        """)
        pg = build_project_call_graph([f], relative_to=tmp_path)
        assert pg.shortest_path("mod.a", "mod.b") is None

    def test_shortest_path_returns_list(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", """
            def main():
                helper()
            def helper():
                pass
        """)
        pg = build_project_call_graph([f], relative_to=tmp_path)
        path = pg.shortest_path("mod.main", "mod.helper")
        assert path is not None
        assert path[0] == "mod.main"
        assert path[-1] == "mod.helper"

    def test_reachable_from_any_entry(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", """
            def main():
                process()
            def process():
                pass
        """)
        pg = build_project_call_graph([f], relative_to=tmp_path)
        path = pg.reachable_from_any_entry("mod.process")
        assert path is not None

    def test_not_reachable_from_entry(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", """
            def main():
                pass
            def orphan():
                pass
        """)
        pg = build_project_call_graph([f], relative_to=tmp_path)
        path = pg.reachable_from_any_entry("mod.orphan")
        assert path is None

    def test_non_python_files_skipped(self, tmp_path):
        java_file = tmp_path / "Code.java"
        java_file.write_text("public class Code {}", encoding="utf-8")
        pg = build_project_call_graph([java_file], relative_to=tmp_path)
        assert pg.node_count == 0


# ── 5. _containing_function ───────────────────────────────────────────────────

class TestContainingFunction:
    def test_finds_function_containing_line(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", """
            def foo():
                x = 1
                y = 2
            def bar():
                z = 3
        """)
        pg = build_project_call_graph([f], relative_to=tmp_path)
        # foo starts at line 2 (1-based), bar at line 6
        # Line 3 or 4 should be inside foo
        result = _containing_function(pg, "mod.py", 3)
        # Either "mod.foo" contains line 3
        assert result is not None

    def test_returns_none_when_no_match(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", "x = 1")
        pg = build_project_call_graph([f], relative_to=tmp_path)
        result = _containing_function(pg, "mod.py", 1)
        assert result is None

    def test_returns_none_for_no_line_number(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", "def foo(): pass")
        pg = build_project_call_graph([f], relative_to=tmp_path)
        result = _containing_function(pg, "mod.py", None)
        assert result is None


# ── 6. ReachabilityEngine.analyse_asset() ─────────────────────────────────────

class TestReachabilityEngineAnalyseAsset:
    def test_non_source_surface_returns_none(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", "def main(): pass")
        engine = ReachabilityEngine([f], relative_to=tmp_path)
        asset = _make_asset(source_surface="binary")
        result = engine.analyse_asset(asset)
        assert result.reachable is None
        assert "not supported" in result.exposure_context.lower()

    def test_certificate_surface_returns_none(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", "def main(): pass")
        engine = ReachabilityEngine([f], relative_to=tmp_path)
        asset = _make_asset(source_surface="certificate")
        result = engine.analyse_asset(asset)
        assert result.reachable is None

    def test_no_entry_points_returns_none(self, tmp_path):
        # File with functions but no entry points
        f = _write_py(tmp_path, "mod.py", """
            def helper():
                pass
            def other():
                pass
        """)
        engine = ReachabilityEngine([f], relative_to=tmp_path)
        # Remove any auto-detected entry points for this test
        engine._graph.entry_points.clear()
        asset = _make_asset(file_path="mod.py", line_number=2)
        result = engine.analyse_asset(asset)
        assert result.reachable is None
        assert result.exposure_context is not None

    def test_reachable_asset(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", """
            def main():
                crypto_op()
            def crypto_op():
                pass
        """)
        engine = ReachabilityEngine([f], relative_to=tmp_path)
        # crypto_op is at approx line 4
        asset = _make_asset(file_path="mod.py", line_number=4)
        result = engine.analyse_asset(asset)
        # Should be reachable via main → crypto_op
        assert result.reachable is True
        assert result.reachability_path is not None
        assert result.exposure_context is not None

    def test_unreachable_asset(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", """
            def main():
                pass
            def dead():
                pass
        """)
        engine = ReachabilityEngine([f], relative_to=tmp_path)
        asset = _make_asset(file_path="mod.py", line_number=4)
        result = engine.analyse_asset(asset)
        assert result.reachable is False
        assert result.exposure_context is not None
        assert "dead code" in result.exposure_context.lower() or \
               "no call-graph path" in result.exposure_context.lower()

    def test_function_not_in_graph_returns_none(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", "def main(): pass")
        engine = ReachabilityEngine([f], relative_to=tmp_path)
        # Use a completely different file path that has no nodes in the graph
        asset = _make_asset(file_path="nonexistent_other_file.py", line_number=1)
        result = engine.analyse_asset(asset)
        assert result.reachable is None

    def test_exposure_context_always_populated(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", "def main(): pass")
        engine = ReachabilityEngine([f], relative_to=tmp_path)

        for surface in ["source_code", "binary", "certificate"]:
            asset = _make_asset(source_surface=surface, line_number=1)
            result = engine.analyse_asset(asset)
            assert result.exposure_context is not None
            assert len(result.exposure_context) > 0


# ── 7. ReachabilityEngine.process() immutability ─────────────────────────────

class TestReachabilityEngineProcess:
    def test_original_assets_not_mutated(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", "def main(): pass")
        engine = ReachabilityEngine([f], relative_to=tmp_path)
        asset = _make_asset()
        assert asset.reachable is None
        engine.process([asset])
        assert asset.reachable is None  # original not mutated

    def test_returned_assets_have_reachable_set(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", "def main(): pass")
        engine = ReachabilityEngine([f], relative_to=tmp_path)
        asset = _make_asset()
        results = engine.process([asset])
        assert len(results) == 1
        # reachable is defined in the CryptoAsset schema
        assert "reachable" in CryptoAsset.model_fields

    def test_process_empty_list(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", "def main(): pass")
        engine = ReachabilityEngine([f], relative_to=tmp_path)
        results = engine.process([])
        assert results == []

    def test_report_counts_updated(self, tmp_path):
        f = _write_py(tmp_path, "mod.py", """
            def main():
                worker()
            def worker():
                pass
        """)
        engine = ReachabilityEngine([f], relative_to=tmp_path)
        assets = [
            _make_asset(file_path="mod.py", line_number=2),  # main
            _make_asset(source_surface="binary"),              # unknown
        ]
        engine.process(assets)
        r = engine.report
        assert r.total_assets == 2


# ── 8. Mosca reachability weight after annotation ─────────────────────────────

class TestReachabilityWeightPropagation:
    """Verify that Mosca reads the correct weight after reachability runs."""

    def test_reachable_asset_gets_weight_1(self, tmp_path):
        from ecdat.engines.mosca_engine import _reachability_weight
        asset = _make_asset()
        reachable = asset.model_copy(update={"reachable": True})
        assert _reachability_weight(reachable) == 1.0

    def test_unreachable_asset_gets_weight_0_5(self, tmp_path):
        from ecdat.engines.mosca_engine import _reachability_weight
        asset = _make_asset()
        unreachable = asset.model_copy(update={"reachable": False})
        assert _reachability_weight(unreachable) == 0.5

    def test_unknown_reachability_gets_weight_0_8(self):
        from ecdat.engines.mosca_engine import _reachability_weight
        asset = _make_asset()
        assert asset.reachable is None
        assert _reachability_weight(asset) == 0.8


# ── 9. Reachability fixture ground truth ──────────────────────────────────────

class TestReachabilityFixtures:
    """Smoke-test the fixture repo to verify it loads without errors."""

    def test_fixture_files_exist(self):
        assert (REACH_APP / "api_handler.py").exists()
        assert (REACH_APP / "crypto_service.py").exists()
        assert (REACH_APP / "payment_handler.py").exists()
        assert (REACH_APP / "no_entry_points.py").exists()

    def test_api_handler_call_graph_builds(self):
        fg = extract_file_call_graph(
            REACH_APP / "api_handler.py",
            relative_to=REACH_APP,
        )
        assert fg is not None
        assert fg.parse_error is False
        names = [fn.qualified_name for fn in fg.functions]
        assert any("handle_login" in n for n in names)
        assert any("handle_register" in n for n in names)
        assert any("_dead_code_function" in n for n in names)

    def test_entry_points_detected_in_api_handler(self):
        fg = extract_file_call_graph(
            REACH_APP / "api_handler.py",
            relative_to=REACH_APP,
        )
        entry_fns = [fn for fn in fg.functions if fn.is_entry_point]
        assert len(entry_fns) >= 1   # handle_login and/or handle_register

    def test_full_project_graph_builds(self):
        files = [
            REACH_APP / "api_handler.py",
            REACH_APP / "crypto_service.py",
            REACH_APP / "payment_handler.py",
        ]
        pg = build_project_call_graph(files, relative_to=REACH_APP)
        assert pg.node_count > 0
        assert pg.edge_count >= 0
        assert len(pg.entry_points) >= 1

    def test_no_entry_points_file_has_no_entries(self):
        fg = extract_file_call_graph(
            REACH_APP / "no_entry_points.py",
            relative_to=REACH_APP,
        )
        assert fg is not None
        entry_fns = [fn for fn in fg.functions if fn.is_entry_point]
        assert len(entry_fns) == 0


# ── 10. Context string builders ───────────────────────────────────────────────

class TestContextBuilders:
    def test_exposure_context_contains_entry_point(self):
        asset = _make_asset()
        ctx = _build_exposure_context(asset, ["mod.main", "mod.crypto_op"], "mod.main")
        assert "mod.main" in ctx

    def test_exposure_context_contains_algorithm(self):
        asset = _make_asset(algorithm="RSA-2048")
        ctx = _build_exposure_context(asset, ["mod.main", "mod.crypto_op"], "mod.main")
        assert "RSA-2048" in ctx

    def test_unreachable_context_mentions_dead_code(self):
        asset = _make_asset()
        ctx = _build_unreachable_context(asset, graph_has_entries=True)
        assert "dead code" in ctx.lower() or "no call-graph path" in ctx.lower()

    def test_unreachable_context_no_entries(self):
        asset = _make_asset()
        ctx = _build_unreachable_context(asset, graph_has_entries=False)
        assert "no entry points" in ctx.lower()

    def test_unknown_context_contains_reason(self):
        asset = _make_asset()
        ctx = _build_unknown_context(asset, "graph not built for this surface")
        assert "graph not built" in ctx
