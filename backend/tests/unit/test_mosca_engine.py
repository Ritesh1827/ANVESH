"""
Unit tests — Mosca Risk Engine (engines/mosca_engine.py)

Validates:
  1.  X + Y > Z → urgency_flag=True (core theorem)
  2.  X + Y == Z → urgency_flag=False (boundary — not strictly greater)
  3.  X + Y < Z → urgency_flag=False
  4.  HNDL flag set for key_establishment + long-lived data
  5.  HNDL flag NOT set for hashing/MAC purposes
  6.  HNDL flag NOT set when X < threshold
  7.  Priority assignment: P1 when classical_broken
  8.  Priority assignment: P1 when urgency+HNDL
  9.  Priority assignment: P2 when urgency only
  10. Priority assignment: P2 when HNDL only
  11. Priority assignment: P3 for quantum-vulnerable without urgency
  12. Priority assignment: P4 for safe algorithms
  13. Reachability weight: 1.0 reachable, 0.5 unreachable, 0.8 unknown
  14. Override X/Y/Z values accepted and applied correctly
  15. PRD §9 sample asset scores correctly (X=15, Y=2, Z=12 → P1, urgency+HNDL)
  16. MoscaEngine.process() handles full asset list
  17. Risk record frozen and schema-valid after scoring
  18. Classical_broken assets get P1 regardless of Mosca parameters
"""

from __future__ import annotations

import pytest
from pathlib import Path

from ecdat.schemas import (
    AssetClassification,
    BusinessCriticality,
    CryptoAsset,
    CryptoPurpose,
    DetectionMethod,
    Evidence,
    FindingType,
    LifecycleStage,
    RiskPriority,
    SensitivityLevel,
    SourceLocation,
)
from ecdat.engines.mosca_engine import (
    MoscaEngine,
    _assign_priority,
    _determine_hndl,
    _reachability_weight,
    compute_mosca,
)
from ecdat.engines.pqc_loader import (
    HNDLRules,
    MoscaProfiles,
    DataShelfLifeEntry,
    MigrationTimeEntry,
    load_mosca_profiles,
    load_pqc_config,
)

REPO_ROOT = Path(__file__).parent.parent.parent.parent
MOSCA_PATH = REPO_ROOT / "config" / "mosca_profiles.yaml"
PQC_PATH = REPO_ROOT / "config" / "pqc_mappings.yaml"


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_asset(
    algorithm="RSA-2048",
    purpose="key_establishment",
    classification="application",
    sensitivity="high",
    criticality="critical",
    reachable=None,
) -> CryptoAsset:
    evidence = Evidence(
        detection_method=DetectionMethod.AST_RULE,
        finding_type=FindingType.DETERMINISTIC,
        rule_id="R-001",
        location=SourceLocation(file_path="auth_service.py", line_number=29),
        source_surface="source_code",
        confidence=0.97,
    )
    return CryptoAsset(
        algorithm=algorithm,
        purpose=purpose,
        location="auth_service.py:29",
        source_surface="source_code",
        classification=classification,
        sensitivity=sensitivity,
        business_criticality=criticality,
        lifecycle_stage=LifecycleStage.ACTIVE,
        evidence=evidence,
        reachable=reachable,
    )


def _make_minimal_profiles(
    z: float = 10.0,
    x_app_high: float = 15.0,
    y_rsa: float = 2.0,
) -> MoscaProfiles:
    """Build a minimal MoscaProfiles for controlled unit testing."""
    return MoscaProfiles(
        z_years_default=z,
        z_years_conservative=z,
        z_years_moderate=z + 5,
        z_years_optimistic=z + 10,
        data_shelf_life=[
            DataShelfLifeEntry("application", "high", x_app_high),
            DataShelfLifeEntry("application", "confidential", 7.0),
            DataShelfLifeEntry("application", "internal", 3.0),
            DataShelfLifeEntry("application", "public", 1.0),
            DataShelfLifeEntry("infrastructure", "high", 5.0),
            DataShelfLifeEntry("infrastructure", "critical", 10.0),
        ],
        migration_time=[
            MigrationTimeEntry("RSA", "key_establishment", y_rsa),
            MigrationTimeEntry("MD5", "hashing", 1.0),
            MigrationTimeEntry("SHA-1", "hashing", 1.0),
            MigrationTimeEntry("DES", "encryption", 1.0),
            MigrationTimeEntry("ECDSA", "digital_signature", 3.0),
            MigrationTimeEntry("*", "*", 2.0),
        ],
        hndl_rules=HNDLRules(
            threshold_x_years=3.0,
            hndl_purposes=["key_establishment", "encryption"],
            signature_threshold_x_years=5.0,
        ),
    )


# ── 1–3: Core Mosca theorem ───────────────────────────────────────────────────

class TestMoscaTheorem:
    def setup_method(self):
        self.profiles = _make_minimal_profiles(z=10.0, x_app_high=15.0, y_rsa=2.0)
        self.pqc_config = load_pqc_config(PQC_PATH)

    def test_x_plus_y_greater_than_z_is_urgent(self):
        asset = _make_asset()  # X=15, Y=2 → 17 > 10
        result = compute_mosca(asset, self.profiles, self.pqc_config)
        assert result.urgency_flag is True
        assert result.x_years == 15.0
        assert result.y_years == 2.0
        assert result.z_years == 10.0

    def test_x_plus_y_exactly_equal_z_is_not_urgent(self):
        # 8 + 2 = 10 == 10 — not strictly greater
        asset = _make_asset()
        result = compute_mosca(
            asset, self.profiles, self.pqc_config,
            override_x=8.0, override_y=2.0, override_z=10.0,
        )
        assert result.urgency_flag is False

    def test_x_plus_y_less_than_z_is_not_urgent(self):
        # 3 + 2 = 5 < 10
        asset = _make_asset()
        result = compute_mosca(
            asset, self.profiles, self.pqc_config,
            override_x=3.0, override_y=2.0, override_z=10.0,
        )
        assert result.urgency_flag is False

    def test_urgency_strictly_greater_not_equal(self):
        # 10 + 0 = 10 == 10 → False (strict >)
        asset = _make_asset()
        result = compute_mosca(
            asset, self.profiles, self.pqc_config,
            override_x=10.0, override_y=0.0, override_z=10.0,
        )
        assert result.urgency_flag is False

    def test_one_above_boundary_is_urgent(self):
        # 10 + 1 = 11 > 10 → True
        asset = _make_asset()
        result = compute_mosca(
            asset, self.profiles, self.pqc_config,
            override_x=10.0, override_y=1.0, override_z=10.0,
        )
        assert result.urgency_flag is True

    def test_prd_sample_values(self):
        """Exact PRD §9 sample: X=15, Y=2, Z=12 → urgency=True."""
        asset = _make_asset()
        result = compute_mosca(
            asset, self.profiles, self.pqc_config,
            override_x=15.0, override_y=2.0, override_z=12.0,
        )
        assert result.x_years == 15.0
        assert result.y_years == 2.0
        assert result.z_years == 12.0
        assert result.urgency_flag is True   # 15 + 2 = 17 > 12


# ── 4–6: HNDL flag ───────────────────────────────────────────────────────────

class TestHNDLFlag:
    def setup_method(self):
        self.profiles = _make_minimal_profiles()
        self.pqc_config = load_pqc_config(PQC_PATH)

    def test_key_establishment_long_lived_is_hndl(self):
        asset = _make_asset(purpose="key_establishment")
        result = compute_mosca(
            asset, self.profiles, self.pqc_config,
            override_x=15.0, override_y=2.0, override_z=10.0,
        )
        assert result.hndl_flag is True

    def test_encryption_long_lived_is_hndl(self):
        asset = _make_asset(algorithm="DES-56", purpose="encryption")
        result = compute_mosca(
            asset, self.profiles, self.pqc_config,
            override_x=10.0, override_y=1.0, override_z=10.0,
        )
        assert result.hndl_flag is True

    def test_hashing_is_never_hndl(self):
        asset = _make_asset(algorithm="MD5", purpose="hashing")
        result = compute_mosca(
            asset, self.profiles, self.pqc_config,
            override_x=20.0, override_y=1.0, override_z=10.0,
        )
        assert result.hndl_flag is False

    def test_mac_is_never_hndl(self):
        asset = _make_asset(algorithm="HMAC", purpose="mac")
        result = compute_mosca(
            asset, self.profiles, self.pqc_config,
            override_x=20.0, override_y=1.0, override_z=10.0,
        )
        assert result.hndl_flag is False

    def test_key_establishment_short_lived_is_not_hndl(self):
        # X=1 < threshold=3 → no HNDL even for key_establishment
        asset = _make_asset(purpose="key_establishment")
        result = compute_mosca(
            asset, self.profiles, self.pqc_config,
            override_x=1.0, override_y=2.0, override_z=10.0,
        )
        assert result.hndl_flag is False

    def test_hndl_threshold_boundary(self):
        # X exactly at threshold (3.0) → HNDL True (>= threshold)
        asset = _make_asset(purpose="key_establishment")
        result = compute_mosca(
            asset, self.profiles, self.pqc_config,
            override_x=3.0, override_y=2.0, override_z=10.0,
        )
        assert result.hndl_flag is True

    def test_digital_signature_high_x_is_hndl(self):
        # Signature with X >= 5 (signature threshold)
        asset = _make_asset(algorithm="ECDSA-P256", purpose="digital_signature")
        result = compute_mosca(
            asset, self.profiles, self.pqc_config,
            override_x=5.0, override_y=3.0, override_z=10.0,
        )
        assert result.hndl_flag is True

    def test_digital_signature_low_x_is_not_hndl(self):
        # Signature with X < 5 → not HNDL
        asset = _make_asset(algorithm="ECDSA-P256", purpose="digital_signature")
        result = compute_mosca(
            asset, self.profiles, self.pqc_config,
            override_x=3.0, override_y=3.0, override_z=10.0,
        )
        assert result.hndl_flag is False

    def test_prd_sample_hndl_true(self):
        """PRD §9 sample: RSA-2048 key_establishment, X=15 → hndl=True."""
        asset = _make_asset(algorithm="RSA-2048", purpose="key_establishment")
        result = compute_mosca(
            asset, self.profiles, self.pqc_config,
            override_x=15.0, override_y=2.0, override_z=12.0,
        )
        assert result.hndl_flag is True


# ── 7–12: Priority assignment ─────────────────────────────────────────────────

class TestPriorityAssignment:
    """Tests _assign_priority() directly and via compute_mosca()."""

    def test_classical_broken_is_p1_regardless(self):
        p = _assign_priority(
            urgency_flag=False, hndl_flag=False,
            classical_broken=True, quantum_vulnerable=True, quantum_weakened=False,
        )
        assert p == RiskPriority.P1

    def test_classical_broken_overrides_urgency(self):
        # Even without urgency, classical_broken → P1
        p = _assign_priority(
            urgency_flag=False, hndl_flag=False,
            classical_broken=True, quantum_vulnerable=False, quantum_weakened=False,
        )
        assert p == RiskPriority.P1

    def test_urgency_and_hndl_is_p1(self):
        p = _assign_priority(
            urgency_flag=True, hndl_flag=True,
            classical_broken=False, quantum_vulnerable=True, quantum_weakened=False,
        )
        assert p == RiskPriority.P1

    def test_urgency_without_hndl_is_p2(self):
        p = _assign_priority(
            urgency_flag=True, hndl_flag=False,
            classical_broken=False, quantum_vulnerable=True, quantum_weakened=False,
        )
        assert p == RiskPriority.P2

    def test_hndl_without_urgency_is_p2(self):
        p = _assign_priority(
            urgency_flag=False, hndl_flag=True,
            classical_broken=False, quantum_vulnerable=True, quantum_weakened=False,
        )
        assert p == RiskPriority.P2

    def test_quantum_vulnerable_no_urgency_no_hndl_is_p3(self):
        p = _assign_priority(
            urgency_flag=False, hndl_flag=False,
            classical_broken=False, quantum_vulnerable=True, quantum_weakened=False,
        )
        assert p == RiskPriority.P3

    def test_quantum_weakened_is_p3(self):
        p = _assign_priority(
            urgency_flag=False, hndl_flag=False,
            classical_broken=False, quantum_vulnerable=False, quantum_weakened=True,
        )
        assert p == RiskPriority.P3

    def test_safe_algorithm_is_p4(self):
        p = _assign_priority(
            urgency_flag=False, hndl_flag=False,
            classical_broken=False, quantum_vulnerable=False, quantum_weakened=False,
        )
        assert p == RiskPriority.P4

    def test_md5_gets_p1_via_classical_broken(self):
        profiles = _make_minimal_profiles()
        pqc_config = load_pqc_config(PQC_PATH)
        asset = _make_asset(algorithm="MD5", purpose="hashing")
        result = compute_mosca(asset, profiles, pqc_config)
        assert result.priority == RiskPriority.P1

    def test_des_gets_p1_via_classical_broken(self):
        profiles = _make_minimal_profiles()
        pqc_config = load_pqc_config(PQC_PATH)
        asset = _make_asset(algorithm="DES-56", purpose="encryption")
        result = compute_mosca(asset, profiles, pqc_config)
        assert result.priority == RiskPriority.P1

    def test_sha256_gets_p4(self):
        profiles = _make_minimal_profiles()
        pqc_config = load_pqc_config(PQC_PATH)
        asset = _make_asset(algorithm="SHA-256", purpose="hashing")
        result = compute_mosca(asset, profiles, pqc_config)
        assert result.priority == RiskPriority.P4

    def test_prd_sample_is_p1(self):
        """PRD §9 sample: RSA-2048 key_establishment → P1."""
        profiles = _make_minimal_profiles()
        pqc_config = load_pqc_config(PQC_PATH)
        asset = _make_asset(algorithm="RSA-2048", purpose="key_establishment")
        result = compute_mosca(
            asset, profiles, pqc_config,
            override_x=15.0, override_y=2.0, override_z=12.0,
        )
        assert result.priority == RiskPriority.P1


# ── 13: Reachability weight ───────────────────────────────────────────────────

class TestReachabilityWeight:
    def test_reachable_true_weight_1(self):
        asset = _make_asset(reachable=True)
        assert _reachability_weight(asset) == 1.0

    def test_reachable_false_weight_0_5(self):
        asset = _make_asset(reachable=False)
        assert _reachability_weight(asset) == 0.5

    def test_reachable_none_weight_0_8(self):
        asset = _make_asset(reachable=None)
        assert _reachability_weight(asset) == 0.8

    def test_reachability_weight_in_risk_record(self):
        engine = MoscaEngine(mosca_profiles_path=MOSCA_PATH, pqc_mappings_path=PQC_PATH)
        asset = _make_asset(reachable=True)
        scored = engine.score_asset(asset)
        assert scored.risk.reachability_weight == 1.0

    def test_unreachable_asset_lower_weight_in_risk(self):
        engine = MoscaEngine(mosca_profiles_path=MOSCA_PATH, pqc_mappings_path=PQC_PATH)
        reachable = _make_asset(reachable=True)
        unreachable = _make_asset(reachable=False)
        r1 = engine.score_asset(reachable)
        r2 = engine.score_asset(unreachable)
        assert r1.risk.reachability_weight > r2.risk.reachability_weight


# ── 14: Override values ───────────────────────────────────────────────────────

class TestOverrideValues:
    def setup_method(self):
        self.profiles = _make_minimal_profiles()
        self.pqc_config = load_pqc_config(PQC_PATH)

    def test_override_x_used(self):
        asset = _make_asset()
        result = compute_mosca(asset, self.profiles, self.pqc_config, override_x=1.0)
        assert result.x_years == 1.0

    def test_override_y_used(self):
        asset = _make_asset()
        result = compute_mosca(asset, self.profiles, self.pqc_config, override_y=0.5)
        assert result.y_years == 0.5

    def test_override_z_used(self):
        asset = _make_asset()
        result = compute_mosca(asset, self.profiles, self.pqc_config, override_z=50.0)
        assert result.z_years == 50.0

    def test_override_z_high_makes_not_urgent(self):
        # Same asset but Z=100 → 15+2=17 not > 100
        asset = _make_asset()
        result = compute_mosca(
            asset, self.profiles, self.pqc_config,
            override_x=15.0, override_y=2.0, override_z=100.0,
        )
        assert result.urgency_flag is False


# ── 15: MoscaEngine class ──────────────────────────────────────────────────────

class TestMoscaEngineClass:
    def test_engine_loads_from_config_files(self):
        engine = MoscaEngine(mosca_profiles_path=MOSCA_PATH, pqc_mappings_path=PQC_PATH)
        assert engine.z_years == 10.0

    def test_score_asset_returns_new_instance(self):
        engine = MoscaEngine(mosca_profiles_path=MOSCA_PATH, pqc_mappings_path=PQC_PATH)
        asset = _make_asset()
        assert asset.risk is None
        scored = engine.score_asset(asset)
        assert scored.risk is not None
        assert asset.risk is None   # original not mutated

    def test_scored_asset_risk_is_schema_valid(self):
        engine = MoscaEngine(mosca_profiles_path=MOSCA_PATH, pqc_mappings_path=PQC_PATH)
        scored = engine.score_asset(_make_asset())
        # Pydantic will have validated this on construction
        from ecdat.schemas import Risk
        assert isinstance(scored.risk, Risk)

    def test_process_returns_all_assets(self):
        engine = MoscaEngine(mosca_profiles_path=MOSCA_PATH, pqc_mappings_path=PQC_PATH)
        assets = [
            _make_asset("RSA-2048", "key_establishment"),
            _make_asset("MD5", "hashing"),
            _make_asset("SHA-256", "hashing"),
        ]
        scored = engine.process(assets)
        assert len(scored) == 3

    def test_process_all_have_risk(self):
        engine = MoscaEngine(mosca_profiles_path=MOSCA_PATH, pqc_mappings_path=PQC_PATH)
        assets = [
            _make_asset("RSA-2048", "key_establishment"),
            _make_asset("MD5", "hashing"),
        ]
        for a in engine.process(assets):
            assert a.risk is not None

    def test_urgency_flag_consistent_with_xyz_in_risk(self):
        """Risk schema validator must pass — urgency_flag must match X+Y>Z."""
        engine = MoscaEngine(mosca_profiles_path=MOSCA_PATH, pqc_mappings_path=PQC_PATH)
        scored = engine.score_asset(_make_asset("RSA-2048", "key_establishment"))
        r = scored.risk
        if r.mosca_x_years and r.mosca_y_years and r.mosca_z_years:
            expected = (r.mosca_x_years + r.mosca_y_years) > r.mosca_z_years
            assert r.urgency_flag == expected

    def test_risk_serialises_to_json(self):
        import json
        engine = MoscaEngine(mosca_profiles_path=MOSCA_PATH, pqc_mappings_path=PQC_PATH)
        scored = engine.score_asset(_make_asset())
        data = json.loads(scored.model_dump_json())
        assert "risk" in data
        assert data["risk"]["urgency_flag"] is not None
        assert data["risk"]["priority"] in ("P1", "P2", "P3", "P4", "UNKNOWN")
