"""
Mosca Risk Engine — PRD §5 stage 9.

Implements Mosca's theorem: X + Y > Z → urgency_flag = True

  X = years the data protected by this asset must remain confidential
  Y = years required to complete migration for this asset
  Z = years until a cryptographically relevant quantum computer (CRQC) exists

Additional logic:
  - HNDL (Harvest-Now-Decrypt-Later) flag: set when an adversary may already
    be harvesting ciphertext for later quantum decryption.
  - Priority assignment (P1–P4) combining urgency_flag, hndl_flag,
    classical_broken, and quantum_vulnerable.
  - Optional reachability weighting: assets not reachable from any entry
    point receive a lower effective risk weight (but are still inventoried).

PRD §5 stage 9 exact requirements:
  "Compute quantum-risk urgency explicitly as X + Y compared against Z;
   flag urgency when X + Y > Z. Weight by classification, reachability,
   and an HNDL exposure flag."

IMPORTANT — this engine is READ-ONLY. It annotates assets with risk records.
It NEVER modifies source systems, rotates keys, or applies patches.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ecdat.schemas import (
    AssetClassification,
    BusinessCriticality,
    CryptoAsset,
    CryptoPurpose,
    Risk,
    RiskPriority,
    SensitivityLevel,
)
from ecdat.engines.pqc_loader import (
    MoscaProfiles,
    PQCConfig,
    PQCMapping,
    find_pqc_mapping,
    get_x_years,
    get_y_years,
    load_mosca_profiles,
    load_pqc_config,
)

logger = logging.getLogger(__name__)


# ── HNDL determination ────────────────────────────────────────────────────────

def _determine_hndl(
    purpose: CryptoPurpose,
    x_years: float,
    mapping: Optional[PQCMapping],
    profiles: MoscaProfiles,
) -> bool:
    """
    Determine whether this asset has HNDL (Harvest-Now-Decrypt-Later) exposure.

    An asset is HNDL-flagged when:
      1. It protects data that must remain confidential for long enough that
         it overlaps with the quantum threat window (x_years >= threshold), AND
      2. Its cryptographic purpose involves confidentiality (key_establishment
         or encryption — data harvested today can be decrypted later), AND
      3. The algorithm is quantum-vulnerable (not just classically broken).

    Digital signatures are flagged at a higher X threshold because a signature
    being forged retroactively is a different (and generally shorter-horizon)
    threat than data confidentiality being broken.

    Hashing and MAC are NOT HNDL candidates — hashes/MACs don't protect
    confidentiality in a way that enables harvest-now-decrypt-later attacks.
    """
    rules = profiles.hndl_rules

    # Hashing and MAC cannot be harvested for later decryption
    if purpose in (CryptoPurpose.HASHING, CryptoPurpose.MAC,
                   CryptoPurpose.RANDOM_GENERATION, CryptoPurpose.KEY_DERIVATION):
        return False

    # If not quantum-vulnerable, no HNDL risk
    if mapping and not mapping.quantum_vulnerable:
        return False

    # Key establishment and encryption: harvest-now-decrypt-later is the
    # canonical HNDL scenario
    if purpose.value in rules.hndl_purposes:
        return x_years >= rules.threshold_x_years

    # Digital signatures: HNDL applies at a higher threshold (long-lived
    # signed artefacts like code signing certificates, legal documents)
    if purpose == CryptoPurpose.DIGITAL_SIGNATURE:
        return x_years >= rules.signature_threshold_x_years

    return False


# ── Priority assignment ───────────────────────────────────────────────────────

def _assign_priority(
    urgency_flag: bool,
    hndl_flag: bool,
    classical_broken: bool,
    quantum_vulnerable: bool,
    quantum_weakened: bool,
) -> RiskPriority:
    """
    Assign P1–P4 risk priority from Mosca + HNDL + algorithm state.

    Priority rules (highest to lowest, first match wins):
      P1: already classically broken  (broken NOW regardless of quantum)
      P1: quantum_vulnerable + urgency AND hndl    (quantum urgent + harvest risk)
      P2: quantum_vulnerable + urgency AND NOT hndl (quantum urgent, no harvest)
      P2: quantum_vulnerable + NOT urgency AND hndl (harvest risk)
      P3: quantum_vulnerable, no current urgency
      P3: quantum_weakened (needs upgrade but not broken)
      P4: no quantum risk

    NOTE: urgency_flag and hndl_flag are only meaningful for quantum_vulnerable
    algorithms. A non-quantum-vulnerable algorithm may still have X+Y>Z
    (because X/Y are general values from config), but that does not make it
    urgently in need of PQC migration — it gets P4 unless classically broken
    or quantum_weakened.

    Reachability weighting is applied as a multiplier in the Risk record's
    reachability_weight field — it does not change the priority label itself.
    """
    if classical_broken:
        return RiskPriority.P1

    # For non-quantum-vulnerable algorithms, urgency/HNDL are not applicable
    if not quantum_vulnerable and not quantum_weakened:
        return RiskPriority.P4

    if not quantum_vulnerable and quantum_weakened:
        return RiskPriority.P3

    # quantum_vulnerable from here on
    if urgency_flag and hndl_flag:
        return RiskPriority.P1

    if urgency_flag and not hndl_flag:
        return RiskPriority.P2

    if not urgency_flag and hndl_flag:
        return RiskPriority.P2

    # quantum_vulnerable, no urgency, no hndl
    return RiskPriority.P3


# ── Reachability weight ───────────────────────────────────────────────────────

def _reachability_weight(asset: CryptoAsset) -> float:
    """
    Compute the reachability weight for an asset.

    1.0 = reachable (full weight)
    0.5 = not reachable (lower weight — still tracked, risk not zero)
    None = reachability analysis not yet run (neutral weight = 0.8)

    PRD §5 stage 9: "Weight by classification, reachability, and HNDL flag."
    """
    if asset.reachable is True:
        return 1.0
    if asset.reachable is False:
        return 0.5
    # Not yet analysed — use a conservative neutral weight
    return 0.8


# ── Classification weight ─────────────────────────────────────────────────────

def _classification_weight(asset: CryptoAsset) -> float:
    """
    Compute classification weight for an asset.

    Infrastructure assets protecting critical communication channels
    receive slightly higher weight than application assets at the same
    sensitivity level, because their compromise affects all users.
    """
    if asset.classification == AssetClassification.INFRASTRUCTURE:
        if asset.business_criticality in (BusinessCriticality.CRITICAL,
                                           BusinessCriticality.HIGH):
            return 1.0
        return 0.9
    # Application assets
    if asset.business_criticality == BusinessCriticality.CRITICAL:
        return 1.0
    if asset.business_criticality == BusinessCriticality.HIGH:
        return 0.9
    if asset.business_criticality == BusinessCriticality.MEDIUM:
        return 0.7
    return 0.5


# ── Core Mosca computation ────────────────────────────────────────────────────

@dataclass
class MoscaResult:
    """Intermediate result before building the frozen Risk schema object."""
    x_years: float
    y_years: float
    z_years: float
    urgency_flag: bool
    hndl_flag: bool
    priority: RiskPriority
    reachability_weight: float
    classification_weight: float
    classical_broken: bool
    quantum_vulnerable: bool


def compute_mosca(
    asset: CryptoAsset,
    profiles: MoscaProfiles,
    pqc_config: PQCConfig,
    *,
    override_x: Optional[float] = None,
    override_y: Optional[float] = None,
    override_z: Optional[float] = None,
) -> MoscaResult:
    """
    Run Mosca's theorem for a single CryptoAsset.

    Args:
        asset:      The CryptoAsset to score.
        profiles:   Loaded MoscaProfiles configuration.
        pqc_config: Loaded PQCConfig for algorithm properties.
        override_x: Override X (data shelf life) — for future owner-provided data.
        override_y: Override Y (migration time) — for owner-provided estimates.
        override_z: Override Z (threat timeline) — for org-specific intel.

    Returns:
        MoscaResult with all computed values.
    """
    # ── Look up algorithm properties ──────────────────────────────────────────
    mapping = find_pqc_mapping(pqc_config, asset.algorithm, asset.purpose.value)

    classical_broken = bool(mapping and mapping.classical_broken)
    quantum_vulnerable = bool(mapping.quantum_vulnerable if mapping else True)
    quantum_weakened = bool(mapping and mapping.quantum_weakened)

    # ── Compute X (data shelf life) ───────────────────────────────────────────
    if override_x is not None:
        x = override_x
    else:
        x = get_x_years(
            profiles,
            asset.classification.value,
            asset.sensitivity.value,
        )

    # ── Compute Y (migration time) ────────────────────────────────────────────
    if override_y is not None:
        y = override_y
    else:
        y = get_y_years(profiles, asset.algorithm, asset.purpose.value)

    # ── Z (threat timeline) ───────────────────────────────────────────────────
    z = override_z if override_z is not None else profiles.z_years_default

    # ── Mosca theorem ─────────────────────────────────────────────────────────
    urgency_flag = (x + y) > z

    # ── HNDL ─────────────────────────────────────────────────────────────────
    hndl_flag = _determine_hndl(asset.purpose, x, mapping, profiles)

    # ── Priority ──────────────────────────────────────────────────────────────
    priority = _assign_priority(
        urgency_flag=urgency_flag,
        hndl_flag=hndl_flag,
        classical_broken=classical_broken,
        quantum_vulnerable=quantum_vulnerable,
        quantum_weakened=quantum_weakened,
    )

    # ── Weights ───────────────────────────────────────────────────────────────
    r_weight = _reachability_weight(asset)
    c_weight = _classification_weight(asset)

    logger.debug(
        "Mosca [%s %s]: X=%.0f + Y=%.0f = %.0f vs Z=%.0f → urgency=%s "
        "hndl=%s priority=%s classical_broken=%s",
        asset.algorithm, asset.purpose.value,
        x, y, x + y, z,
        urgency_flag, hndl_flag, priority.value, classical_broken,
    )

    return MoscaResult(
        x_years=x,
        y_years=y,
        z_years=z,
        urgency_flag=urgency_flag,
        hndl_flag=hndl_flag,
        priority=priority,
        reachability_weight=r_weight,
        classification_weight=c_weight,
        classical_broken=classical_broken,
        quantum_vulnerable=quantum_vulnerable,
    )


# ── Engine: process an inventory ──────────────────────────────────────────────

class MoscaEngine:
    """
    Mosca Risk Engine — processes a list of CryptoAssets and annotates
    each with a Risk record.

    Usage:
        engine = MoscaEngine()
        assets_with_risk = engine.process(assets)
    """

    def __init__(
        self,
        mosca_profiles_path: Optional[Path] = None,
        pqc_mappings_path: Optional[Path] = None,
    ) -> None:
        self._profiles = load_mosca_profiles(mosca_profiles_path)
        self._pqc_config = load_pqc_config(pqc_mappings_path)

    def score_asset(
        self,
        asset: CryptoAsset,
        *,
        override_x: Optional[float] = None,
        override_y: Optional[float] = None,
        override_z: Optional[float] = None,
    ) -> CryptoAsset:
        """
        Compute and attach a Risk record to a single CryptoAsset.

        Returns a new CryptoAsset with the risk field populated.
        The original asset is NOT mutated.
        """
        result = compute_mosca(
            asset=asset,
            profiles=self._profiles,
            pqc_config=self._pqc_config,
            override_x=override_x,
            override_y=override_y,
            override_z=override_z,
        )

        risk = Risk(
            mosca_x_years=result.x_years,
            mosca_y_years=result.y_years,
            mosca_z_years=result.z_years,
            urgency_flag=result.urgency_flag,
            hndl_flag=result.hndl_flag,
            priority=result.priority,
            reachability_weight=result.reachability_weight,
            classification_weight=result.classification_weight,
        )

        return asset.model_copy(update={"risk": risk})

    def process(self, assets: list[CryptoAsset]) -> list[CryptoAsset]:
        """
        Score all assets in a list. Returns new CryptoAsset instances
        with risk records attached.
        """
        scored: list[CryptoAsset] = []
        p1_count = p2_count = 0

        for asset in assets:
            scored_asset = self.score_asset(asset)
            scored.append(scored_asset)
            if scored_asset.risk:
                if scored_asset.risk.priority == RiskPriority.P1:
                    p1_count += 1
                elif scored_asset.risk.priority == RiskPriority.P2:
                    p2_count += 1

        logger.info(
            "Mosca engine scored %d assets: %d P1, %d P2",
            len(scored), p1_count, p2_count,
        )
        return scored

    @property
    def z_years(self) -> float:
        """The threat timeline Z value in use."""
        return self._profiles.z_years_default
