"""
ecdat.schemas — Public API for the ECDAT data model.

Import all schema types from here. All other pipeline stages should import
from this package rather than from individual submodules, so that internal
module refactoring does not break consumers.

Usage:
    from ecdat.schemas import CryptoAsset, Evidence, Risk, Recommendation
    from ecdat.schemas import CBOMExport, CBOMMetadata, CBOMQualityScore
    from ecdat.schemas.enums import CryptoPurpose, RiskPriority, DetectionMethod
"""

# ── Enums (import first; models depend on them) ───────────────────────────────
from .enums import (
    AssetClassification,
    BusinessCriticality,
    CBOMFormat,
    CryptoPurpose,
    DetectionMethod,
    FindingType,
    LifecycleStage,
    MigrationPathType,
    RiskPriority,
    SensitivityLevel,
    StandardizationStatus,
)

# ── Evidence ──────────────────────────────────────────────────────────────────
from .evidence import Evidence, SourceLocation

# ── Risk ──────────────────────────────────────────────────────────────────────
from .risk import MoscaParameters, Risk

# ── Recommendation ────────────────────────────────────────────────────────────
from .recommendation import Recommendation

# ── Master inventory record ───────────────────────────────────────────────────
from .crypto_asset import CryptoAsset

# ── CBOM export ───────────────────────────────────────────────────────────────
from .cbom import CBOMExport, CBOMMetadata, CBOMQualityScore, CBOMVersionDiff

__all__ = [
    # Enums
    "AssetClassification",
    "BusinessCriticality",
    "CBOMFormat",
    "CryptoPurpose",
    "DetectionMethod",
    "FindingType",
    "LifecycleStage",
    "MigrationPathType",
    "RiskPriority",
    "SensitivityLevel",
    "StandardizationStatus",
    # Evidence
    "Evidence",
    "SourceLocation",
    # Risk
    "MoscaParameters",
    "Risk",
    # Recommendation
    "Recommendation",
    # CryptoAsset
    "CryptoAsset",
    # CBOM
    "CBOMExport",
    "CBOMMetadata",
    "CBOMQualityScore",
    "CBOMVersionDiff",
]
