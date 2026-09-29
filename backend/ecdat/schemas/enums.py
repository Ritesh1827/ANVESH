"""
Shared enumerations for the ECDAT data model.

These enums define the controlled vocabularies used across all Pydantic schema
models. They enforce structural correctness at the data-contract layer without
embedding any business logic (risk calculations, PQC mapping, migration decisions
all live in their respective engines — not here).

Reference: PRD §5 (pipeline stages), §6 (non-functional requirements), §9 (sample output).
"""

from enum import Enum


# ── Detection / discovery ──────────────────────────────────────────────────────

class DetectionMethod(str, Enum):
    """How a cryptographic asset was detected."""
    AST_RULE = "ast_rule"                     # Tree-sitter AST rule match (source code)
    BINARY_FINGERPRINT = "binary_fingerprint" # Symbol/import extraction from binary
    CERTIFICATE_PARSER = "certificate_parser" # X.509 certificate parser
    LAYER_INSPECTION = "layer_inspection"     # Container layer / package manifest
    TLS_PROBE = "tls_probe"                   # Live TLS handshake inspection
    SSH_PROBE = "ssh_probe"                   # Live SSH handshake inspection
    LLM_ENRICHMENT = "llm_enrichment"         # Ambiguous finding resolved by LLM (secondary)
    ENTROPY_CHECK = "entropy_check"           # High-entropy string / key-like blob detection
    REGEX_FALLBACK = "regex_fallback"         # Regex pattern match (lower confidence)


class FindingType(str, Enum):
    """Whether a finding passed through deterministic rules or LLM enrichment."""
    DETERMINISTIC = "deterministic"
    LLM_ENRICHED = "llm_enriched"


# ── Cryptographic purpose ──────────────────────────────────────────────────────

class CryptoPurpose(str, Enum):
    """
    Cryptographic purpose of the asset.

    Purpose-awareness is mandatory for correct PQC mapping (PRD §5 stage 10):
    key establishment maps to ML-KEM; digital signatures map to ML-DSA / SLH-DSA.
    The Recommendation Engine reads this field — do not conflate purposes here.
    """
    KEY_ESTABLISHMENT = "key_establishment"   # Key encapsulation / key exchange / key agreement
    DIGITAL_SIGNATURE = "digital_signature"   # Signing and verification
    ENCRYPTION = "encryption"                 # Symmetric or asymmetric encryption (confidentiality)
    HASHING = "hashing"                       # Digest / integrity only, no key involved
    MAC = "mac"                               # Message authentication code (keyed)
    KEY_DERIVATION = "key_derivation"         # KDF (HKDF, PBKDF2, etc.)
    RANDOM_GENERATION = "random_generation"   # CSPRNG / entropy source
    CERTIFICATE = "certificate"               # X.509 certificate binding
    UNKNOWN = "unknown"                       # Could not determine; may trigger LLM enrichment


# ── Asset classification (TEC 910018:2025 taxonomy) ────────────────────────────

class AssetClassification(str, Enum):
    """
    High-level classification of the asset's operational domain.

    Matches TEC 910018:2025 taxonomy referenced in PRD §5 stage 6.
    """
    APPLICATION = "application"       # In-application cryptographic usage
    INFRASTRUCTURE = "infrastructure" # TLS endpoints, SSH, VPN, certificate infrastructure


class SensitivityLevel(str, Enum):
    """Data sensitivity of the content protected by this asset."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    HIGH = "high"
    CRITICAL = "critical"


class BusinessCriticality(str, Enum):
    """Business impact if this asset were compromised or broke."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LifecycleStage(str, Enum):
    """Current lifecycle stage of this cryptographic asset."""
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    EXPIRED = "expired"         # Applies to certificates
    ROTATION_PENDING = "rotation_pending"
    LEGACY = "legacy"           # Known-old, still in use
    UNKNOWN = "unknown"


# ── Risk ──────────────────────────────────────────────────────────────────────

class RiskPriority(str, Enum):
    """
    Risk priority level assigned by the Mosca Risk Engine.

    P1 is the highest urgency (X + Y > Z and HNDL exposure).
    The Mosca engine assigns this; the schema validates it.
    """
    P1 = "P1"   # Critical — immediate action required
    P2 = "P2"   # High — plan within current cycle
    P3 = "P3"   # Medium — include in next migration wave
    P4 = "P4"   # Low — monitor, no immediate action
    UNKNOWN = "UNKNOWN"


# ── PQC recommendation / standardization status ───────────────────────────────

class StandardizationStatus(str, Enum):
    """
    Standardization status of the recommended PQC algorithm.

    PRD §5 stage 10 explicitly requires keeping finalized algorithms
    separate from those still under standardization. Never recommend
    non-finalized algorithms as primary replacements.
    """
    STANDARDIZED = "standardized"         # NIST-finalized: FIPS 203 / 204 / 205
    UNDER_STANDARDIZATION = "under_standardization"  # Still in NIST process (e.g. HQC)
    CLASSICAL = "classical"               # Classical algorithm (source, not recommendation)
    DEPRECATED = "deprecated"             # Broken or formally deprecated


class MigrationPathType(str, Enum):
    """
    Migration strategy type for the recommended transition.

    PRD §5 stage 10: hybrid (classical + PQC) is the default during migration;
    pure-PQC only for greenfield systems.
    """
    HYBRID = "hybrid"           # Classical + PQC in parallel (migration default)
    PURE_PQC = "pure_pqc"       # PQC-only (greenfield)
    CLASSICAL_UPGRADE = "classical_upgrade"  # Upgrade within classical (e.g. RSA-2048 → RSA-4096)
    NO_ACTION = "no_action"     # Already quantum-safe


# ── CBOM / output ─────────────────────────────────────────────────────────────

class CBOMFormat(str, Enum):
    """Supported CycloneDX export formats."""
    JSON = "json"
    XML = "xml"
