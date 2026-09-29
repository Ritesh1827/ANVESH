"""
Infrastructure probe — PRD §5 stages 1 & 2 (infrastructure surface).

PRD §5 stage 2: "a TLS/SSH probe (infrastructure)".
PRD §8 Technology Stack: "Infrastructure probe: Python `ssl`/`socket`,
`paramiko` — Lightweight TLS/SSH handshake inspection without needing a
full scanner framework."
PRD §11: "Infrastructure scanning is demonstrated against a defined set
of endpoints, not a full enterprise network sweep."

Scope (bounded, honest):
  - TLS probe via stdlib `ssl`/`socket` only: connect, read the negotiated
    TLS version, cipher suite, and peer certificate (public key algorithm
    + key size + signature hash + expiry). No paramiko dependency — SSH
    probing stays recorded-only until that dependency is justified.
  - Each endpoint yields up to THREE assets through the shared path:
      1. The negotiated cipher suite (algorithm + purpose from
         config/infra_rules.yaml — config-driven, never hardcoded).
      2. The peer certificate public key (RSA/EC → key_establishment or
         digital_signature, same mapping as cert_scanner).
      3. The peer certificate signature hash (weak-hash capture, same as
         the C-002 certificate asset).
  - Findings carry detection_method TLS_PROBE, reachable=None is NOT set
    blindly: a live handshake that negotiates a cipher IS evidence of
    exposure, so these assets are reachable=True with an exposure context
    naming the endpoint. This is the one surface where reachability is
    known-positive by construction — the probe itself is the entry point.
    (ReachabilityEngine leaves any pre-set reachable value intact; it only
    computes call-graph reachability for source_code assets.)
  - Timeouts are short (10s default), failures are parse errors — an
    unreachable endpoint never becomes a finding.

Read-only guarantee (PRD §6): a normal TLS handshake performs no
modification on the target. No credentials are sent.
"""

from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import yaml
from pathlib import Path

from cryptography import x509

from ecdat.discovery.cert_scanner import _extract_public_key_info
from ecdat.engines.evidence_engine import (
    _STAGING_CLASSIFICATION,
    _STAGING_CRITICALITY,
    _STAGING_SENSITIVITY,
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

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).parent.parent.parent.parent
_DEFAULT_RULES_PATH = _REPO_ROOT / "config" / "infra_rules.yaml"

DEFAULT_TIMEOUT_S = 10.0


@dataclass(frozen=True)
class InfraCipherRule:
    """One config-driven cipher-suite mapping rule."""

    rule_id: str
    description: str
    pattern: str
    algorithm: str
    purpose: str
    confidence: float


def load_infra_rules(rules_path: Optional[Path] = None) -> list[InfraCipherRule]:
    """Load and validate infrastructure cipher rules from YAML."""
    import re

    path = Path(rules_path) if rules_path else _DEFAULT_RULES_PATH
    if not path.exists():
        raise FileNotFoundError(f"Infrastructure rules not found: {path}")
    with open(path, "r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict) or "infra_rules" not in raw:
        raise ValueError(f"Invalid infra rules file: {path}")
    rules: list[InfraCipherRule] = []
    seen: set[str] = set()
    for entry in raw["infra_rules"]:
        rule_id = entry.get("rule_id", "")
        if rule_id in seen:
            raise ValueError(f"Duplicate infra rule_id '{rule_id}'")
        seen.add(rule_id)
        for required in ("rule_id", "description", "pattern", "algorithm",
                         "purpose", "confidence"):
            if required not in entry:
                raise ValueError(f"Infra rule {rule_id} missing '{required}'")
        try:
            CryptoPurpose(entry["purpose"])
        except ValueError:
            raise ValueError(
                f"Infra rule {rule_id}: unknown purpose '{entry['purpose']}'"
            ) from None
        re.compile(entry["pattern"])
        confidence = float(entry["confidence"])
        if not (0.0 <= confidence <= 1.0):
            raise ValueError(f"Infra rule {rule_id}: confidence outside [0.0, 1.0]")
        rules.append(InfraCipherRule(
            rule_id=rule_id,
            description=entry["description"],
            pattern=entry["pattern"],
            algorithm=entry["algorithm"],
            purpose=entry["purpose"],
            confidence=confidence,
        ))
    logger.info("Loaded %d infra rules from %s", len(rules), path)
    return rules


@dataclass
class InfraEndpointResult:
    """Result of probing a single host:port endpoint."""

    endpoint: str
    host: str
    port: int
    assets: list[CryptoAsset]
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    probe_error: bool = False
    error_message: Optional[str] = None

    @property
    def asset_count(self) -> int:
        return len(self.assets)


@dataclass
class InfraScanResults:
    """Aggregate result across all probed endpoints."""

    results: list[InfraEndpointResult]
    endpoints_probed: int
    endpoints_failed: int = 0

    @property
    def all_assets(self) -> list[CryptoAsset]:
        assets: list[CryptoAsset] = []
        for result in self.results:
            assets.extend(result.assets)
        return assets

    @property
    def total_assets(self) -> int:
        return sum(r.asset_count for r in self.results)


def parse_endpoint(ref: str) -> tuple[str, int]:
    """Parse 'host' or 'host:port' (default 443); raises ValueError."""
    cleaned = ref.strip()
    if not cleaned or "://" in cleaned or " " in cleaned:
        raise ValueError(f"Invalid endpoint (use host or host:port): {ref}")
    if cleaned.count(":") > 1 and not cleaned.startswith("["):
        raise ValueError(f"Invalid endpoint (use host or host:port): {ref}")
    if ":" in cleaned:
        host, _, port_str = cleaned.rpartition(":")
        if not host:
            raise ValueError(f"Invalid endpoint (use host or host:port): {ref}")
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"Invalid port in endpoint: {ref}") from None
        if not (1 <= port <= 65535):
            raise ValueError(f"Port out of range in endpoint: {ref}")
        return host, port
    return cleaned, 443


def _base_evidence(
    endpoint: str,
    rule_id: str,
    confidence: float,
    snippet: str,
) -> Evidence:
    return Evidence(
        detection_method=DetectionMethod.TLS_PROBE,
        finding_type=FindingType.DETERMINISTIC,
        rule_id=rule_id,
        location=SourceLocation(
            file_path=f"tls://{endpoint}",
            line_number=None,
            snippet=snippet[:200],
        ),
        source_surface="infrastructure",
        confidence=confidence,
    )


def _exposure(endpoint: str, detail: str) -> str:
    return f"Live TLS endpoint tls://{endpoint} negotiates {detail} — directly exposed."


def _match_cipher(
    cipher_name: str, rules: list[InfraCipherRule]
) -> Optional[InfraCipherRule]:
    import re

    for rule in rules:
        if re.search(rule.pattern, cipher_name, re.IGNORECASE):
            return rule
    return None


def probe_endpoint(
    ref: str,
    rules: Optional[list[InfraCipherRule]] = None,
    scan_id: Optional[str] = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> InfraEndpointResult:
    """Perform a read-only TLS handshake and build findings from it."""
    import re

    host, port = parse_endpoint(ref)
    endpoint = f"{host}:{port}"
    loaded = rules if rules is not None else load_infra_rules()

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1

    try:
        with socket.create_connection((host, port), timeout=timeout_s) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                version = tls.version() or "unknown"
                cipher = tls.cipher()
                cipher_name = cipher[0] if cipher else "unknown"
                der = tls.getpeercert(binary_form=True)
    except Exception as exc:  # noqa: BLE001 — probe failure is data, not a crash
        return InfraEndpointResult(
            endpoint=endpoint, host=host, port=port, assets=[],
            probe_error=True, error_message=str(exc)[:300],
        )

    assets: list[CryptoAsset] = []

    matched = _match_cipher(cipher_name, loaded)
    if matched is not None:
        try:
            purpose = CryptoPurpose(matched.purpose)
        except ValueError:
            purpose = CryptoPurpose.UNKNOWN
        assets.append(CryptoAsset(
            scan_id=scan_id,
            algorithm=matched.algorithm,
            purpose=purpose,
            location=f"tls://{endpoint}",
            protocol=version,
            source_surface="infrastructure",
            classification=AssetClassification.INFRASTRUCTURE,
            sensitivity=SensitivityLevel.HIGH,
            business_criticality=BusinessCriticality.CRITICAL,
            lifecycle_stage=LifecycleStage.ACTIVE,
            reachable=True,
            exposure_context=_exposure(endpoint, f"{cipher_name} over {version}"),
            evidence=_base_evidence(
                endpoint, matched.rule_id, matched.confidence,
                f"{version} {cipher_name}",
            ),
            risk=None,
            recommendation=None,
        ))
    else:
        logger.debug("No infra rule matched cipher %s on %s", cipher_name, endpoint)

    _ = re
    if der:
        try:
            cert = x509.load_der_x509_certificate(der)
        except Exception as exc:  # noqa: BLE001 — cert parse failure is data
            logger.debug("Peer cert parse failed for %s: %s", endpoint, exc)
            cert = None
        if cert is not None:
            pk_info = _extract_public_key_info(cert)
            try:
                expiry = cert.not_valid_after_utc
            except AttributeError:
                expiry = datetime.now(timezone.utc)
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            serial = hex(cert.serial_number)
            if pk_info is not None:
                assets.append(CryptoAsset(
                    scan_id=scan_id,
                    algorithm=pk_info.algorithm,
                    key_size_bits=pk_info.key_size_bits,
                    purpose=pk_info.purpose,
                    location=f"tls://{endpoint}",
                    protocol=version,
                    source_surface="infrastructure",
                    classification=AssetClassification.INFRASTRUCTURE,
                    sensitivity=SensitivityLevel.CRITICAL,
                    business_criticality=BusinessCriticality.CRITICAL,
                    lifecycle_stage=LifecycleStage.ACTIVE,
                    certificate_subject=subject,
                    certificate_issuer=issuer,
                    certificate_expiry=expiry,
                    certificate_serial=serial,
                    reachable=True,
                    exposure_context=_exposure(
                        endpoint, f"certificate key {pk_info.algorithm}"),
                    evidence=_base_evidence(
                        endpoint, "I-100", 0.97,
                        f"peer cert {pk_info.algorithm}",
                    ),
                    risk=None,
                    recommendation=None,
                ))
            sig_hash = cert.signature_hash_algorithm
            if sig_hash is not None and sig_hash.name.lower() in ("md5", "sha1"):
                weak = "MD5" if sig_hash.name.lower() == "md5" else "SHA-1"
                assets.append(CryptoAsset(
                    scan_id=scan_id,
                    algorithm=weak,
                    purpose=CryptoPurpose.HASHING,
                    location=f"tls://{endpoint}",
                    protocol=version,
                    source_surface="infrastructure",
                    classification=AssetClassification.INFRASTRUCTURE,
                    sensitivity=SensitivityLevel.HIGH,
                    business_criticality=BusinessCriticality.CRITICAL,
                    lifecycle_stage=LifecycleStage.ACTIVE,
                    certificate_subject=subject,
                    certificate_issuer=issuer,
                    certificate_expiry=expiry,
                    certificate_serial=serial,
                    reachable=True,
                    exposure_context=_exposure(
                        endpoint, f"weak signature hash {weak}"),
                    evidence=_base_evidence(
                        endpoint, "I-101", 0.95,
                        f"peer cert signed with {weak}",
                    ),
                    risk=None,
                    recommendation=None,
                ))

    return InfraEndpointResult(
        endpoint=endpoint, host=host, port=port, assets=assets,
        tls_version=version, cipher_suite=cipher_name,
    )


def probe_endpoints(
    refs: list[str],
    rules: Optional[list[InfraCipherRule]] = None,
    scan_id: Optional[str] = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> InfraScanResults:
    """Probe each endpoint; invalid refs and failures never become findings."""
    loaded = rules if rules is not None else load_infra_rules()
    results: list[InfraEndpointResult] = []
    failed = 0
    for ref in refs:
        try:
            result = probe_endpoint(ref, rules=loaded, scan_id=scan_id,
                                    timeout_s=timeout_s)
        except ValueError as exc:
            results.append(InfraEndpointResult(
                endpoint=ref.strip(), host=ref.strip(), port=0, assets=[],
                probe_error=True, error_message=str(exc)[:300],
            ))
            failed += 1
            continue
        if result.probe_error:
            failed += 1
        results.append(result)
    return InfraScanResults(
        results=results, endpoints_probed=len(refs), endpoints_failed=failed,
    )
