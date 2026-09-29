"""
Container scanner — PRD §5 stages 1 & 2 (containers surface).

PRD §5 stage 2: "Apply the detection mechanism appropriate to each input
type: ... layer inspection (containers)".
PRD §11: "Container analysis covers layer/package inspection, not deep
binary analysis of every packaged artifact."

Scope (bounded, honest):
  Container image *references* (e.g. "nginx:1.25", "registry/org/img:tag")
  are recorded. When the reference points at a local directory (an
  unpacked image rootfs or build context), the scanner performs layer/
  package inspection: it reads package manifests (apk/db, dpkg/status,
  rpm databases are out of scope — manifest *files* such as
  Dockerfile, requirements.txt, package.json, and *.txt lockfiles are
  inspected for pinned crypto libraries) and records each pinned
  cryptographic library as a finding. No registry network access, no
  image pulls, no Docker daemon required.

  Each manifest hit becomes a CryptoAsset with detection_method
  LAYER_INSPECTION, purpose from a config-driven manifest rule file
  (config/container_rules.yaml), and reachable=None (no call graph for
  container contents — same discipline as certificates/binaries).

Findings flow through the SAME inventory → Classification (container
surface rules already exist) → Reachability (None) → Completeness path.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from ecdat.engines.evidence_engine import (
    _STAGING_CLASSIFICATION,
    _STAGING_CRITICALITY,
    _STAGING_SENSITIVITY,
)
from ecdat.schemas import (
    CryptoAsset,
    CryptoPurpose,
    DetectionMethod,
    Evidence,
    FindingType,
    LifecycleStage,
    SourceLocation,
    BusinessCriticality,
)

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).parent.parent.parent.parent
_DEFAULT_RULES_PATH = _REPO_ROOT / "config" / "container_rules.yaml"

_MANIFEST_FILENAMES = frozenset({
    "dockerfile", "containerfile",
    "requirements.txt", "requirements.lock",
    "package.json", "package-lock.json",
    "go.mod", "cargo.toml", "cargo.lock",
    "pom.xml", "build.gradle",
})

_IMAGE_REF_RE = re.compile(
    r"^(?:(?P<registry>[a-zA-Z0-9][a-zA-Z0-9._:-]*)/)?"
    r"(?P<name>[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*)"
    r"(?::(?P<tag>[\w][\w.-]*))?(?:@sha256:(?P<digest>[a-f0-9]{64}))?$"
)


@dataclass(frozen=True)
class ContainerRule:
    """One config-driven container manifest rule."""

    rule_id: str
    description: str
    pattern: str
    algorithm: str
    purpose: str
    confidence: float
    compiled: re.Pattern


def load_container_rules(rules_path: Optional[Path] = None) -> list[ContainerRule]:
    """Load and validate container manifest rules from YAML."""
    path = Path(rules_path) if rules_path else _DEFAULT_RULES_PATH
    if not path.exists():
        raise FileNotFoundError(f"Container rules not found: {path}")
    with open(path, "r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict) or "container_rules" not in raw:
        raise ValueError(f"Invalid container rules file: {path}")
    rules: list[ContainerRule] = []
    seen: set[str] = set()
    for entry in raw["container_rules"]:
        rule_id = entry.get("rule_id", "")
        if rule_id in seen:
            raise ValueError(f"Duplicate container rule_id '{rule_id}'")
        seen.add(rule_id)
        for required in ("rule_id", "description", "pattern", "algorithm",
                         "purpose", "confidence"):
            if required not in entry:
                raise ValueError(f"Container rule {rule_id} missing '{required}'")
        try:
            CryptoPurpose(entry["purpose"])
        except ValueError:
            raise ValueError(
                f"Container rule {rule_id}: unknown purpose '{entry['purpose']}'"
            ) from None
        confidence = float(entry["confidence"])
        if not (0.0 <= confidence <= 1.0):
            raise ValueError(f"Container rule {rule_id}: confidence outside [0.0, 1.0]")
        rules.append(ContainerRule(
            rule_id=rule_id,
            description=entry["description"],
            pattern=entry["pattern"],
            algorithm=entry["algorithm"],
            purpose=entry["purpose"],
            confidence=confidence,
            compiled=re.compile(entry["pattern"], re.IGNORECASE),
        ))
    logger.info("Loaded %d container rules from %s", len(rules), path)
    return rules


@dataclass
class ContainerScanResult:
    """Result of inspecting one container reference."""

    image_ref: str
    assets: list[CryptoAsset]
    inspected_path: Optional[Path] = None
    parse_error: bool = False
    error_message: Optional[str] = None

    @property
    def asset_count(self) -> int:
        return len(self.assets)


@dataclass
class ContainerScanResults:
    """Aggregate result across all container references in a scan."""

    results: list[ContainerScanResult]
    refs_scanned: int
    refs_recorded_only: int = 0

    @property
    def all_assets(self) -> list[CryptoAsset]:
        assets: list[CryptoAsset] = []
        for result in self.results:
            assets.extend(result.assets)
        return assets

    @property
    def total_assets(self) -> int:
        return sum(r.asset_count for r in self.results)


def parse_image_ref(ref: str) -> Optional[dict]:
    """Validate a container image reference; None when it is not one."""
    match = _IMAGE_REF_RE.match(ref.strip())
    if not match:
        return None
    return match.groupdict()


def _make_container_asset(
    image_ref: str,
    rule: ContainerRule,
    manifest_rel: str,
    matched_text: str,
    scan_id: Optional[str],
) -> CryptoAsset:
    try:
        purpose = CryptoPurpose(rule.purpose)
    except ValueError:
        purpose = CryptoPurpose.UNKNOWN
    file_path = f"{image_ref} :: {manifest_rel}"
    location = SourceLocation(
        file_path=file_path,
        line_number=None,
        snippet=f"{rule.rule_id}: {matched_text[:120]}",
    )
    evidence = Evidence(
        detection_method=DetectionMethod.LAYER_INSPECTION,
        finding_type=FindingType.DETERMINISTIC,
        rule_id=rule.rule_id,
        location=location,
        source_surface="container",
        confidence=rule.confidence,
    )
    return CryptoAsset(
        scan_id=scan_id,
        algorithm=rule.algorithm,
        purpose=purpose,
        location=file_path,
        source_surface="container",
        classification=_STAGING_CLASSIFICATION,
        sensitivity=_STAGING_SENSITIVITY,
        business_criticality=BusinessCriticality.LOW,
        lifecycle_stage=LifecycleStage.ACTIVE,
        reachable=None,
        evidence=evidence,
        risk=None,
        recommendation=None,
    )


def scan_container_refs(
    refs: list[str],
    rules: Optional[list[ContainerRule]] = None,
    scan_id: Optional[str] = None,
    local_contexts: Optional[dict[str, Path]] = None,
) -> ContainerScanResults:
    """Inspect container references; inspect local contexts when provided.

    A reference that is a local directory is layer-inspected (manifests).
    Any other syntactically valid reference is recorded with zero assets
    (registry pulls are out of scope — PRD §11). Invalid references are
    recorded as parse errors, never as findings.
    """
    loaded = rules if rules is not None else load_container_rules()
    contexts = local_contexts or {}
    results: list[ContainerScanResult] = []
    recorded_only = 0
    for ref in refs:
        cleaned = ref.strip()
        local_dir = contexts.get(cleaned)
        if local_dir is not None and Path(local_dir).is_dir():
            results.append(_inspect_local_context(
                cleaned, Path(local_dir), loaded, scan_id,
            ))
            continue
        if Path(cleaned).is_dir():
            results.append(_inspect_local_context(
                cleaned, Path(cleaned), loaded, scan_id,
            ))
            continue
        parsed = parse_image_ref(cleaned)
        if parsed is None:
            results.append(ContainerScanResult(
                image_ref=cleaned, assets=[], parse_error=True,
                error_message="Not a valid image reference or local directory",
            ))
            continue
        recorded_only += 1
        results.append(ContainerScanResult(image_ref=cleaned, assets=[]))
    return ContainerScanResults(
        results=results,
        refs_scanned=len(refs),
        refs_recorded_only=recorded_only,
    )


def _inspect_local_context(
    ref: str,
    root: Path,
    rules: list[ContainerRule],
    scan_id: Optional[str],
) -> ContainerScanResult:
    assets: list[CryptoAsset] = []
    seen: set[str] = set()
    manifests = [
        item for item in sorted(root.rglob("*"))
        if item.is_file() and item.name.lower() in _MANIFEST_FILENAMES
        and ".git/" not in item.as_posix()
    ]
    for manifest in manifests[:50]:
        try:
            text = manifest.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(manifest.relative_to(root)).replace("\\", "/")
        for line in text.splitlines():
            for rule in rules:
                key = (rule.rule_id, rel)
                if key in seen:
                    continue
                match = rule.compiled.search(line)
                if match:
                    seen.add(key)
                    assets.append(_make_container_asset(
                        ref, rule, rel, match.group(0), scan_id,
                    ))
    return ContainerScanResult(
        image_ref=ref, assets=assets, inspected_path=root,
    )
