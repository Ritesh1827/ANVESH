"""
Binary scanner — PRD §5 stages 1 & 2 (binaries/libraries surface).

PRD §5 stage 2: "Apply the detection mechanism appropriate to each input
type: ... binary fingerprinting (compiled artefacts)".
PRD §8 Technology Stack: "Binary analysis: pyelftools / LIEF — Mature,
tested parsers for ELF/PE symbol and import extraction."

Scope (bounded, honest):
  - ELF binaries: imported-symbol and dynamic-section fingerprinting via
    pyelftools (DT_NEEDED entries, .dynsym symbol names). No disassembly,
    no deep per-function analysis (PRD §11: container/binary depth limits).
  - PE binaries: best-effort import-table scan from raw bytes for known
    cryptographic DLL names (advapi32, bcrypt, crypt32, ncrypt). Full PE
    parsing via LIEF is intentionally not required here — LIEF ships binary
    wheels that complicate the locked environment, and the string-table
    approach captures the import evidence the pipeline needs.
  - Every candidate string match is verified against config-driven
    fingerprint rules (config/binary_fingerprints.yaml) — the same
    "config-driven, not hardcoded" discipline as detection_rules.yaml.
    Unknown strings never become findings.

Findings flow through the SAME downstream path as every other surface:
  Evidence Engine semantics (location, method, confidence) → the shared
  inventory → ClassificationEngine's config-driven rules (binary surface
  rules already exist in classification_rules.yaml) → Reachability
  (reachable=None for binaries, enforced by ReachabilityEngine) →
  Completeness (binary surface counted when scanned).

Read-only guarantee (PRD §6): binaries are opened read-only and memory-
mapped; nothing is executed, extracted, or modified.
"""

from __future__ import annotations

import logging
import mmap
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from ecdat.engines.evidence_engine import (
    _STAGING_CLASSIFICATION,
    _STAGING_CRITICALITY,
    _STAGING_SENSITIVITY,
)
from ecdat.schemas import (
    BusinessCriticality,
    CryptoAsset,
    CryptoPurpose,
    DetectionMethod,
    Evidence,
    FindingType,
    LifecycleStage,
    SourceLocation,
)

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).parent.parent.parent.parent
_DEFAULT_FINGERPRINTS_PATH = _REPO_ROOT / "config" / "binary_fingerprints.yaml"

_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"

_MAX_BINARY_BYTES = 200 * 1024 * 1024

_SCAN_EXTENSIONS = frozenset({
    ".so", ".dylib", ".dll", ".exe", ".elf", ".o", ".a", ".ko",
    ".bin", ".out", ".node",
})

_NAME_HINTS = ("libcrypto", "libssl", "openssl", "crypt", "ssl", "tls",
               "crypto", "libeay", "ssleay")


# ── Config ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class FingerprintRule:
    """One config-driven binary fingerprint rule."""

    rule_id: str
    description: str
    pattern: str
    algorithm: str
    purpose: str
    confidence: float
    compiled: re.Pattern = field(compare=False, repr=False)


def load_fingerprint_rules(
    fingerprints_path: Optional[Path] = None,
) -> list[FingerprintRule]:
    """Load and validate binary fingerprint rules from YAML."""
    path = Path(fingerprints_path) if fingerprints_path else _DEFAULT_FINGERPRINTS_PATH
    if not path.exists():
        raise FileNotFoundError(f"Binary fingerprint rules not found: {path}")
    with open(path, "r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict) or "fingerprints" not in raw:
        raise ValueError(f"Invalid fingerprint file — expected 'fingerprints' key: {path}")
    rules: list[FingerprintRule] = []
    seen: set[str] = set()
    for entry in raw["fingerprints"]:
        rule_id = entry.get("rule_id", "")
        if rule_id in seen:
            raise ValueError(f"Duplicate fingerprint rule_id '{rule_id}' in {path}")
        seen.add(rule_id)
        for required in ("rule_id", "description", "pattern", "algorithm",
                         "purpose", "confidence"):
            if required not in entry:
                raise ValueError(f"Fingerprint {rule_id} missing '{required}'")
        confidence = float(entry["confidence"])
        if not (0.0 <= confidence <= 1.0):
            raise ValueError(f"Fingerprint {rule_id}: confidence outside [0.0, 1.0]")
        try:
            CryptoPurpose(entry["purpose"])
        except ValueError:
            raise ValueError(
                f"Fingerprint {rule_id}: unknown purpose '{entry['purpose']}'"
            ) from None
        rules.append(FingerprintRule(
            rule_id=rule_id,
            description=entry["description"],
            pattern=entry["pattern"],
            algorithm=entry["algorithm"],
            purpose=entry["purpose"],
            confidence=confidence,
            compiled=re.compile(entry["pattern"].encode("ascii"),
                                re.IGNORECASE),
        ))
    logger.info("Loaded %d binary fingerprint rules from %s", len(rules), path)
    return rules


# ── Binary type detection ─────────────────────────────────────────────────────

def _classify_binary(path: Path) -> Optional[str]:
    """Return 'elf', 'pe', or None based on magic bytes + extension hints."""
    try:
        with open(path, "rb") as handle:
            magic = handle.read(4)
    except OSError:
        return None
    if magic.startswith(_ELF_MAGIC):
        return "elf"
    if magic[:2] == _PE_MAGIC:
        return "pe"
    if path.suffix.lower() in _SCAN_EXTENSIONS:
        return "unknown-elf-like"
    return None


def _read_bytes(path: Path) -> Optional[bytes]:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size <= 0 or size > _MAX_BINARY_BYTES:
        return None
    try:
        with open(path, "rb") as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                return bytes(mapped)
    except (OSError, ValueError):
        return None


def _elf_strings(path: Path) -> list[str]:
    """Extract symbol/import strings from an ELF file via pyelftools."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection

    names: list[str] = []
    try:
        with open(path, "rb") as handle:
            elffile = ELFFile(handle)
            for section in elffile.iter_sections():
                if isinstance(section, DynamicSection):
                    for tag in section.iter_tags():
                        if tag.entry.d_tag in ("DT_NEEDED", "DT_SONAME", "DT_RPATH", "DT_RUNPATH"):
                            value = tag.needed if hasattr(tag, "needed") else str(tag)
                            names.append(str(value))
            dynsym = elffile.get_section_by_name(".dynsym")
            if dynsym is not None:
                for symbol in dynsym.iter_symbols():
                    name = symbol.name
                    if name:
                        names.append(name)
            symtab = elffile.get_section_by_name(".symtab")
            if symtab is not None:
                for symbol in symtab.iter_symbols():
                    name = symbol.name
                    if name and len(names) < 20000:
                        names.append(name)
    except Exception as exc:  # noqa: BLE001 — fall back to raw strings
        logger.debug("pyelftools parse failed for %s: %s", path, exc)
        return []
    return names


def _raw_ascii_strings(data: bytes, min_len: int = 6, limit: int = 20000) -> list[str]:
    strings: list[str] = []
    current: bytearray = bytearray()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= min_len:
                try:
                    strings.append(current.decode("ascii"))
                except UnicodeDecodeError:
                    pass
                if len(strings) >= limit:
                    return strings
            current = bytearray()
    if len(current) >= min_len:
        strings.append(current.decode("ascii", errors="replace"))
    return strings


# ── Asset construction ────────────────────────────────────────────────────────

@dataclass
class BinaryScanResult:
    """Result of scanning a single binary file."""

    file_path: Path
    assets: list[CryptoAsset]
    binary_kind: Optional[str] = None
    parse_error: bool = False
    error_message: Optional[str] = None

    @property
    def asset_count(self) -> int:
        return len(self.assets)


@dataclass
class BinaryDirectoryScanResult:
    """Aggregate result of scanning paths for binary files."""

    root_path: Path
    binary_results: list[BinaryScanResult]
    files_scanned: int
    files_skipped: int

    @property
    def all_assets(self) -> list[CryptoAsset]:
        assets: list[CryptoAsset] = []
        for result in self.binary_results:
            assets.extend(result.assets)
        return assets

    @property
    def total_assets(self) -> int:
        return sum(r.asset_count for r in self.binary_results)


def _purpose_from_string(purpose_str: str) -> CryptoPurpose:
    try:
        return CryptoPurpose(purpose_str)
    except ValueError:
        return CryptoPurpose.UNKNOWN


def _make_binary_asset(
    file_path: Path,
    rule: FingerprintRule,
    matched_text: str,
    scan_id: Optional[str],
    relative_to: Optional[Path],
) -> CryptoAsset:
    display_path = (
        str(file_path.relative_to(relative_to))
        if relative_to and file_path.is_relative_to(relative_to)
        else str(file_path)
    )
    display_path = display_path.replace("\\", "/")
    location = SourceLocation(
        file_path=display_path,
        line_number=None,
        snippet=f"{rule.rule_id}: {matched_text[:120]}",
    )
    evidence = Evidence(
        detection_method=DetectionMethod.BINARY_FINGERPRINT,
        finding_type=FindingType.DETERMINISTIC,
        rule_id=rule.rule_id,
        location=location,
        source_surface="binary",
        confidence=rule.confidence,
    )
    return CryptoAsset(
        scan_id=scan_id,
        algorithm=rule.algorithm,
        purpose=_purpose_from_string(rule.purpose),
        location=display_path,
        source_surface="binary",
        classification=_STAGING_CLASSIFICATION,
        sensitivity=_STAGING_SENSITIVITY,
        business_criticality=BusinessCriticality.LOW,
        lifecycle_stage=LifecycleStage.ACTIVE,
        reachable=None,
        evidence=evidence,
        risk=None,
        recommendation=None,
    )


def scan_binary_file(
    file_path: Path,
    rules: Optional[list[FingerprintRule]] = None,
    scan_id: Optional[str] = None,
    relative_to: Optional[Path] = None,
) -> Optional[BinaryScanResult]:
    """Fingerprint a single binary file against config-driven rules.

    Returns None when the file is not a recognisable binary (not an error).
    """
    file_path = Path(file_path)
    kind = _classify_binary(file_path)
    if kind is None:
        return None
    loaded = rules if rules is not None else load_fingerprint_rules()

    candidates: list[str] = []
    if kind == "elf":
        candidates = _elf_strings(file_path)
    if not candidates:
        data = _read_bytes(file_path)
        if data is None:
            return BinaryScanResult(
                file_path=file_path, assets=[], binary_kind=kind,
                parse_error=True, error_message="Unreadable or oversized file",
            )
        candidates = _raw_ascii_strings(data)

    seen_rules: set[str] = set()
    assets: list[CryptoAsset] = []
    for text in candidates:
        text_bytes = text.encode("ascii", errors="ignore")
        for rule in loaded:
            if rule.rule_id in seen_rules:
                continue
            if rule.compiled.search(text_bytes):
                seen_rules.add(rule.rule_id)
                assets.append(_make_binary_asset(
                    file_path, rule, text, scan_id, relative_to,
                ))
    return BinaryScanResult(file_path=file_path, assets=assets, binary_kind=kind)


def scan_binary_paths(
    paths: list[Path],
    rules: Optional[list[FingerprintRule]] = None,
    scan_id: Optional[str] = None,
    exclude_dirs: Optional[set[str]] = None,
) -> BinaryDirectoryScanResult:
    """Scan explicit binary paths (files or directories) for fingerprints."""
    loaded = rules if rules is not None else load_fingerprint_rules()
    excluded = exclude_dirs or {".git", ".venv", "venv", "env", "node_modules", "__pycache__"}
    results: list[BinaryScanResult] = []
    skipped = 0
    for raw in paths:
        candidate = Path(raw)
        if not candidate.exists():
            skipped += 1
            continue
        targets: list[Path] = []
        if candidate.is_file():
            targets = [candidate]
        else:
            for item in sorted(candidate.rglob("*")):
                if any(part in excluded for part in item.parts):
                    continue
                if item.is_file():
                    targets.append(item)
        for target in targets:
            result = scan_binary_file(
                target, rules=loaded, scan_id=scan_id,
                relative_to=candidate if candidate.is_dir() else candidate.parent,
            )
            if result is None:
                skipped += 1
                continue
            results.append(result)
    return BinaryDirectoryScanResult(
        root_path=Path(paths[0]) if paths else Path("."),
        binary_results=results,
        files_scanned=len(results),
        files_skipped=skipped,
    )
