"""
Relationship engine — Phase 7 (CBOM relationships, Phase 6 correlation).

Derives evidence-backed relationships BETWEEN assets already in the
inventory. Never invents: every relationship cites the evidence that
supports it (shared certificate serial, shared file+statement siblings,
shared algorithm family across surfaces).

Relationship kinds:
  cert_uses_key      certificate asset → its public-key sibling asset
                     (same file: C-001 key asset + C-002 hash asset share
                     the certificate's serial/subject)
  cert_signed_with   certificate asset → signature-hash sibling asset
  source_invokes     source asset → sibling algorithm observed in the
                     same statement (sibling_symbols from the AST match)
  cross_surface      same algorithm family on two surfaces
                     (source usage ↔ certificate observation)

Each relationship: {from_id, to_id, kind, evidence}.
The CBOM exporter renders these as CycloneDX dependencies.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from ecdat.engines.inventory import _normalize_family
from ecdat.schemas import CryptoAsset

logger = logging.getLogger(__name__)

# Cap: relationships are evidence links, not a full mesh. Per-asset
# fan-out is bounded so a 30k-asset scan cannot produce millions of edges.
_MAX_EDGES_PER_ASSET = 8


def build_relationships(assets: list[CryptoAsset]) -> list[dict]:
    """Build evidence-backed relationships between inventoried assets."""
    relationships: list[dict] = []
    fan_out: dict[str, int] = defaultdict(int)

    def _link(from_id: str, to_id: str, kind: str, evidence: str) -> None:
        if from_id == to_id:
            return
        if fan_out[from_id] >= _MAX_EDGES_PER_ASSET:
            return
        relationships.append({
            "from_id": from_id,
            "to_id": to_id,
            "kind": kind,
            "evidence": evidence[:300],
        })
        fan_out[from_id] += 1

    by_id = {a.asset_id: a for a in assets}

    # ── Certificate-internal links (shared serial ⇒ same certificate) ──────
    # Direction follows the evidence: the certificate record (subject-bearing
    # asset) uses its key (cert_uses_key) and was signed with its hash
    # (cert_signed_with). With 2 assets per cert (key + hash), that yields
    # exactly 2 directed edges; the seen_pairs guard prevents A→B + B→A
    # duplicates when groups are larger.
    by_serial: dict[str, list[CryptoAsset]] = defaultdict(list)
    for asset in assets:
        if asset.source_surface == "certificate" and asset.certificate_serial:
            by_serial[asset.certificate_serial].append(asset)
    for serial, group in by_serial.items():
        keys = [a for a in group if a.purpose.value != "hashing"]
        hashes = [a for a in group if a.purpose.value == "hashing"]
        seen_pairs: set[tuple[str, str]] = set()
        # cert_uses_key: hash record → key record (the certificate uses
        # the key). cert_signed_with: key record → hash record (the key
        # material was certified with this hash). Fixed directions keep
        # the pair unique without depending on iteration order.
        for key in keys:
            for hs in hashes:
                pair = (hs.asset_id, key.asset_id)
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    _link(hs.asset_id, key.asset_id, "cert_uses_key",
                          f"shared certificate serial {serial}")
                pair = (key.asset_id, hs.asset_id)
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    _link(key.asset_id, hs.asset_id, "cert_signed_with",
                          f"shared certificate serial {serial}")

    # ── Source-statement links (sibling symbols observed together) ──────────
    # Tightened (Task 2): a source_invokes edge requires the sibling symbol
    # to be the OBSERVED callee of the holder's own match — i.e. the holder
    # asset's match statement actually invokes that crypto symbol — not
    # merely co-occurring identifiers in a noisy statement. Concretely:
    #   1. the sibling symbol must itself be an observed crypto symbol in
    #      this scan (same guard as before), AND
    #   2. the holder's own observed_symbol must differ from it (no
    #      self-links through shared allocator/macro names), AND
    #   3. the sibling must appear in the holder's snippet text — the
    #      statement actually contains the invocation, not just a nearby
    #      declaration in the same collected scope.
    # This keeps genuine EVP fetch→init pairs (EVP_aes_256_gcm beside
    # EVP_EncryptInit_ex) while dropping allocator/macro fan-out.
    crypto_symbols: set[str] = set()
    for asset in assets:
        if asset.evidence.observed_symbol:
            crypto_symbols.add(asset.evidence.observed_symbol)
    by_symbol: dict[str, list[CryptoAsset]] = defaultdict(list)
    for asset in assets:
        if asset.source_surface == "source_code":
            snippet = (asset.evidence.location.snippet or "")
            own = asset.evidence.observed_symbol
            for sym in asset.evidence.sibling_symbols or ():
                if sym not in crypto_symbols:
                    continue
                if own is not None and sym == own:
                    continue
                if sym not in snippet:
                    continue
                by_symbol[sym].append(asset)
    observed: dict[str, list[CryptoAsset]] = defaultdict(list)
    for asset in assets:
        if asset.evidence.observed_symbol:
            observed[asset.evidence.observed_symbol].append(asset)
    for sym, holders in by_symbol.items():
        for target in observed.get(sym, []):
            for holder in holders:
                if holder.asset_id != target.asset_id:
                    _link(holder.asset_id, target.asset_id, "source_invokes",
                          f"sibling symbol '{sym}' in same statement")

    # ── Cross-surface links (same family, different surfaces) ───────────────
    by_family: dict[str, list[CryptoAsset]] = defaultdict(list)
    for asset in assets:
        by_family[_normalize_family(asset.algorithm)].append(asset)
    for family, group in by_family.items():
        surfaces = {a.source_surface for a in group}
        if len(surfaces) < 2:
            continue
        reps: dict[str, CryptoAsset] = {}
        for asset in group:
            reps.setdefault(asset.source_surface, asset)
        surfaces_sorted = sorted(reps)
        for i, surface in enumerate(surfaces_sorted):
            for other in surfaces_sorted[i + 1:]:
                _link(reps[surface].asset_id, reps[other].asset_id,
                      "cross_surface",
                      f"shared algorithm family {family} across "
                      f"{surface} ↔ {other}")

    logger.info(
        "Relationships built: %d edges across %d assets",
        len(relationships), len(by_id),
    )
    return relationships
