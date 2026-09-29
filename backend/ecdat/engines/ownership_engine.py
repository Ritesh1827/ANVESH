"""User-configurable ownership mapping — `owner` stops being a null field.

OwnershipRule records live in the database and are managed through the API
(Settings page). The engine applies them after Classification and before
Reachability so every downstream stage (Mosca weights, roadmaps, CBOM)
sees the real owner. Rules are evaluated in priority order; first match
wins. Matching reuses the same criteria vocabulary as classification
(surface / purpose / algorithm prefix / path substring) so there is no
parallel ad-hoc heuristic.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from ecdat.schemas import CryptoAsset

logger = logging.getLogger(__name__)


def _ownership_session():
    """Import database lazily to avoid a pipeline ↔ persistence import cycle."""
    from ecdat.persistence import database
    return database.session()


@dataclass(frozen=True)
class OwnershipRule:
    """One evaluated ownership rule (DB row materialised)."""

    owner: str
    priority: int
    surface: Optional[str] = None
    purpose: Optional[str] = None
    algorithm_prefix: Optional[str] = None
    path_contains: Optional[str] = None


def load_ownership_rules() -> list[OwnershipRule]:
    """Load all ownership rules ordered by priority descending.

    Returns [] when the table does not exist yet (fresh database before
    the first API initialisation) — ownership is then simply unassigned.
    """
    from sqlalchemy.exc import OperationalError

    from ecdat.persistence.models import OwnershipRuleRecord

    try:
        with _ownership_session() as session:
            rows = (
                session.query(OwnershipRuleRecord)
                .order_by(
                    OwnershipRuleRecord.priority.desc(),
                    OwnershipRuleRecord.id.asc(),
                )
                .all()
            )
    except OperationalError:
        return []
    return [
        OwnershipRule(
            owner=row.owner,
            priority=row.priority,
            surface=row.surface,
            purpose=row.purpose,
            algorithm_prefix=row.algorithm_prefix,
            path_contains=row.path_contains,
        )
        for row in rows
    ]


def _matches(rule: OwnershipRule, asset: CryptoAsset) -> bool:
    if rule.surface is not None and asset.source_surface != rule.surface:
        return False
    if rule.purpose is not None and asset.purpose.value != rule.purpose:
        return False
    if rule.algorithm_prefix is not None and not asset.algorithm.upper().startswith(
        rule.algorithm_prefix.upper()
    ):
        return False
    if rule.path_contains is not None and rule.path_contains.lower() not in (
        asset.evidence.location.file_path or ""
    ).lower():
        return False
    return True


def resolve_owner(asset: CryptoAsset, rules: list[OwnershipRule]) -> Optional[str]:
    """Return the first matching rule's owner, or None when nothing matches."""
    for rule in rules:
        if _matches(rule, asset):
            return rule.owner
    return None


def apply_ownership(
    assets: list[CryptoAsset],
    rules: Optional[list[OwnershipRule]] = None,
) -> list[CryptoAsset]:
    """Annotate assets with owner from user-configured rules.

    Assets that already carry an owner (e.g. from a future enrichment stage)
    keep it; rules only fill blanks. Original assets are NOT mutated.
    """
    loaded = rules if rules is not None else load_ownership_rules()
    if not loaded:
        return list(assets)
    result: list[CryptoAsset] = []
    assigned = 0
    for asset in assets:
        if asset.owner:
            result.append(asset)
            continue
        owner = resolve_owner(asset, loaded)
        if owner is None:
            result.append(asset)
            continue
        assigned += 1
        result.append(asset.model_copy(update={"owner": owner}))
    logger.info("Ownership applied: %d/%d assets assigned an owner", assigned, len(assets))
    return result
