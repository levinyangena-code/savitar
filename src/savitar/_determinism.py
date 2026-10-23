"""Stable-sort helpers. Tiebreak on entity_id so ranking is deterministic."""

from typing import Any


def stable_rank_key(item: dict[str, Any]) -> tuple[float, str]:
    return (-float(item.get("final", 0.0)), str(item.get("entity_id", "")))
