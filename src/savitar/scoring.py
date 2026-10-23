"""Confidence × Recency × Impact scoring model."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from .evidence import Evidence
from .graph import Node


@dataclass(frozen=True)
class ScoreBreakdown:
    confidence: float
    recency: float
    impact: float
    final: float
    factors: dict[str, Any]


def compute_confidence(depth: int, evidences: Iterable[Evidence]) -> float:
    evs = list(evidences)
    depth_factor = 0.9 ** max(0, depth)
    unique_sources = len({e.source for e in evs}) if evs else 0
    diversity = min(1.0, unique_sources / 3.0)
    hint = (sum(e.confidence_hint for e in evs) / len(evs)) if evs else 0.5
    base = depth_factor * (0.6 + 0.4 * diversity)
    return max(0.0, min(1.0, base * (0.7 + 0.3 * hint)))


HALF_LIVES_HOURS = {
    "vulnerability": 168.0,
    "ioc":           24.0,
    "incident":      720.0,
    "actor":         720.0,
    "asset":         2160.0,
    "identity":      2160.0,
}


def compute_recency(timestamp: datetime, now: datetime, node_type: str) -> float:
    half_life = HALF_LIVES_HOURS.get(node_type, 168.0)
    age_hours = max(0.0, (now - timestamp).total_seconds() / 3600.0)
    return 0.5 ** (age_hours / half_life)


def compute_impact(node: Node) -> float:
    t = node.type
    if t == "vulnerability":
        base = node.cvss / 10.0
        kev_boost = 1.5 if node.in_kev else 1.0
        return min(1.0, base * kev_boost)
    if t == "asset":
        return {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}.get(
            node.criticality, 0.5)
    if t == "identity":
        mfa_penalty = 1.0 if node.mfa else 0.85
        return min(1.0, node.privilege_score * mfa_penalty)
    if t == "actor":
        return min(1.0, node.threat_level / 10.0)
    if t == "incident":
        sev = node.attrs.get("severity", "medium")
        return {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.25}.get(sev, 0.5)
    if t == "ioc":
        return 0.7
    return 0.5


def score_relationship(
    node: Node,
    depth: int,
    evidences: Iterable[Evidence],
    now: datetime,
) -> ScoreBreakdown:
    evs = list(evidences)           # materialize once — both callers reuse it
    c = compute_confidence(depth, evs)
    ts = max((e.timestamp for e in evs), default=now)
    r = compute_recency(ts, now, node.type)
    i = compute_impact(node)
    return ScoreBreakdown(
        confidence=round(c, 4),
        recency=round(r, 4),
        impact=round(i, 4),
        final=round(c * r * i, 6),
        factors={
            "depth": depth,
            "evidence_count": len(evs),
            "node_type": node.type,
            "half_life_hours": HALF_LIVES_HOURS.get(node.type),
        },
    )
