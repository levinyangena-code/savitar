"""The three core API operations."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any

from ._determinism import stable_rank_key
from .evidence import Evidence, DEFAULT_RULE_VERSION, SCORING_MODEL_VERSION
from .graph import Graph, Node
from .patterns import detect_recurring_patterns
from .scoring import score_relationship


@dataclass
class RelatedEntity:
    entity_id: str
    entity_type: str
    depth: int
    confidence: float
    recency: float
    impact: float
    final: float
    factors: dict[str, Any]
    evidence: list[dict[str, Any]] = field(default_factory=list)
    path: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _matches_filters(node: Node, filters: dict[str, Any]) -> bool:
    for k, v in filters.items():
        if k == "type" and node.type != v:
            return False
        if k == "business_unit" and node.business_unit != v:
            return False
        if k == "exposed" and node.exposed != bool(v):
            return False
        if k == "in_kev" and node.in_kev != bool(v):
            return False
    return True


def find_related(
    graph: Graph,
    entity_id: str,
    *,
    hops: int = 3,
    filters: dict[str, Any] | None = None,
    now: datetime | None = None,
    max_results: int = 100,
) -> list[RelatedEntity]:
    filters = filters or {}
    now = now or datetime.now(timezone.utc)
    if graph.node(entity_id) is None:
        return []

    best_depth: dict[str, int] = {entity_id: 0}
    evidence_map: dict[str, list[Evidence]] = defaultdict(list)
    path_map: dict[str, list[str]] = {entity_id: [entity_id]}
    frontier = [entity_id]

    for depth in range(1, hops + 1):
        next_frontier: list[str] = []
        for nid in frontier:
            for edge, neighbor, _ in graph.neighbors(nid):
                evidence_map[neighbor.id].append(edge.evidence)
                if neighbor.id not in best_depth:
                    best_depth[neighbor.id] = depth
                    path_map[neighbor.id] = path_map[nid] + [neighbor.id]
                    next_frontier.append(neighbor.id)
        frontier = next_frontier
        if not frontier:
            break

    results: list[RelatedEntity] = []
    for nid, depth in best_depth.items():
        if nid == entity_id:
            continue
        node = graph.node(nid)
        if not node or not _matches_filters(node, filters):
            continue
        sb = score_relationship(node, depth, evidence_map[nid], now)
        results.append(RelatedEntity(
            entity_id=nid,
            entity_type=node.type,
            depth=depth,
            confidence=sb.confidence,
            recency=sb.recency,
            impact=sb.impact,
            final=sb.final,
            factors=sb.factors,
            evidence=[e.to_dict() for e in evidence_map[nid]],
            path=path_map.get(nid, []),
        ))

    results.sort(key=lambda r: stable_rank_key(
        {"final": r.final, "entity_id": r.entity_id}))
    return results[:max_results]


def find_recurring_patterns(
    graph: Graph,
    *,
    scope: dict[str, Any] | None = None,
    window_days: float = 30.0,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    patterns = detect_recurring_patterns(
        graph, scope=scope, window_days=window_days, now=now)
    return [p.to_dict() for p in patterns]


def _incident_evidence(graph: Graph, nid: str):
    for edge, neighbor, d in graph.neighbors(nid):
        if neighbor.type == "incident":
            yield edge, neighbor, d


def rank_by_decision_relevance(
    graph: Graph,
    entity_ids: list[str],
    *,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    now = now or datetime.now(timezone.utc)
    out: list[dict[str, Any]] = []
    for nid in entity_ids:
        node = graph.node(nid)
        if not node:
            continue
        evidences = [e.evidence for _, _, _ in _incident_evidence(graph, nid)]
        if not evidences:
            evidences = [Evidence(
                source="self",
                timestamp=now,
                rule_version=DEFAULT_RULE_VERSION,
                model_version=SCORING_MODEL_VERSION,
                confidence_hint=0.5,
            )]
        sb = score_relationship(node, 0, evidences, now)
        out.append({
            "entity_id": nid,
            "entity_type": node.type,
            "confidence": sb.confidence,
            "recency": sb.recency,
            "impact": sb.impact,
            "final": sb.final,
            "factors": sb.factors,
            "evidence": [e.to_dict() for e in evidences],
        })
    out.sort(key=stable_rank_key)
    return out
