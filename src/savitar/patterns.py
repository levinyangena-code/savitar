"""Recurring-pattern detector (precision over recall, cap 20)."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any

from .graph import Graph, Edge


@dataclass
class Pattern:
    motif: str
    occurrences: int
    precision: float
    example_pairs: list[tuple[str, str]]
    business_units: list[str]
    window_days: float

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["example_pairs"] = [list(p) for p in self.example_pairs]
        return d


def detect_recurring_patterns(
    graph: Graph,
    *,
    scope: dict[str, Any] | None = None,
    window_days: float = 30.0,
    now: datetime | None = None,
    min_occurrences: int = 2,
    top_k: int = 20,
) -> list[Pattern]:
    if top_k > 20:
        raise ValueError("precision-over-recall cap is 20")

    now = now or datetime.now(timezone.utc)
    scope = scope or {}
    cutoff = now.timestamp() - window_days * 86400

    def in_scope(nid: str) -> bool:
        n = graph.node(nid)
        if not n:
            return False
        for k, v in scope.items():
            if k == "business_unit" and n.business_unit != v:
                return False
            if k == "type" and n.type != v:
                return False
        return True

    motif_edges: dict[str, list[Edge]] = defaultdict(list)
    for edge in graph.edges():
        if edge.evidence.timestamp.timestamp() < cutoff:
            continue
        if not (in_scope(edge.src) or in_scope(edge.dst)):
            continue
        sn = graph.node(edge.src)
        dn = graph.node(edge.dst)
        if not sn or not dn:
            continue
        motif = f"{sn.type} -- {edge.relation} --> {dn.type}"
        motif_edges[motif].append(edge)

    patterns: list[Pattern] = []
    for motif, edges in motif_edges.items():
        if len(edges) < min_occurrences:
            continue

        # Motif string is "srcType -- relation --> dstType"; trust the edges
        # themselves for the endpoint types rather than re-parsing the string.
        src_type = graph.node(edges[0].src).type
        dst_type = graph.node(edges[0].dst).type

        src_nodes = [n for n in graph.nodes()
                     if n.type == src_type and in_scope(n.id)]
        dst_nodes = [n for n in graph.nodes()
                     if n.type == dst_type and in_scope(n.id)]
        possible = max(1, len(src_nodes) * len(dst_nodes))
        precision = min(1.0, len(edges) / possible)
        examples = [(e.src, e.dst) for e in edges[:5]]
        if scope:
            bus = sorted({
                graph.node(end).business_unit
                for e in edges
                for end in (e.src, e.dst)
                if in_scope(end)
            })
        else:
            bus = sorted({
                graph.node(e.src).business_unit
                for e in edges
                if graph.node(e.src)
            })
        patterns.append(Pattern(
            motif=motif,
            occurrences=len(edges),
            precision=round(precision, 4),
            example_pairs=examples,
            business_units=bus,
            window_days=window_days,
        ))

    patterns.sort(key=lambda p: (-p.precision, -p.occurrences, p.motif))
    return patterns[:top_k]
