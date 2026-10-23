"""FastAPI app exposing the four endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .graph import NOW, build_sample_graph, Graph
from .patterns import detect_recurring_patterns
from .queries import (
    find_related,
    find_recurring_patterns,
    rank_by_decision_relevance,
)
from .scoring import compute_impact

_graph: Graph | None = None


def _g() -> Graph:
    global _graph
    if _graph is None:
        _graph = build_sample_graph()
    return _graph


def _now() -> datetime:
    """Reference time for the demo graph (aligned with sample-data snapshot)."""
    return NOW


app = FastAPI(title="Project Savitar", version="0.1.0")


class RelatedReq(BaseModel):
    entity_id: str
    hops: int = Field(3, ge=1, le=6)
    filters: dict[str, Any] = Field(default_factory=dict)


class PatternsReq(BaseModel):
    scope: dict[str, Any] = Field(default_factory=dict)
    window_days: float = Field(30.0, gt=0, le=365)


class RankReq(BaseModel):
    entity_ids: list[str] = Field(..., min_length=1, max_length=500)


@app.post("/v1/find_related")
def api_find_related(req: RelatedReq) -> dict:
    res = find_related(_g(), req.entity_id, hops=req.hops,
                       filters=req.filters, now=_now())
    return {"entity_id": req.entity_id, "count": len(res),
            "results": [r.to_dict() for r in res]}


@app.post("/v1/find_recurring_patterns")
def api_find_recurring_patterns(req: PatternsReq) -> dict:
    res = find_recurring_patterns(_g(), scope=req.scope,
                                  window_days=req.window_days, now=_now())
    return {"count": len(res), "patterns": res}


@app.post("/v1/rank_by_decision_relevance")
def api_rank(req: RankReq) -> dict:
    res = rank_by_decision_relevance(_g(), req.entity_ids, now=_now())
    return {"count": len(res), "ranking": res}


@app.get("/v1/executive_summary")
def api_executive_summary() -> dict:
    g = _g()
    patterns = detect_recurring_patterns(g, window_days=30.0, now=_now(), top_k=20)
    out = []
    for p in patterns:
        impacts = [compute_impact(g.node(dst))
                   for _, dst in p.example_pairs if g.node(dst)]
        headline = p.precision * (sum(impacts) / len(impacts) if impacts else 0.5)
        out.append({
            "motif": p.motif,
            "occurrences": p.occurrences,
            "precision": p.precision,
            "headline_score": round(headline, 4),
            "business_units": p.business_units,
            "example_pairs": [list(x) for x in p.example_pairs],
            "window_days": p.window_days,
        })
    out.sort(key=lambda x: (-x["headline_score"], x["motif"]))
    return {"generated_at": _now().isoformat(), "count": len(out),
            "patterns": out[:20]}


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "graph_nodes": len(_g())}
