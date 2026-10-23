from savitar.queries import (
    find_related,
    find_recurring_patterns,
    rank_by_decision_relevance,
)


def test_find_related_returns_scored_results(graph, now):
    res = find_related(graph, "ioc:sha256:deadbeef", hops=3, now=now)
    assert len(res) > 0
    assert res[0].entity_id == "asset:web-prod-01"
    assert res[0].depth == 1
    for r in res:
        assert r.evidence, f"missing evidence on {r.entity_id}"
        for ev in r.evidence:
            assert {"source", "timestamp", "rule_version", "model_version"} <= set(ev)


def test_find_related_filters_by_type(graph, now):
    res = find_related(graph, "ioc:sha256:deadbeef", hops=3,
                       filters={"type": "vulnerability"}, now=now)
    assert all(r.entity_type == "vulnerability" for r in res)


def test_find_related_empty_for_unknown(graph, now):
    assert find_related(graph, "does-not-exist", now=now) == []


def test_find_recurring_patterns_capped_at_20(graph, now):
    pats = find_recurring_patterns(graph, window_days=60, now=now)
    assert len(pats) <= 20
    for p in pats:
        assert {"motif", "occurrences", "precision", "example_pairs", "business_units"} <= set(p)


def test_find_recurring_patterns_scope(graph, now):
    pats = find_recurring_patterns(graph, scope={"business_unit": "payments"},
                                   window_days=60, now=now)
    for p in pats:
        assert "payments" in p["business_units"]


def test_rank_deterministic(graph, now):
    ids = ["asset:web-prod-01", "vuln:CVE-2026-1001", "id:svc-payments",
           "actor:TEMP-REVE", "inc:2026-09-12"]
    a = rank_by_decision_relevance(graph, ids, now=now)
    b = rank_by_decision_relevance(graph, ids, now=now)
    assert [x["entity_id"] for x in a] == [x["entity_id"] for x in b]
    for x, y in zip(a, b):
        assert x["final"] == y["final"]
