from savitar.queries import find_related, rank_by_decision_relevance


def test_find_related_deterministic(graph, now):
    a = find_related(graph, "ioc:sha256:deadbeef", hops=3, now=now)
    b = find_related(graph, "ioc:sha256:deadbeef", hops=3, now=now)
    assert [r.entity_id for r in a] == [r.entity_id for r in b]
    for x, y in zip(a, b):
        assert x.final == y.final


def test_rank_deterministic_under_permutation(graph, now):
    ids = ["asset:web-prod-01", "vuln:CVE-2026-1001", "id:svc-payments",
           "actor:TEMP-REVE", "inc:2026-09-12"]
    r1 = rank_by_decision_relevance(graph, ids, now=now)
    r2 = rank_by_decision_relevance(graph, list(reversed(ids)), now=now)
    assert [x["entity_id"] for x in r1] == [x["entity_id"] for x in r2]
