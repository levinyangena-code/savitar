from fastapi.testclient import TestClient

from savitar.api import app
import savitar.api as api_mod
from savitar.graph import build_sample_graph


def test_e2e_ioc_to_ranked_list(monkeypatch):
    g = build_sample_graph(seed=42)
    monkeypatch.setattr(api_mod, "_graph", g)
    client = TestClient(app)

    r1 = client.post("/v1/find_related",
                     json={"entity_id": "ioc:sha256:deadbeef", "hops": 3})
    assert r1.status_code == 200
    body = r1.json()
    assert body["count"] >= 1
    ids = [x["entity_id"] for x in body["results"]]

    r2 = client.post("/v1/rank_by_decision_relevance",
                     json={"entity_ids": ids})
    assert r2.status_code == 200
    ranking = r2.json()["ranking"]
    assert len(ranking) == len(ids)
    finals = [x["final"] for x in ranking]
    assert finals == sorted(finals, reverse=True)
    for x in ranking:
        assert x["evidence"]


def test_executive_summary_endpoint(monkeypatch):
    g = build_sample_graph(seed=42)
    monkeypatch.setattr(api_mod, "_graph", g)
    client = TestClient(app)

    r = client.get("/v1/executive_summary")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] <= 20
    for p in body["patterns"]:
        assert "business_units" in p and p["business_units"]
        assert "headline_score" in p
