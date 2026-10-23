# Project Savitar — Cross-Source Pattern & Relationship Discovery

## What was built

A defensive pattern-discovery and relationship-analytics layer that sits on
top of the asset / identity / vulnerability / threat-actor / telemetry graph
and exposes:

- `POST /v1/find_related` — BFS up to N hops with filters; every result
  carries confidence, recency, impact, final score, evidence lineage, and
  the traversed path.
- `POST /v1/find_recurring_patterns` — precision-over-recall motif detector,
  hard-capped at 20 patterns.
- `POST /v1/rank_by_decision_relevance` — deterministic ranking of a
  supplied entity list with explainable factors.
- `GET  /v1/executive_summary` — top-20 patterns with business-unit
  attribution and a headline score for leadership.

Plus five documented Cypher queries in `docs/pattern-discovery-queries.md`
and the scoring model in `docs/scoring-model.md`.

## Acceptance criteria — all met

- [x] Three API operations implemented and unit-tested.
- [x] `find_related` is O(V+E) BFS; returns well under 2 s on 10k/50k.
- [x] Five example Cypher queries with sample output.
- [x] Every returned relationship carries `evidence[]` with
      `source`, `timestamp`, `rule_version`, `model_version`.
- [x] Recurring-pattern detector returns ≤ 20 patterns.
- [x] End-to-end integration test: IOC → related → ranked list.
- [x] Determinism tests: identical inputs ⇒ identical ranking.
- [x] Executive summary endpoint returns ≤ 20 patterns with BU attribution.

## How to run

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```

To run the API locally:

```bash
uvicorn savitar.api:app --reload
curl http://localhost:8000/healthz
```

## Sample query output (`find_related` from IOC)

```
asset:web-prod-01   depth=1  conf=0.9310 rec=0.9983 imp=1.0000 final=0.9279
vuln:CVE-2026-1001  depth=2  conf=0.7634 rec=0.9198 imp=1.0000 final=0.7021
id:svc-payments     depth=2  conf=0.6888 rec=0.9997 imp=0.7650 final=0.5262
actor:TEMP-REVE     depth=3  conf=0.5905 rec=0.8609 imp=0.8500 final=0.4323
```

## Open questions for human review

1. **Half-life tuning** — configurable per deployment or locked for audit stability?
2. **Graph backend** — Neo4j (mature Cypher) or Kuzu (embedded, fast)?
3. **Pattern precision denominator** — temporal denominator in v2?
4. **Executive headline score** — weight by BU criticality or incident history?
5. **Rate limiting / auth** — not yet wired; flag before production.

Leaving for human review — not merging.
