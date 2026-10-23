# Project Savitar

Defensive pattern-discovery and relationship-analytics layer for the
Exposure-to-Exploit Decision Graph.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
```

## Run tests

```bash
pytest -q
```

## Run API

```bash
uvicorn savitar.api:app --reload
curl http://localhost:8000/healthz
```

## Docs

- `docs/scoring-model.md` — confidence × recency × impact formulas.
- `docs/pattern-discovery-queries.md` — five example Cypher queries.
