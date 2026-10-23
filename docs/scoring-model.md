# Savitar Scoring Model — `savitar-score-v1`

Every relationship returned by Savitar carries three normalized factors in
`[0, 1]` and a final score that is their product:

```
final = confidence × recency × impact
```

Tiebreaks use `entity_id` (ascending) so the ranking is deterministic.

## 1. Confidence

```
depth_factor      = 0.9 ^ depth
unique_sources    = |{e.source for e in evidences}|
diversity         = min(1.0, unique_sources / 3)
hint              = mean(e.confidence_hint for e in evidences)   # or 0.5 if none
confidence        = depth_factor × (0.6 + 0.4 × diversity) × (0.7 + 0.3 × hint)
```

- **Depth decay** (0.9/hop) — indirect relationships are weaker but still useful.
- **Source diversity** — two independent sensors are more trustworthy; capped at 3.
- **Source-reported hint** — lets upstream systems express confidence.

## 2. Recency

```
recency = 0.5 ^ (age_hours / half_life_hours)
```

## 3. Impact

Per node type — see `scoring.py::compute_impact`.

## 4. Lineage

Every returned relationship carries:

```json
"evidence": [{
  "source": "edr:win10-42",
  "timestamp": "2026-10-23T10:14:00Z",
  "rule_version": "rule-v1",
  "model_version": "savitar-score-v1",
  "confidence_hint": 0.92
}]
```

Bump `SCORING_MODEL_VERSION` in `evidence.py` whenever any formula changes.

## 5. Properties

- **Bounded** — final ∈ [0, 1].
- **Deterministic** — same inputs ⇒ same ranking.
- **Explainable** — every factor is named; every edge has evidence.
- **Defensive** — no exploit code, purely analytic.
