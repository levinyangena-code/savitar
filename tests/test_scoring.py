from datetime import datetime, timedelta, timezone

from savitar.scoring import (
    compute_confidence,
    compute_recency,
    compute_impact,
    score_relationship,
)
from savitar.evidence import Evidence, DEFAULT_RULE_VERSION, SCORING_MODEL_VERSION
from savitar.graph import Node


def _ev(source, days_ago):
    return Evidence(
        source=source,
        timestamp=datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
        - timedelta(days=days_ago),
        rule_version=DEFAULT_RULE_VERSION,
        model_version=SCORING_MODEL_VERSION,
        confidence_hint=0.9,
    )


def test_confidence_decays_with_depth():
    evs = [_ev("s1", 0)]
    assert compute_confidence(0, evs) > compute_confidence(1, evs) > compute_confidence(3, evs)


def test_confidence_rewards_diverse_sources():
    evs1 = [_ev("s1", 0)]
    evs3 = [_ev("s1", 0), _ev("s2", 0), _ev("s3", 0)]
    assert compute_confidence(1, evs3) > compute_confidence(1, evs1)


def test_recency_half_life():
    now = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
    r0 = compute_recency(now, now, "vulnerability")
    r1w = compute_recency(now - timedelta(hours=168), now, "vulnerability")
    assert abs(r0 - 1.0) < 1e-6
    assert abs(r1w - 0.5) < 1e-6


def test_impact_kev_boost():
    v_kev = Node("v1", "vulnerability", {"cvss": 8.0, "in_kev": True})
    v_no = Node("v2", "vulnerability", {"cvss": 8.0, "in_kev": False})
    assert compute_impact(v_kev) > compute_impact(v_no)


def test_impact_mfa_penalty():
    a = Node("i1", "identity", {"privilege_score": 0.9, "mfa": True})
    b = Node("i2", "identity", {"privilege_score": 0.9, "mfa": False})
    assert compute_impact(a) > compute_impact(b)


def test_score_relationship_bounded():
    n = Node("v", "vulnerability", {"cvss": 9.0, "in_kev": True})
    sb = score_relationship(
        n, 2, [_ev("s1", 1)],
        datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc),
    )
    assert 0.0 <= sb.final <= 1.0
    assert sb.confidence > 0 and sb.recency > 0 and sb.impact > 0
