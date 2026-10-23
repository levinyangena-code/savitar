from savitar.patterns import detect_recurring_patterns


def test_pattern_cap_enforced(graph, now):
    pats = detect_recurring_patterns(graph, window_days=365, now=now, top_k=20)
    assert len(pats) <= 20


def test_pattern_precision_bounded(graph, now):
    pats = detect_recurring_patterns(graph, window_days=365, now=now)
    for p in pats:
        assert 0.0 <= p.precision <= 1.0


def test_pattern_occurrences_respect_window(graph, now):
    wide = detect_recurring_patterns(graph, window_days=365, now=now)
    narrow = detect_recurring_patterns(graph, window_days=1, now=now)
    wide_map = {p.motif: p.occurrences for p in wide}
    for p in narrow:
        assert p.occurrences <= wide_map.get(p.motif, 0) + 1e-9
