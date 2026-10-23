from __future__ import annotations

from savitar.integration.sensors import (
    extract_entities_from_pdf,
    join_sensor_events,
    synthetic_sensor_events,
)


def test_pdf_entities_link_to_resolved_assets():
    resolved = [
        {"id": "resolved:payments-web-01", "canonical_name": "payments-web-01"},
        {"id": "resolved:hr-app-01", "canonical_name": "hr-app-01"},
        {"id": "resolved:ot-plc-01", "canonical_name": "ot-plc-01"},
    ]
    facts = extract_entities_from_pdf("payments-web-01 hr-app-01 ot-plc-01", resolved)
    assert len(facts) >= 3
    assert all(f.entity_id for f in facts)


def test_sensor_events_join_to_asset():
    resolved = [{"id": "resolved:payments-web-01", "canonical_name": "payments-web-01", "attributes": {"ip": "10.0.0.12"}}]
    matched = join_sensor_events(synthetic_sensor_events(), resolved)
    assert matched["matched"]
    assert matched["unmatched"]
