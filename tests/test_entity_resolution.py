from __future__ import annotations

from savitar.integration.entity_resolution import build_sample_staging_store, resolve_entities


def test_same_name_distinct_assets_do_not_merge():
    records = build_sample_staging_store()
    result = resolve_entities(records)
    assert result.blocked
    assert any(item["reason"].startswith("hard conflict") for item in result.blocked)


def test_conflict_resolution_keeps_unmerged_values():
    records = build_sample_staging_store()
    result = resolve_entities(records)
    assert result.resolved
    assert all("merge_history" in entity.to_dict() for entity in result.resolved)


def test_shared_picture_returns_lineage_and_audit_ids():
    from savitar.integration.entity_resolution import shared_picture

    body = shared_picture("resolved:payments-web-01")
    assert body["lineage_record_id"]
    assert body["audit_event_id"]
    assert len(body["source_types"]) >= 4
