"""Project Doom integration layer for entity resolution and shared picture views."""

from .entity_resolution import (
    EntityResolutionResult,
    ResolvedEntity,
    SourceRecord,
    build_sample_staging_store,
    field_confidence,
    merge_confidence,
    extraction_confidence,
    manual_review_queue,
    resolve_entities,
    resolved_entity,
    shared_picture,
)

__all__ = [
    "EntityResolutionResult",
    "ResolvedEntity",
    "SourceRecord",
    "build_sample_staging_store",
    "field_confidence",
    "merge_confidence",
    "extraction_confidence",
    "manual_review_queue",
    "resolve_entities",
    "resolved_entity",
    "shared_picture",
]
