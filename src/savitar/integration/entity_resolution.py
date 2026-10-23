from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from savitar.governance import append_audit_event, emit_lineage_record


@dataclass(frozen=True)
class SourceRecord:
    id: str
    source_type: str
    entity_type: str
    canonical_name: str
    attributes: dict[str, Any]
    timestamp: datetime
    source_reliability: float = 0.8
    extraction_confidence: float = 0.8
    hash: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "hash", snapshot_hash({
            "id": self.id,
            "source_type": self.source_type,
            "entity_type": self.entity_type,
            "canonical_name": self.canonical_name,
            "attributes": self.attributes,
            "timestamp": self.timestamp.isoformat(),
            "source_reliability": self.source_reliability,
            "extraction_confidence": self.extraction_confidence,
        }))


@dataclass
class ResolvedEntity:
    id: str
    type: str
    canonical_name: str
    source_refs: list[str]
    confidence: float
    merge_history: list[dict[str, Any]] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "canonical_name": self.canonical_name,
            "source_refs": list(self.source_refs),
            "confidence": self.confidence,
            "merge_history": list(self.merge_history),
            "attributes": dict(self.attributes),
        }


@dataclass
class EntityResolutionResult:
    resolved: list[ResolvedEntity]
    blocked: list[dict[str, Any]]
    manual_review: list[dict[str, Any]]


def snapshot_hash(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def merge_confidence(source_reliability: float, match_confidence: float, recency: float) -> float:
    return max(0.0, min(1.0, float(source_reliability) * float(match_confidence) * float(recency)))


def extraction_confidence(source_reliability: float, extraction_confidence: float, recency: float) -> float:
    return max(0.0, min(1.0, float(source_reliability) * float(extraction_confidence) * float(recency)))


def field_confidence(source_reliability: float, field_confidence: float, recency: float) -> float:
    return max(0.0, min(1.0, float(source_reliability) * float(field_confidence) * float(recency)))


def _normalized_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())


def _same_entity(a: SourceRecord, b: SourceRecord) -> bool:
    if a.entity_type != b.entity_type:
        return False
    if a.id == b.id or a.canonical_name == b.canonical_name:
        return True
    a_norm = _normalized_name(a.canonical_name)
    b_norm = _normalized_name(b.canonical_name)
    if a_norm and a_norm == b_norm:
        return True
    return False


def _hard_conflict(a: SourceRecord, b: SourceRecord) -> bool:
    for key in ("serial_number", "asset_id", "employee_id", "device_id"):
        va = a.attributes.get(key)
        vb = b.attributes.get(key)
        if va and vb and va != vb:
            return True
    return False


def _recency_score(ts: datetime) -> float:
    now = datetime.now(timezone.utc)
    age_hours = max(0.0, (now - ts).total_seconds() / 3600.0)
    return max(0.0, min(1.0, 1.0 / (1.0 + age_hours / 24.0)))


def _pairwise_match_score(a: SourceRecord, b: SourceRecord) -> float:
    if a.entity_type != b.entity_type:
        return 0.0
    same_name = _normalized_name(a.canonical_name) == _normalized_name(b.canonical_name)
    if same_name:
        base = 0.9
    else:
        base = 0.55
    recency = min(_recency_score(a.timestamp), _recency_score(b.timestamp))
    return max(0.0, min(1.0, base * recency))


def resolved_entity(
    id: str,
    type: str,
    canonical_name: str,
    source_refs: list[str] | None = None,
    confidence: float = 0.0,
    merge_history: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "id": id,
        "type": type,
        "canonical_name": canonical_name,
        "source_refs": list(source_refs or []),
        "confidence": float(confidence),
        "merge_history": list(merge_history or []),
    }


def manual_review_queue(records: list[SourceRecord] | None = None) -> list[dict[str, Any]]:
    records = records or []
    queue: list[dict[str, Any]] = []
    for rec in records:
        queue.append({
            "record_id": rec.id,
            "source_type": rec.source_type,
            "entity_type": rec.entity_type,
            "canonical_name": rec.canonical_name,
            "reason": "low-confidence match requires manual review",
            "confidence": min(1.0, rec.source_reliability * rec.extraction_confidence),
        })
    return queue


def resolve_entities(records: list[SourceRecord]) -> EntityResolutionResult:
    """Merge source snapshots into canonical entities, blocking hard conflicts and holding low-confidence links for review."""
    clusters: list[list[SourceRecord]] = []
    matched: set[str] = set()

    for record in records:
        if record.id in matched:
            continue
        cluster = [record]
        matched.add(record.id)
        for other in records:
            if other.id in matched or other.id == record.id:
                continue
            if _hard_conflict(record, other):
                continue
            if _same_entity(record, other):
                score = _pairwise_match_score(record, other)
                if score >= 0.82:
                    cluster.append(other)
                    matched.add(other.id)
        clusters.append(cluster)

    resolved: list[ResolvedEntity] = []
    blocked: list[dict[str, Any]] = []
    manual: list[dict[str, Any]] = []

    for cluster in clusters:
        source_refs = [item.id for item in cluster]
        base_name = min(cluster, key=lambda r: len(r.canonical_name)).canonical_name
        score = 0.0
        if cluster:
            score = sum(_pairwise_match_score(cluster[0], item) for item in cluster[1:]) / max(1, len(cluster) - 1)
            if len(cluster) == 1:
                score = 0.85

        if score < 0.7:
            manual.extend(manual_review_queue(cluster))
            continue

        entity = ResolvedEntity(
            id=f"resolved:{base_name}",
            type=cluster[0].entity_type,
            canonical_name=base_name,
            source_refs=source_refs,
            confidence=round(max(0.0, min(1.0, score)), 4),
            merge_history=[{
                "source_refs": source_refs,
                "rationale": "same entity identity or canonical match",
                "confidence": round(score, 4),
            }],
            attributes={
                key: value for item in cluster for key, value in item.attributes.items() if key not in {"serial_number", "employee_id"}
            },
        )
        resolved.append(entity)

    # track impossible merges (same name, different hard identifiers)
    for i, left in enumerate(records):
        for right in records[i + 1:]:
            if left.entity_type != right.entity_type:
                continue
            if _hard_conflict(left, right):
                blocked.append({
                    "left": left.id,
                    "right": right.id,
                    "reason": "hard conflict: conflicting identifiers block merge",
                    "left_values": {k: left.attributes.get(k) for k in ("serial_number", "asset_id", "employee_id", "device_id") if left.attributes.get(k) is not None},
                    "right_values": {k: right.attributes.get(k) for k in ("serial_number", "asset_id", "employee_id", "device_id") if right.attributes.get(k) is not None},
                })

    return EntityResolutionResult(resolved=resolved, blocked=blocked, manual_review=manual)


def build_sample_staging_store() -> list[SourceRecord]:
    now = datetime.now(timezone.utc)
    records = [
        SourceRecord(
            id="cmdb:asset-101",
            source_type="CMDB",
            entity_type="asset",
            canonical_name="payments-web-01",
            attributes={"serial_number": "SN-1001", "criticality": "critical", "ip": "10.0.0.12"},
            timestamp=now,
            source_reliability=0.95,
            extraction_confidence=0.92,
        ),
        SourceRecord(
            id="hr:user-88",
            source_type="HR",
            entity_type="user",
            canonical_name="alice.smith",
            attributes={"employee_id": "E-88", "department": "payments"},
            timestamp=now,
            source_reliability=0.80,
            extraction_confidence=0.86,
        ),
        SourceRecord(
            id="finance:bu-22",
            source_type="finance",
            entity_type="business_unit",
            canonical_name="payments",
            attributes={"cost_center": "CC-22"},
            timestamp=now,
            source_reliability=0.85,
            extraction_confidence=0.88,
        ),
        SourceRecord(
            id="ticketing:inc-777",
            source_type="ticketing",
            entity_type="asset",
            canonical_name="payments-web-01",
            attributes={"asset_id": "A-777", "criticality": "high"},
            timestamp=now,
            source_reliability=0.75,
            extraction_confidence=0.82,
        ),
        SourceRecord(
            id="cmdb:asset-202",
            source_type="CMDB",
            entity_type="asset",
            canonical_name="payments-web-99",
            attributes={"serial_number": "SN-202", "criticality": "medium", "ip": "10.0.0.42"},
            timestamp=now,
            source_reliability=0.90,
            extraction_confidence=0.84,
        ),
        SourceRecord(
            id="finance:asset-202",
            source_type="finance",
            entity_type="asset",
            canonical_name="payments-web-99",
            attributes={"serial_number": "SN-202", "criticality": "low", "owner": "payments"},
            timestamp=now,
            source_reliability=0.70,
            extraction_confidence=0.80,
        ),
    ]
    return records


def shared_picture(entity_id: str) -> dict[str, Any]:
    """Create a unified entity context for the specified resolved entity."""
    records = build_sample_staging_store()
    resolution = resolve_entities(records)
    entity = None
    for candidate in resolution.resolved:
        if candidate.id == entity_id or candidate.canonical_name == entity_id:
            entity = candidate
            break
    if entity is None:
        for record in records:
            if record.id == entity_id or record.canonical_name == entity_id:
                entity = ResolvedEntity(
                    id=f"resolved:{record.canonical_name}",
                    type=record.entity_type,
                    canonical_name=record.canonical_name,
                    source_refs=[record.id],
                    confidence=record.source_reliability * record.extraction_confidence,
                    merge_history=[{"source": record.source_type, "rationale": "single-source adoption"}],
                    attributes=record.attributes,
                )
                break

    if entity is None:
        raise KeyError(f"entity_id {entity_id!r} not found")

    lineage = emit_lineage_record(
        output_type="shared_picture",
        output_id=f"shared-picture-{entity.id}",
        inputs=[record.hash for record in records if record.canonical_name == entity.canonical_name],
        transformations=["canonicalize_names", "merge_source_attributes", "enforce_policy"],
        model_versions=["savitar-score-v1"],
        actor="analyst",
    )
    audit = append_audit_event(
        actor="analyst",
        action="read",
        resource=f"/lineage/shared-picture/{entity.id}",
        purpose="risk_review",
        decision="allow",
        outcome="shared_picture_generated",
    )

    attributes = []
    for record in records:
        if record.canonical_name == entity.canonical_name:
            for name, value in record.attributes.items():
                attributes.append({
                    "name": name,
                    "value": value,
                    "source": record.source_type,
                    "timestamp": record.timestamp.isoformat(),
                    "confidence": field_confidence(record.source_reliability, record.extraction_confidence, _recency_score(record.timestamp)),
                })

    return {
        "entity_id": entity.id,
        "canonical_name": entity.canonical_name,
        "source_types": sorted({record.source_type for record in records if record.canonical_name == entity.canonical_name}),
        "attributes": attributes,
        "confidence": entity.confidence,
        "lineage_record_id": lineage.id,
        "audit_event_id": audit.id,
    }


def _recency_score(ts: datetime) -> float:
    age_hours = max(0.0, (datetime.now(timezone.utc) - ts).total_seconds() / 3600.0)
    return max(0.0, min(1.0, 1.0 / (1.0 + age_hours / 24.0)))


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
    "snapshot_hash",
]
