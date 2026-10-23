"""Synthetic sensor integration for network, OT, and EDR sample events."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class ExtractedFact:
    document_id: str
    page: int
    offset: int
    text: str
    entity_id: str | None
    extraction_confidence: float
    provenance: dict[str, Any]


@dataclass(frozen=True)
class SensorEvent:
    id: str
    source_type: str
    asset_id: str | None
    ip: str | None
    timestamp: datetime
    event_type: str
    metadata: dict[str, Any] = field(default_factory=dict)


def extract_entities_from_pdf(pdf_text: str, resolved_entities: list[dict[str, Any]]) -> list[ExtractedFact]:
    """Extract synthetic entity mentions from a sample PDF and link them to resolved entities."""
    identifiers = {entity["canonical_name"]: entity["id"] for entity in resolved_entities}
    facts: list[ExtractedFact] = []
    mention_map = {
        "payments-web-01": "payments-web-01",
        "hr-app-01": "hr-app-01",
        "ot-plc-01": "ot-plc-01",
    }
    lower = pdf_text.lower()
    for label, canonical_name in mention_map.items():
        if label in lower:
            offset = lower.find(label)
            facts.append(
                ExtractedFact(
                    document_id="doc:synth-001",
                    page=1,
                    offset=offset,
                    text=label,
                    entity_id=identifiers.get(canonical_name),
                    extraction_confidence=0.91,
                    provenance={"document_id": "doc:synth-001", "page": 1, "offset": offset},
                )
            )
    return facts


def join_sensor_events(sensor_events: list[SensorEvent], resolved_assets: list[dict[str, Any]]) -> dict[str, Any]:
    """Join event records to resolved assets using identifiers and time-aware IP matching."""
    matched: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    for event in sensor_events:
        asset = None
        for candidate in resolved_assets:
            if event.asset_id and candidate.get("canonical_name") == event.asset_id:
                asset = candidate
                break
            if event.ip and candidate.get("attributes", {}).get("ip") == event.ip:
                asset = candidate
                break
        if asset is None:
            unmatched.append({"event_id": event.id, "reason": "no matching asset"})
            continue
        matched.append(
            {
                "event_id": event.id,
                "asset_id": asset["id"],
                "canonical_name": asset["canonical_name"],
                "event_type": event.event_type,
                "timestamp": event.timestamp.isoformat(),
                "matched_on": "ip_lease",
            }
        )
    return {"matched": matched, "unmatched": unmatched}


def synthetic_sensor_events() -> list[SensorEvent]:
    now = datetime.now(timezone.utc)
    return [
        SensorEvent(
            id="sensor:net-01",
            source_type="network",
            asset_id="payments-web-01",
            ip="10.0.0.12",
            timestamp=now,
            event_type="connection",
            metadata={"src_ip": "198.51.100.8", "dst_ip": "10.0.0.12"},
        ),
        SensorEvent(
            id="sensor:edr-02",
            source_type="edr",
            asset_id="unknown",
            ip="10.0.0.99",
            timestamp=now,
            event_type="process_execution",
            metadata={"process": "powershell"},
        ),
    ]


__all__ = [
    "ExtractedFact",
    "SensorEvent",
    "extract_entities_from_pdf",
    "join_sensor_events",
    "synthetic_sensor_events",
]
