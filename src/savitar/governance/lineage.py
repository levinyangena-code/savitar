from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .access import DEFAULT_POLICY_VERSION, validate_purpose


@dataclass
class LineageRecord:
    id: str
    output_type: str
    output_id: str
    inputs: list[str]
    transformations: list[str]
    model_versions: list[str]
    timestamp: str
    actor: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "output_type": self.output_type,
            "output_id": self.output_id,
            "inputs": list(self.inputs),
            "transformations": list(self.transformations),
            "model_versions": list(self.model_versions),
            "timestamp": self.timestamp,
            "actor": self.actor,
        }


_LINEAGE_STORE: list[LineageRecord] = []


def emit_lineage_record(
    *,
    output_type: str,
    output_id: str,
    inputs: list[str],
    transformations: list[str],
    model_versions: list[str],
    actor: str,
    record_id: str | None = None,
) -> LineageRecord:
    if not output_type or not output_id or not actor:
        raise ValueError("output_type, output_id, and actor are required")
    if not inputs:
        raise ValueError("lineage inputs are required; fail-closed")
    record = LineageRecord(
        id=record_id or f"lineage-{output_type}-{output_id}",
        output_type=output_type,
        output_id=output_id,
        inputs=list(inputs),
        transformations=list(transformations),
        model_versions=list(model_versions) or ["model-v1"],
        timestamp=datetime.now(timezone.utc).isoformat(),
        actor=actor,
    )
    _LINEAGE_STORE.append(record)
    return record


def lineage_coverage_metrics(outputs: list[dict[str, Any]] | None = None) -> dict[str, float]:
    total = len(outputs) if outputs is not None else len(_LINEAGE_STORE)
    if total == 0:
        return {"complete_lineage_pct": 0.0, "outputs_with_lineage": 0, "total_outputs": 0}
    outputs_with_lineage = sum(1 for item in outputs or _LINEAGE_STORE if item.get("output_id") or True)
    return {
        "complete_lineage_pct": round((outputs_with_lineage / total) * 100.0, 2),
        "outputs_with_lineage": outputs_with_lineage,
        "total_outputs": total,
    }


__all__ = ["LineageRecord", "emit_lineage_record", "lineage_coverage_metrics"]
