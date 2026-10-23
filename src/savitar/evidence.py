"""Evidence and lineage types. Every relationship carries these for auditability."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Evidence:
    source: str                     # e.g. "edr:win10-42", "nessus:scan-2026-10-21"
    timestamp: datetime
    rule_version: str               # deterministic rule/model identifier
    model_version: str              # scoring-model version
    confidence_hint: float = 1.0    # source-reported confidence in [0, 1]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


# Bump whenever scoring formulas change — every output records this.
SCORING_MODEL_VERSION = "savitar-score-v1"
DEFAULT_RULE_VERSION = "rule-v1"
