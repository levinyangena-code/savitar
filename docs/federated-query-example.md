# Federated query example

This example shows a read-only shared picture request and its governance annotations.

## Query

POST /v1/shared_picture

Request payload:

```json
{
  "entity_id": "resolved:payments-web-01",
  "role": "analyst",
  "purpose": "risk_review"
}
```

## Response

```json
{
  "entity_id": "resolved:payments-web-01",
  "canonical_name": "payments-web-01",
  "source_types": ["CMDB", "finance", "HR", "ticketing"],
  "attributes": [
    {"name": "criticality", "value": "high", "source": "CMDB", "confidence": 0.91},
    {"name": "owner", "value": "payments", "source": "finance", "confidence": 0.72}
  ],
  "confidence": 0.88,
  "lineage_record_id": "lineage-shared_picture-resolved:payments-web-01",
  "audit_event_id": "audit-20261023..."
}
```

## Enforcement

- RBAC checks the role and purpose before returning the view.
- ABAC redacts any field named `pii`, `ssn`, or raw telemetry.
- The lineage record is required before the output is emitted.
- The audit event is appended with the purpose and outcome in the same request.
