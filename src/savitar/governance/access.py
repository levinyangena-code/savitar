from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

VALID_ROLES = {
    "analyst",
    "ir_responder",
    "executive",
    "auditor",
    "admin",
}

ROLE_PERMISSIONS = {
    "analyst": {"read": {"/v1/", "/lineage/", "/reports/"}, "write": set()},
    "ir_responder": {"read": {"/v1/", "/lineage/", "/intel/"}, "write": {"/intel/"}},
    "executive": {"read": {"/v1/", "/reports/", "/lineage/"}, "write": set()},
    "auditor": {"read": {"/v1/", "/audit/", "/lineage/"}, "write": {"/audit/"}},
    "admin": {"read": {"/v1/", "/audit/", "/lineage/", "/policy/"}, "write": {"/policy/", "/audit/"}},
}

PURPOSE_TAXONOMY = {
    "incident_response": {"analyst", "ir_responder", "executive", "auditor", "admin"},
    "risk_review": {"analyst", "ir_responder", "executive", "auditor", "admin"},
    "lineage_verification": {"auditor", "admin"},
    "audit_review": {"auditor", "admin"},
    "executive_report": {"executive", "admin"},
    "policy_change": {"admin"},
    "audit_write": {"admin", "auditor"},
    "telemetry_access": {"analyst", "ir_responder", "executive", "auditor", "admin"},
}

DEFAULT_POLICY_VERSION = "v1"


def _policy_version() -> str:
    version_path = Path(__file__).resolve().parents[3] / "policies" / "VERSION"
    if version_path.exists():
        try:
            return version_path.read_text(encoding="utf-8").strip() or DEFAULT_POLICY_VERSION
        except OSError:
            pass
    return DEFAULT_POLICY_VERSION


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    reason: str
    policy_version: str
    redactions: list[str]


def validate_purpose(role: str, purpose: str) -> bool:
    if role not in VALID_ROLES:
        return False
    if purpose not in PURPOSE_TAXONOMY:
        return False
    return role in PURPOSE_TAXONOMY[purpose]


def _resource_matches(resource: str, resource_prefix: str) -> bool:
    return resource.startswith(resource_prefix) or resource == resource_prefix


def authorize_access(
    actor_role: str,
    action: str,
    resource: str,
    purpose: str,
    *,
    require_second_approver: bool = False,
    field_name: str | None = None,
) -> AccessDecision:
    """Return RBAC/ABAC evaluation for a request.

    - Deny by default.
    - Use role-based checks for endpoint/resource access.
    - Use field ABAC to redact sensitive data instead of leaking raw values.
    """
    role = (actor_role or "").lower()
    policy_version = _policy_version()

    if role not in VALID_ROLES:
        return AccessDecision(False, f"unknown role '{actor_role}'", policy_version, [])
    if not validate_purpose(role, purpose):
        return AccessDecision(False, f"purpose '{purpose}' is invalid for role '{role}'", policy_version, [])

    permissions = ROLE_PERMISSIONS.get(role, {})
    allowed_resources = set(permissions.get(action, set()))

    if not allowed_resources and action == "read":
        allowed_resources = set(permissions.get("read", set()))
    if not allowed_resources and action == "write":
        allowed_resources = set(permissions.get("write", set()))

    resource_allowed = any(_resource_matches(resource, prefix) for prefix in allowed_resources)
    if not resource_allowed:
        return AccessDecision(False, f"role '{role}' is denied for {action} on resource '{resource}'", policy_version, [])

    if "pii" in resource.lower() and role in {"analyst", "admin"}:
        return AccessDecision(False, "raw identity PII is denied for this role", policy_version, [])

    if "telemetry" in resource.lower() and role == "auditor" and not resource.lower().startswith("/lineage"):
        return AccessDecision(False, "auditors cannot view raw telemetry", policy_version, [])

    if role == "admin" and action in {"write_policy", "write_audit"} and require_second_approver is False:
        return AccessDecision(False, "admin policy or audit writes require a second approver", policy_version, [])

    redactions: list[str] = []
    if field_name:
        lowered = field_name.lower()
        if lowered in {"ssn", "email", "phone", "employee_id", "serial_number", "raw_telemetry", "pii"}:
            redactions.append("[REDACTED:policy_id]")

    return AccessDecision(True, "authorized", policy_version, redactions)


def redact_sensitive_fields(payload: dict[str, Any], actor_role: str, purpose: str) -> dict[str, Any]:
    """Return a sanitized copy of a payload without leaking sensitive field values."""
    if not isinstance(payload, dict):
        return payload
    result = dict(payload)
    for key, value in list(result.items()):
        key_lower = str(key).lower()
        if key_lower in {"ssn", "email", "phone", "employee_id", "serial_number", "raw_telemetry", "pii"}:
            decision = authorize_access(actor_role, "read", "/lineage/", purpose, field_name=key)
            if not decision.allowed or decision.redactions:
                result[key] = "[REDACTED:policy_id]"
    return result
