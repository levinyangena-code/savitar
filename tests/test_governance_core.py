from __future__ import annotations

from savitar.governance import append_audit_event, audit_query, verify_chain
from savitar.governance.access import authorize_access


def test_authorize_access_examples():
    assert authorize_access("analyst", "read", "/reports/summary", "risk_review").allowed is True
    assert authorize_access("analyst", "read", "/identity/raw-pii", "risk_review").allowed is False
    assert authorize_access("auditor", "read", "/lineage/record-1", "lineage_verification").allowed is True
    assert authorize_access("auditor", "read", "/telemetry/raw", "telemetry_access").allowed is False


def test_audit_chain_enforced():
    evt = append_audit_event(
        actor="auditor",
        action="read",
        resource="/audit/query",
        purpose="audit_review",
        decision="allow",
        outcome="query_ok",
    )
    assert evt.hash
    assert verify_chain() is True
    assert audit_query(page=1, page_size=10)


def test_analyst_redaction_and_denial():
    decision = authorize_access("analyst", "read", "/identity/raw-pii", "risk_review")
    assert decision.allowed is False
    assert "raw identity PII" in decision.reason


def test_policy_version_recorded():
    decision = authorize_access("admin", "read", "/policy/policies", "policy_change")
    assert decision.policy_version == "v1"
