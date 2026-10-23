package savitar.policy

test_analyst_can_read_non_pii {
    allow with input as {"role": "analyst", "action": "read", "resource": "/reports/summary"}
}

test_analyst_cannot_read_pii {
    not allow with input as {"role": "analyst", "action": "read", "resource": "/identity/raw-pii"}
}

test_auditor_can_view_lineage {
    allow with input as {"role": "auditor", "action": "read", "resource": "/lineage/record-1"}
}

test_admin_requires_second_approver_for_policy_change {
    not allow with input as {"role": "admin", "action": "write_policy", "second_approver": false}
}
