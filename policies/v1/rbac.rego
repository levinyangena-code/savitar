package savitar.policy

default allow := false

allow if {
    input.role == "analyst"
    input.action == "read"
    not contains(input.resource, "pii")
}

allow if {
    input.role == "auditor"
    input.action == "read"
    contains(input.resource, "lineage")
}

allow if {
    input.role == "admin"
    input.action == "read"
}

allow if {
    input.role == "admin"
    input.action == "write_policy"
    input.second_approver == true
}
