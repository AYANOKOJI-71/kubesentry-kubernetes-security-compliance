package kubesentry.workload

# Illustrative OPA/Rego policy reference. The deterministic local demo evaluates
# equivalent checks in Python; this module supports a future OPA adapter.

deny contains result if {
  container := input.spec.template.spec.containers[_]
  container.securityContext.privileged == true
  result := {
    "policy_id": "KSB-001",
    "message": sprintf("container %q is privileged", [container.name]),
  }
}

deny contains result if {
  container := input.spec.template.spec.containers[_]
  container.securityContext.allowPrivilegeEscalation != false
  result := {
    "policy_id": "KSB-002",
    "message": sprintf("container %q must disable privilege escalation", [container.name]),
  }
}

deny contains result if {
  container := input.spec.template.spec.containers[_]
  not container.securityContext.capabilities.drop[_] == "ALL"
  result := {
    "policy_id": "KSB-005",
    "message": sprintf("container %q must drop ALL capabilities", [container.name]),
  }
}
