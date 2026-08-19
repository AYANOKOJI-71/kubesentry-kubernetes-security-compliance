package kubesentry.network

# Illustrative bundle-level reference. A future OPA adapter receives all submitted
# resources as data and can determine whether a workload namespace has policy evidence.

workload_namespaces contains namespace if {
  resource := input.resources[_]
  resource.kind == "Deployment"
  namespace := object.get(resource.metadata, "namespace", "default")
}

network_policy_namespaces contains namespace if {
  resource := input.resources[_]
  resource.kind == "NetworkPolicy"
  namespace := object.get(resource.metadata, "namespace", "default")
}

deny contains result if {
  namespace := workload_namespaces[_]
  not network_policy_namespaces[namespace]
  result := {
    "policy_id": "KSB-011",
    "message": sprintf("no NetworkPolicy evidence for namespace %q", [namespace]),
  }
}
