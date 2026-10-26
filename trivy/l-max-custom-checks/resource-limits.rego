# METADATA
# title: Container must set CPU and memory limits
# description: Without limits one container can starve its neighbours and a leak can take a node down.
# custom:
#   id: USER-K8S-003
#   severity: MEDIUM
#   recommended_actions: Set resources.limits.cpu and resources.limits.memory.
#   input:
#     selector:
#     - type: kubernetes
package user.kubernetes.ID003

import rego.v1

import data.lib.k8s

deny contains msg if {
	input.kind in k8s.workload_kinds
	some container in k8s.containers(input)
	some resource in ["cpu", "memory"]
	not container.resources.limits[resource]
	msg := sprintf("%s '%s': container '%s' has no %s limit", [input.kind, input.metadata.name, container.name, resource])
}
