# METADATA
# title: Container must not be privileged
# description: A privileged container has nearly the same access as root on the node.
# custom:
#   id: USER-K8S-002
#   severity: CRITICAL
#   recommended_actions: Remove securityContext.privileged, add only the specific capabilities needed.
#   input:
#     selector:
#     - type: kubernetes
package user.kubernetes.ID002

import rego.v1

import data.lib.k8s

deny contains msg if {
	input.kind in k8s.workload_kinds
	some container in k8s.containers(input)
	container.securityContext.privileged == true
	msg := sprintf("%s '%s': container '%s' is privileged", [input.kind, input.metadata.name, container.name])
}
