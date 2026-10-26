# METADATA
# title: Pod must not share host namespaces
# description: hostNetwork, hostPID and hostIPC expose the node's network stack, process table and IPC to the pod.
# custom:
#   id: USER-K8S-005
#   severity: HIGH
#   recommended_actions: Remove hostNetwork, hostPID and hostIPC from the pod spec.
#   input:
#     selector:
#     - type: kubernetes
package user.kubernetes.ID005

import rego.v1

import data.lib.k8s

deny contains msg if {
	input.kind in k8s.workload_kinds
	some field in ["hostNetwork", "hostPID", "hostIPC"]
	k8s.pod_spec(input)[field] == true
	msg := sprintf("%s '%s': %s is enabled", [input.kind, input.metadata.name, field])
}
