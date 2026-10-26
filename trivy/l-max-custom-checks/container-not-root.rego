# METADATA
# title: Container must not run as root
# description: Running as UID 0 widens the blast radius of a container escape. Require runAsNonRoot or a UID >= 1000.
# custom:
#   id: USER-K8S-001
#   severity: HIGH
#   recommended_actions: Set securityContext.runAsNonRoot to true, or runAsUser to 1000 or higher.
#   input:
#     selector:
#     - type: kubernetes
package user.kubernetes.ID001

import rego.v1

import data.lib.k8s

deny contains msg if {
	input.kind in k8s.workload_kinds
	some container in k8s.containers(input)
	not runs_as_non_root(container)
	msg := sprintf("%s '%s': container '%s' may run as root", [input.kind, input.metadata.name, container.name])
}

runs_as_non_root(container) if container.securityContext.runAsNonRoot == true

runs_as_non_root(container) if container.securityContext.runAsUser >= 1000

# pod-level setting applies when the container does not override it
runs_as_non_root(container) if {
	not container.securityContext.runAsNonRoot
	k8s.pod_spec(input).securityContext.runAsNonRoot == true
}
