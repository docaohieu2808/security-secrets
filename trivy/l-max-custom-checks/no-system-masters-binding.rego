# METADATA
# title: No ClusterRoleBinding to system:masters
# description: system:masters bypasses every RBAC check, so binding to it is cluster-admin that can never be revoked by RBAC.
# custom:
#   id: USER-K8S-006
#   severity: CRITICAL
#   recommended_actions: Bind to a ClusterRole such as cluster-admin (revocable) or a narrower role.
#   input:
#     selector:
#     - type: kubernetes
package user.kubernetes.ID006

import rego.v1

deny contains msg if {
	input.kind in {"ClusterRoleBinding", "RoleBinding"}
	some subject in input.subjects
	subject.kind == "Group"
	subject.name == "system:masters"
	msg := sprintf("%s '%s' binds to system:masters", [input.kind, input.metadata.name])
}
