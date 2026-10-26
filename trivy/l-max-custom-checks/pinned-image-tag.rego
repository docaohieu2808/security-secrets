# METADATA
# title: Image must be pinned to a version or digest
# description: A missing tag or :latest makes a deployment non-reproducible and lets an unscanned image in.
# custom:
#   id: USER-K8S-004
#   severity: MEDIUM
#   recommended_actions: Use an exact version tag, or better a digest (image@sha256:...).
#   input:
#     selector:
#     - type: kubernetes
package user.kubernetes.ID004

import rego.v1

import data.lib.k8s

deny contains msg if {
	input.kind in k8s.workload_kinds
	some container in k8s.containers(input)
	k8s.image_is_mutable(container.image)
	msg := sprintf("%s '%s': container '%s' uses a mutable image reference (%s)", [input.kind, input.metadata.name, container.name, container.image])
}
