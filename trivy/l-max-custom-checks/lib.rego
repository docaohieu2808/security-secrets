# Helpers shared by the checks in this directory. Not a check itself: it has no `deny` rule and lives outside
# the `user.*` namespace Trivy is told to evaluate.
package lib.k8s

import rego.v1

workload_kinds := {"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"}

pod_spec(resource) := resource.spec if resource.kind == "Pod"

pod_spec(resource) := resource.spec.template.spec if resource.kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"}

pod_spec(resource) := resource.spec.jobTemplate.spec.template.spec if resource.kind == "CronJob"

containers(resource) := array.concat(
	object.get(pod_spec(resource), "containers", []),
	object.get(pod_spec(resource), "initContainers", []),
)

# image_is_mutable: no tag or `latest`, and not pinned by digest. The tag is looked for in the last path
# segment only, so "registry:5000/app" (a port, no tag) is correctly seen as untagged.
image_is_mutable(image) if {
	not contains(image, "@sha256:")
	last := regex.split("/", image)[count(regex.split("/", image)) - 1]
	not contains(last, ":")
}

image_is_mutable(image) if {
	not contains(image, "@sha256:")
	endswith(image, ":latest")
}
