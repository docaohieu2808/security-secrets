# Reusable Kubernetes helpers (OPA v1 syntax; no `import future.keywords` needed).
#
# Four packages used to live in one file, which OPA rejects ("unexpected package"):
# one file = one package. They are now lib/kubernetes.rego, networking.rego, rbac.rego, images.rego.
package lib.kubernetes

import data.lib.images

# is_pod(resource): a Pod or a workload kind that embeds a pod template.
is_pod(resource) if resource.kind == "Pod"

is_pod(resource) if resource.kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"}

# pod_spec(resource): the PodSpec, wherever the kind keeps it.
pod_spec(resource) := resource.spec if resource.kind == "Pod"

pod_spec(resource) := resource.spec.template.spec if resource.kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"}

pod_spec(resource) := resource.spec.jobTemplate.spec.template.spec if resource.kind == "CronJob"

# get_containers(resource): containers + initContainers of any pod-bearing kind.
get_containers(resource) := array.concat(
	object.get(pod_spec(resource), "containers", []),
	object.get(pod_spec(resource), "initContainers", []),
)

is_privileged(container) if container.securityContext.privileged == true

# runs_as_root(container): may run as root (no runAsNonRoot and no non-root runAsUser).
# The comparison lives in its own function on purpose: `not a.b.c >= 1000` is compiled with the
# reference evaluated outside the negation, so an unset runAsUser would make the whole rule undefined.
runs_as_root(container) if {
	not container.securityContext.runAsNonRoot == true
	not has_non_root_uid(container)
}

has_non_root_uid(container) if container.securityContext.runAsUser >= 1000

dangerous_caps := {
	"NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE",
	"SYS_RAWIO", "DAC_OVERRIDE", "DAC_READ_SEARCH",
	"SETUID", "SETGID", "NET_RAW", "SYS_CHROOT",
}

has_dangerous_capability(container) if {
	some cap in container.securityContext.capabilities.add
	cap in dangerous_caps
}

missing_resource_limits(container) if not container.resources.limits.memory

missing_resource_limits(container) if not container.resources.limits.cpu

# uses_latest_tag(container): image has no tag, or the tag is `latest`, and is not digest-pinned.
uses_latest_tag(container) if images.is_mutable(container.image)

allows_privilege_escalation(container) if not container.securityContext.allowPrivilegeEscalation == false

writable_root_fs(container) if not container.securityContext.readOnlyRootFilesystem == true

get_namespace(resource) := resource.metadata.namespace if resource.metadata.namespace

else := "default"

has_label(resource, key) if resource.metadata.labels[key]

has_annotation(resource, key) if resource.metadata.annotations[key]

system_namespaces := {
	"kube-system", "kube-public", "kube-node-lease",
	"gatekeeper-system", "kyverno", "cert-manager",
	"falco", "monitoring", "logging",
}

is_system_namespace(ns) if ns in system_namespaces
