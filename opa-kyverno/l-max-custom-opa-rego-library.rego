# =============================================================================
# l-max-custom-opa-rego-library.rego — OPA L-Max: Reusable Rego policy library
#
# A shared library of helper functions and policies for use across OPA Gatekeeper,
# Conftest, and Trivy custom policy evaluations.
#
# Usage with Conftest (CI pipeline):
#   conftest test ./k8s-manifests/ --policy ./l-max-custom-opa-rego-library.rego
#
# Usage with OPA CLI:
#   opa eval --data l-max-custom-opa-rego-library.rego \
#            --input manifest.json "data.lib.kubernetes.is_privileged"
#
# Usage with Gatekeeper (reference in ConstraintTemplate rego block):
#   import data.lib.kubernetes
#   import data.lib.networking
# =============================================================================

# --- Package: lib.kubernetes — K8s resource helpers --------------------------
package lib.kubernetes

import future.keywords.in
import future.keywords.if

# -----------------------------------------------------------------------------
# is_pod(resource): true if resource is a Pod or workload that contains pods
# -----------------------------------------------------------------------------
is_pod(resource) if resource.kind == "Pod"
is_pod(resource) if resource.kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"}
is_pod(resource) if resource.kind == "CronJob"

# -----------------------------------------------------------------------------
# get_containers(resource): returns all containers (including init containers)
# Works for Pod, Deployment, DaemonSet, StatefulSet, Job, CronJob
# -----------------------------------------------------------------------------
get_containers(resource) = containers if {
    resource.kind == "Pod"
    containers := array.concat(
        object.get(resource.spec, "containers", []),
        object.get(resource.spec, "initContainers", []),
    )
}

get_containers(resource) = containers if {
    resource.kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet"}
    containers := array.concat(
        object.get(resource.spec.template.spec, "containers", []),
        object.get(resource.spec.template.spec, "initContainers", []),
    )
}

get_containers(resource) = containers if {
    resource.kind == "Job"
    containers := array.concat(
        object.get(resource.spec.template.spec, "containers", []),
        object.get(resource.spec.template.spec, "initContainers", []),
    )
}

get_containers(resource) = containers if {
    resource.kind == "CronJob"
    containers := array.concat(
        object.get(resource.spec.jobTemplate.spec.template.spec, "containers", []),
        object.get(resource.spec.jobTemplate.spec.template.spec, "initContainers", []),
    )
}

# -----------------------------------------------------------------------------
# is_privileged(container): true if container runs in privileged mode
# -----------------------------------------------------------------------------
is_privileged(container) if container.securityContext.privileged == true

# -----------------------------------------------------------------------------
# runs_as_root(container): true if container may run as root
# -----------------------------------------------------------------------------
runs_as_root(container) if {
    not container.securityContext.runAsNonRoot == true
    not container.securityContext.runAsUser >= 1000
}

# -----------------------------------------------------------------------------
# has_dangerous_capability(container): true if any dangerous Linux cap is added
# -----------------------------------------------------------------------------
dangerous_caps := {
    "NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE",
    "SYS_RAWIO", "DAC_OVERRIDE", "DAC_READ_SEARCH",
    "SETUID", "SETGID", "NET_RAW", "SYS_CHROOT",
}

has_dangerous_capability(container) if {
    cap := container.securityContext.capabilities.add[_]
    cap in dangerous_caps
}

# -----------------------------------------------------------------------------
# missing_resource_limits(container): true if CPU or memory limits absent
# -----------------------------------------------------------------------------
missing_resource_limits(container) if not container.resources.limits.memory
missing_resource_limits(container) if not container.resources.limits.cpu

# -----------------------------------------------------------------------------
# uses_latest_tag(container): true if image uses :latest or has no tag
# -----------------------------------------------------------------------------
uses_latest_tag(container) if endswith(container.image, ":latest")
uses_latest_tag(container) if not contains(container.image, ":")

# -----------------------------------------------------------------------------
# allows_privilege_escalation(container): true if allowPrivilegeEscalation not false
# -----------------------------------------------------------------------------
allows_privilege_escalation(container) if {
    not container.securityContext.allowPrivilegeEscalation == false
}

# -----------------------------------------------------------------------------
# writable_root_fs(container): true if readOnlyRootFilesystem is not true
# -----------------------------------------------------------------------------
writable_root_fs(container) if {
    not container.securityContext.readOnlyRootFilesystem == true
}

# -----------------------------------------------------------------------------
# get_namespace(resource): returns namespace or "default" if unset
# -----------------------------------------------------------------------------
get_namespace(resource) = ns if {
    ns := resource.metadata.namespace
} else = "default"

# -----------------------------------------------------------------------------
# has_label(resource, key): true if resource has the given label key
# -----------------------------------------------------------------------------
has_label(resource, key) if resource.metadata.labels[key]

# -----------------------------------------------------------------------------
# has_annotation(resource, key): true if resource has the given annotation key
# -----------------------------------------------------------------------------
has_annotation(resource, key) if resource.metadata.annotations[key]

# -----------------------------------------------------------------------------
# is_system_namespace(ns): true if namespace is a well-known system namespace
# -----------------------------------------------------------------------------
system_namespaces := {
    "kube-system", "kube-public", "kube-node-lease",
    "gatekeeper-system", "kyverno", "cert-manager",
    "falco", "monitoring", "logging",
}

is_system_namespace(ns) if ns in system_namespaces


# --- Package: lib.networking — Network policy helpers ------------------------
package lib.networking

import future.keywords.in

# -----------------------------------------------------------------------------
# has_networkpolicy(namespace, policies): true if namespace has a NetworkPolicy
# policies is the list of NetworkPolicy objects to check against
# -----------------------------------------------------------------------------
has_networkpolicy(namespace, policies) if {
    policy := policies[_]
    policy.metadata.namespace == namespace
}

# -----------------------------------------------------------------------------
# is_default_deny(policy): true if NetworkPolicy is a default-deny-all
# A default-deny has empty podSelector and covers both Ingress and Egress
# -----------------------------------------------------------------------------
is_default_deny(policy) if {
    policy.spec.podSelector == {}
    "Ingress" in policy.spec.policyTypes
    "Egress" in policy.spec.policyTypes
    not policy.spec.ingress
    not policy.spec.egress
}

# -----------------------------------------------------------------------------
# port_in_range(port, min, max): true if port number is within [min, max]
# -----------------------------------------------------------------------------
port_in_range(port, min, max) if {
    port >= min
    port <= max
}

# -----------------------------------------------------------------------------
# is_sensitive_port(port): true if port is a well-known privileged service port
# -----------------------------------------------------------------------------
sensitive_ports := {22, 23, 3389, 5900, 2375, 2376, 4243}  # SSH, Telnet, RDP, VNC, Docker

is_sensitive_port(port) if port in sensitive_ports


# --- Package: lib.rbac — RBAC risk helpers -----------------------------------
package lib.rbac

import future.keywords.in

# -----------------------------------------------------------------------------
# high_risk_verbs: verbs that grant write/admin access
# -----------------------------------------------------------------------------
high_risk_verbs := {"create", "update", "patch", "delete", "deletecollection", "*"}

# -----------------------------------------------------------------------------
# high_risk_resources: K8s resources that are sensitive to access
# -----------------------------------------------------------------------------
high_risk_resources := {
    "secrets", "pods/exec", "pods/attach", "nodes",
    "clusterroles", "clusterrolebindings", "roles", "rolebindings",
    "*",
}

# -----------------------------------------------------------------------------
# rule_is_high_risk(rule): true if a PolicyRule grants high-risk access
# -----------------------------------------------------------------------------
rule_is_high_risk(rule) if {
    verb := rule.verbs[_]
    verb in high_risk_verbs
    resource := rule.resources[_]
    resource in high_risk_resources
}

# -----------------------------------------------------------------------------
# binds_to_system_masters(binding): true if binding grants system:masters
# system:masters bypasses all RBAC authorization
# -----------------------------------------------------------------------------
binds_to_system_masters(binding) if {
    subject := binding.subjects[_]
    subject.kind == "Group"
    subject.name == "system:masters"
}

# -----------------------------------------------------------------------------
# is_wildcard_role(role): true if role grants wildcard verbs on wildcard resources
# Equivalent to cluster-admin — should never be granted to non-system accounts
# -----------------------------------------------------------------------------
is_wildcard_role(role) if {
    rule := role.rules[_]
    "*" in rule.verbs
    "*" in rule.resources
    "*" in rule.apiGroups
}


# --- Package: lib.images — Container image policy helpers --------------------
package lib.images

import future.keywords.in

# -----------------------------------------------------------------------------
# approved_registries: set of registry prefixes allowed in the organization
# Override this list in environment-specific policy bundles
# -----------------------------------------------------------------------------
approved_registries := {
    "gcr.io/my-org/",
    "registry.company.com/",
    "ghcr.io/my-org/",
    "public.ecr.aws/amazonlinux/",
    "docker.io/library/",    # Official Docker Hub library images
}

# -----------------------------------------------------------------------------
# from_approved_registry(image): true if image originates from an approved registry
# -----------------------------------------------------------------------------
from_approved_registry(image) if {
    registry := approved_registries[_]
    startswith(image, registry)
}

# -----------------------------------------------------------------------------
# has_digest(image): true if image reference includes a SHA256 digest
# Digest-pinned images are immutable and not affected by tag mutation
# -----------------------------------------------------------------------------
has_digest(image) if contains(image, "@sha256:")

# -----------------------------------------------------------------------------
# extract_registry(image): returns the registry hostname from an image reference
# e.g. "gcr.io/project/image:tag" -> "gcr.io"
# -----------------------------------------------------------------------------
extract_registry(image) = registry if {
    parts := split(image, "/")
    # Registry is first component if it contains a dot or colon (hostname indicators)
    contains(parts[0], ".")
    registry := parts[0]
} else = "docker.io"  # Default registry when no hostname prefix present
