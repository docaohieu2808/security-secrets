# =============================================================================
# l-max-custom-policy.rego — Trivy L-Max: Custom OPA Rego policy for Trivy
#
# Custom Rego policies extend Trivy's built-in checks with org-specific rules.
#
# Usage with Trivy:
#   trivy config --policy ./l-max-custom-policy.rego --namespaces custom ./k8s-manifests
#   trivy image  --policy ./l-max-custom-policy.rego --namespaces custom nginx:latest
#
# Policy namespaces must match: custom.*
# Each rule must define:
#   - __rego_metadata__: title, description, severity, type
#   - __rego_input__: selector for which resource types to apply
#   - deny[msg]: the actual policy check
# =============================================================================

package custom.kubernetes.security

import future.keywords.in

# -----------------------------------------------------------------------------
# Rule 1: Deny containers running as root (UID 0)
# Containers should run as non-root to limit blast radius of container escapes.
# -----------------------------------------------------------------------------
__rego_metadata__ := {
    "id":          "CUSTOM-K8S-001",
    "title":       "Container must not run as root",
    "severity":    "HIGH",
    "type":        "Kubernetes Security Check",
    "description": "Running containers as root (UID 0) increases risk of privilege escalation. Set runAsNonRoot: true or runAsUser >= 1000.",
}

__rego_input__ := {
    "selector": [{"type": "kubernetes"}],
}

deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"}
    container := get_containers(input)[_]
    not container_runs_as_non_root(container)
    msg := sprintf("Container '%s' may run as root. Set securityContext.runAsNonRoot=true or runAsUser>=1000", [container.name])
}

container_runs_as_non_root(container) {
    container.securityContext.runAsNonRoot == true
}

container_runs_as_non_root(container) {
    container.securityContext.runAsUser >= 1000
}

container_runs_as_non_root(container) {
    # Check pod-level security context as fallback
    input.spec.securityContext.runAsNonRoot == true
}

# -----------------------------------------------------------------------------
# Rule 2: Deny privileged containers
# Privileged containers have full host access — equivalent to root on the node.
# -----------------------------------------------------------------------------
deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet"}
    container := get_containers(input)[_]
    container.securityContext.privileged == true
    msg := sprintf("Container '%s' is running in privileged mode. Remove securityContext.privileged=true", [container.name])
}

# -----------------------------------------------------------------------------
# Rule 3: Require resource limits (CPU and memory)
# Containers without limits can starve other workloads (noisy neighbor problem).
# -----------------------------------------------------------------------------
deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet", "Job"}
    container := get_containers(input)[_]
    not container.resources.limits.memory
    msg := sprintf("Container '%s' has no memory limit set. Add resources.limits.memory", [container.name])
}

deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet", "Job"}
    container := get_containers(input)[_]
    not container.resources.limits.cpu
    msg := sprintf("Container '%s' has no CPU limit set. Add resources.limits.cpu", [container.name])
}

# -----------------------------------------------------------------------------
# Rule 4: Deny containers with dangerous Linux capabilities
# CAP_NET_ADMIN, CAP_SYS_ADMIN, etc. allow host-level privilege escalation.
# -----------------------------------------------------------------------------
dangerous_capabilities := {
    "NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE",
    "SYS_RAWIO", "DAC_OVERRIDE", "DAC_READ_SEARCH", "SETUID", "SETGID",
}

deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet"}
    container := get_containers(input)[_]
    cap := container.securityContext.capabilities.add[_]
    cap in dangerous_capabilities
    msg := sprintf("Container '%s' adds dangerous capability '%s'. Remove from securityContext.capabilities.add", [container.name, cap])
}

# -----------------------------------------------------------------------------
# Rule 5: Require read-only root filesystem
# Prevents attackers from writing malware or modifying binaries at runtime.
# -----------------------------------------------------------------------------
deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet"}
    container := get_containers(input)[_]
    not container.securityContext.readOnlyRootFilesystem == true
    msg := sprintf("Container '%s' does not have readOnlyRootFilesystem=true. Set securityContext.readOnlyRootFilesystem=true", [container.name])
}

# -----------------------------------------------------------------------------
# Rule 6: Deny hostNetwork, hostPID, hostIPC
# These share host namespaces, enabling host-level process and network visibility.
# -----------------------------------------------------------------------------
deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet"}
    input.spec.hostNetwork == true
    msg := "Pod uses hostNetwork=true which exposes the host network stack. Remove spec.hostNetwork"
}

deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet"}
    input.spec.hostPID == true
    msg := "Pod uses hostPID=true which exposes host process table. Remove spec.hostPID"
}

deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet"}
    input.spec.hostIPC == true
    msg := "Pod uses hostIPC=true which exposes host IPC namespace. Remove spec.hostIPC"
}

# -----------------------------------------------------------------------------
# Rule 7: Require image digest or pinned tag (not :latest)
# Using :latest makes deployments non-reproducible and bypasses image scanning.
# -----------------------------------------------------------------------------
deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet"}
    container := get_containers(input)[_]
    endswith(container.image, ":latest")
    msg := sprintf("Container '%s' uses ':latest' image tag. Pin to a specific digest or version tag", [container.name])
}

deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet"}
    container := get_containers(input)[_]
    not contains(container.image, ":")
    msg := sprintf("Container '%s' has no image tag specified (implies :latest). Pin to a specific version", [container.name])
}

# -----------------------------------------------------------------------------
# Rule 8: Deny allowPrivilegeEscalation
# Prevents a process inside a container from gaining more privileges than its parent.
# -----------------------------------------------------------------------------
deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet"}
    container := get_containers(input)[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container '%s' does not set allowPrivilegeEscalation=false. Add to securityContext", [container.name])
}

# -----------------------------------------------------------------------------
# Rule 9: Require namespace labels for network policy enforcement
# Namespaces without labels cannot be targeted by NetworkPolicy selectors.
# -----------------------------------------------------------------------------
deny[msg] {
    input.kind == "Namespace"
    not input.metadata.labels["app.kubernetes.io/name"]
    msg := sprintf("Namespace '%s' is missing required label 'app.kubernetes.io/name'", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# Rule 10: Deny RBAC ClusterRoleBindings to system:masters group
# system:masters bypasses all RBAC checks — equivalent to unrestricted cluster admin.
# -----------------------------------------------------------------------------
deny[msg] {
    input.kind == "ClusterRoleBinding"
    subject := input.subjects[_]
    subject.kind == "Group"
    subject.name == "system:masters"
    msg := sprintf("ClusterRoleBinding '%s' binds to system:masters group which bypasses all RBAC. Remove this binding", [input.metadata.name])
}

# -----------------------------------------------------------------------------
# Helper: extract containers from various workload kinds
# Handles spec.containers, spec.initContainers, and nested template specs.
# -----------------------------------------------------------------------------
get_containers(resource) = containers {
    resource.kind == "Pod"
    containers := array.concat(
        object.get(resource.spec, "containers", []),
        object.get(resource.spec, "initContainers", []),
    )
}

get_containers(resource) = containers {
    resource.kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet"}
    containers := array.concat(
        object.get(resource.spec.template.spec, "containers", []),
        object.get(resource.spec.template.spec, "initContainers", []),
    )
}

get_containers(resource) = containers {
    resource.kind == "CronJob"
    containers := array.concat(
        object.get(resource.spec.jobTemplate.spec.template.spec, "containers", []),
        object.get(resource.spec.jobTemplate.spec.template.spec, "initContainers", []),
    )
}

get_containers(resource) = containers {
    resource.kind == "Job"
    containers := array.concat(
        object.get(resource.spec.template.spec, "containers", []),
        object.get(resource.spec.template.spec, "initContainers", []),
    )
}
