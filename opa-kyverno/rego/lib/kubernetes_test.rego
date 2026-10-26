package lib.kubernetes_test

import data.lib.kubernetes

pod := {"kind": "Pod", "metadata": {"name": "p"}, "spec": {
	"containers": [{"name": "app", "image": "nginx:1.27"}],
	"initContainers": [{"name": "init", "image": "busybox:latest"}],
}}

deployment := {"kind": "Deployment", "metadata": {"name": "d", "namespace": "shop"}, "spec": {"template": {"spec": {
	"containers": [{"name": "app", "image": "nginx:1.27"}],
}}}}

cronjob := {"kind": "CronJob", "spec": {"jobTemplate": {"spec": {"template": {"spec": {
	"containers": [{"name": "job", "image": "alpine:3.22"}],
}}}}}}

test_get_containers_pod_includes_init if {
	names := {c.name | some c in kubernetes.get_containers(pod)}
	names == {"app", "init"}
}

test_get_containers_deployment if {
	count(kubernetes.get_containers(deployment)) == 1
}

test_get_containers_cronjob if {
	kubernetes.get_containers(cronjob)[0].name == "job"
}

test_is_pod_for_workloads if {
	kubernetes.is_pod(pod)
	kubernetes.is_pod(deployment)
	kubernetes.is_pod(cronjob)
	not kubernetes.is_pod({"kind": "Service"})
}

test_is_privileged if {
	kubernetes.is_privileged({"securityContext": {"privileged": true}})
	not kubernetes.is_privileged({"securityContext": {"privileged": false}})
	not kubernetes.is_privileged({})
}

test_runs_as_root if {
	kubernetes.runs_as_root({})
	kubernetes.runs_as_root({"securityContext": {"runAsUser": 0}})
	not kubernetes.runs_as_root({"securityContext": {"runAsNonRoot": true}})
	not kubernetes.runs_as_root({"securityContext": {"runAsUser": 10001}})
}

test_dangerous_capability if {
	kubernetes.has_dangerous_capability({"securityContext": {"capabilities": {"add": ["NET_ADMIN"]}}})
	not kubernetes.has_dangerous_capability({"securityContext": {"capabilities": {"add": ["CHOWN"]}}})
	not kubernetes.has_dangerous_capability({})
}

test_missing_resource_limits if {
	kubernetes.missing_resource_limits({})
	kubernetes.missing_resource_limits({"resources": {"limits": {"cpu": "1"}}})
	kubernetes.missing_resource_limits({"resources": {"limits": {"memory": "1Gi"}}})
	not kubernetes.missing_resource_limits({"resources": {"limits": {"cpu": "1", "memory": "1Gi"}}})
}

test_uses_latest_tag if {
	kubernetes.uses_latest_tag({"image": "nginx"})
	kubernetes.uses_latest_tag({"image": "nginx:latest"})
	not kubernetes.uses_latest_tag({"image": "nginx:1.27"})
}

test_hardening_helpers if {
	kubernetes.allows_privilege_escalation({})
	not kubernetes.allows_privilege_escalation({"securityContext": {"allowPrivilegeEscalation": false}})
	kubernetes.writable_root_fs({})
	not kubernetes.writable_root_fs({"securityContext": {"readOnlyRootFilesystem": true}})
}

test_get_namespace_defaults if {
	kubernetes.get_namespace(deployment) == "shop"
	kubernetes.get_namespace(pod) == "default"
}

test_labels_and_annotations if {
	kubernetes.has_label({"metadata": {"labels": {"team": "pay"}}}, "team")
	not kubernetes.has_label({"metadata": {}}, "team")
	kubernetes.has_annotation({"metadata": {"annotations": {"a": "b"}}}, "a")
}

test_system_namespace if {
	kubernetes.is_system_namespace("kube-system")
	not kubernetes.is_system_namespace("shop")
}
