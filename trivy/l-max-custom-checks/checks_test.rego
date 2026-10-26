package user.kubernetes.checks_test

import rego.v1

import data.user.kubernetes.ID001
import data.user.kubernetes.ID002
import data.user.kubernetes.ID003
import data.user.kubernetes.ID004
import data.user.kubernetes.ID005
import data.user.kubernetes.ID006

good := {"kind": "Deployment", "metadata": {"name": "web"}, "spec": {"template": {"spec": {"containers": [{
	"name": "web",
	"image": "nginx:1.27",
	"resources": {"limits": {"cpu": "1", "memory": "1Gi"}},
	"securityContext": {"runAsNonRoot": true},
}]}}}}

bad_pod := {"kind": "Pod", "metadata": {"name": "bad"}, "spec": {
	"hostNetwork": true,
	"containers": [{"name": "app", "image": "nginx", "securityContext": {"privileged": true}}],
}}

test_good_workload_passes_every_check if {
	count(ID001.deny) == 0 with input as good
	count(ID002.deny) == 0 with input as good
	count(ID003.deny) == 0 with input as good
	count(ID004.deny) == 0 with input as good
	count(ID005.deny) == 0 with input as good
}

test_root_is_flagged if count(ID001.deny) == 1 with input as bad_pod

test_privileged_is_flagged if count(ID002.deny) == 1 with input as bad_pod

test_missing_limits_flags_cpu_and_memory if count(ID003.deny) == 2 with input as bad_pod

test_untagged_image_is_flagged if count(ID004.deny) == 1 with input as bad_pod

test_registry_port_is_not_a_tag if {
	registry_no_tag := object.union(bad_pod, {"spec": {"containers": [{"name": "app", "image": "registry.example:5000/app"}]}})
	count(ID004.deny) == 1 with input as registry_no_tag
}

test_digest_pinned_image_passes if {
	pinned := object.union(bad_pod, {"spec": {"containers": [{"name": "app", "image": "nginx:latest@sha256:0000000000000000000000000000000000000000000000000000000000000000"}]}})
	count(ID004.deny) == 0 with input as pinned
}

test_host_network_is_flagged if count(ID005.deny) == 1 with input as bad_pod

test_pod_level_run_as_non_root_counts if {
	pod_level := {"kind": "Pod", "metadata": {"name": "p"}, "spec": {
		"securityContext": {"runAsNonRoot": true},
		"containers": [{"name": "app", "image": "nginx:1.27"}],
	}}
	count(ID001.deny) == 0 with input as pod_level
}

test_system_masters_binding_is_flagged if {
	binding := {"kind": "ClusterRoleBinding", "metadata": {"name": "oops"}, "subjects": [{"kind": "Group", "name": "system:masters"}]}
	count(ID006.deny) == 1 with input as binding
}

test_other_group_binding_passes if {
	binding := {"kind": "ClusterRoleBinding", "metadata": {"name": "ok"}, "subjects": [{"kind": "Group", "name": "devs"}]}
	count(ID006.deny) == 0 with input as binding
}
