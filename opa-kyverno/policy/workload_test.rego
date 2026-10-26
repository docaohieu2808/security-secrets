package main_test

import data.main

good := {"kind": "Deployment", "metadata": {"name": "ok"}, "spec": {"template": {"spec": {"containers": [{
	"name": "app",
	"image": "nginx:1.27",
	"resources": {"limits": {"cpu": "1", "memory": "1Gi"}},
}]}}}}

test_good_deployment_has_no_denies if {
	count(main.deny) == 0 with input as good
}

test_privileged_latest_unlimited_container_is_denied if {
	bad := {"kind": "Pod", "metadata": {"name": "bad"}, "spec": {"containers": [{
		"name": "app",
		"image": "nginx",
		"securityContext": {"privileged": true},
	}]}}
	count(main.deny) == 3 with input as bad
}

test_wildcard_clusterrole_is_denied if {
	role := {"kind": "ClusterRole", "metadata": {"name": "root"}, "rules": [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}]}
	count(main.deny) == 1 with input as role
}
