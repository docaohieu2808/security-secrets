# Conftest policy built on the lib.* packages in ../rego/lib.
#
#   conftest test fixtures/good --policy policy --policy rego/lib     (passes)
#   conftest test fixtures/bad  --policy policy --policy rego/lib     (fails: 5 denies)
package main

import data.lib.kubernetes
import data.lib.rbac

deny contains msg if {
	kubernetes.is_pod(input)
	some c in kubernetes.get_containers(input)
	kubernetes.is_privileged(c)
	msg := sprintf("%s/%s: container %q is privileged", [input.kind, input.metadata.name, c.name])
}

deny contains msg if {
	kubernetes.is_pod(input)
	some c in kubernetes.get_containers(input)
	kubernetes.uses_latest_tag(c)
	msg := sprintf("%s/%s: container %q uses a mutable image tag (%s)", [input.kind, input.metadata.name, c.name, c.image])
}

deny contains msg if {
	kubernetes.is_pod(input)
	some c in kubernetes.get_containers(input)
	kubernetes.missing_resource_limits(c)
	msg := sprintf("%s/%s: container %q has no cpu/memory limits", [input.kind, input.metadata.name, c.name])
}

deny contains msg if {
	kubernetes.is_pod(input)
	some c in kubernetes.get_containers(input)
	kubernetes.has_dangerous_capability(c)
	msg := sprintf("%s/%s: container %q adds a dangerous Linux capability", [input.kind, input.metadata.name, c.name])
}

deny contains msg if {
	input.kind in {"ClusterRole", "Role"}
	rbac.is_wildcard_role(input)
	msg := sprintf("%s/%s grants * on * (cluster-admin equivalent)", [input.kind, input.metadata.name])
}
