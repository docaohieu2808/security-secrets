package lib.rbac

high_risk_verbs := {"create", "update", "patch", "delete", "deletecollection", "*"}

high_risk_resources := {
	"secrets", "pods/exec", "pods/attach", "nodes",
	"clusterroles", "clusterrolebindings", "roles", "rolebindings",
	"*",
}

# rule_is_high_risk(rule): a PolicyRule that writes to a sensitive resource.
rule_is_high_risk(rule) if {
	some verb in rule.verbs
	verb in high_risk_verbs
	some resource in rule.resources
	resource in high_risk_resources
}

# binds_to_system_masters(binding): system:masters bypasses RBAC authorization entirely.
binds_to_system_masters(binding) if {
	some subject in binding.subjects
	subject.kind == "Group"
	subject.name == "system:masters"
}

# is_wildcard_role(role): `*` on verbs, resources and apiGroups, i.e. cluster-admin.
is_wildcard_role(role) if {
	some rule in role.rules
	"*" in rule.verbs
	"*" in rule.resources
	"*" in rule.apiGroups
}
