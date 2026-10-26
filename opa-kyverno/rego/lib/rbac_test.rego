package lib.rbac_test

import data.lib.rbac

test_high_risk_rule if {
	rbac.rule_is_high_risk({"verbs": ["get", "delete"], "resources": ["secrets"]})
	not rbac.rule_is_high_risk({"verbs": ["get", "list"], "resources": ["secrets"]})
	not rbac.rule_is_high_risk({"verbs": ["create"], "resources": ["configmaps"]})
}

test_system_masters if {
	rbac.binds_to_system_masters({"subjects": [{"kind": "Group", "name": "system:masters"}]})
	not rbac.binds_to_system_masters({"subjects": [{"kind": "User", "name": "system:masters"}]})
}

test_wildcard_role if {
	rbac.is_wildcard_role({"rules": [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}]})
	not rbac.is_wildcard_role({"rules": [{"verbs": ["*"], "resources": ["pods"], "apiGroups": [""]}]})
}
