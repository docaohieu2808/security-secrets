package lib.networking_test

import data.lib.networking

default_deny := {"spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}}

test_default_deny if {
	networking.is_default_deny(default_deny)
}

test_not_default_deny_when_rules_present if {
	not networking.is_default_deny(object.union(default_deny, {"spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"], "egress": [{}]}}))
}

test_not_default_deny_when_selector_set if {
	not networking.is_default_deny({"spec": {"podSelector": {"matchLabels": {"a": "b"}}, "policyTypes": ["Ingress", "Egress"]}})
}

test_has_networkpolicy if {
	pols := [{"metadata": {"namespace": "shop"}}]
	networking.has_networkpolicy("shop", pols)
	not networking.has_networkpolicy("other", pols)
}

test_ports if {
	networking.port_in_range(8080, 1024, 65535)
	not networking.port_in_range(80, 1024, 65535)
	networking.is_sensitive_port(22)
	not networking.is_sensitive_port(8080)
}
