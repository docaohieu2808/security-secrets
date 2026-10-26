package lib.networking

# has_networkpolicy(namespace, policies): `policies` is a list of NetworkPolicy objects.
has_networkpolicy(namespace, policies) if {
	some policy in policies
	policy.metadata.namespace == namespace
}

# is_default_deny(policy): empty podSelector, both policy types, no allow rules.
is_default_deny(policy) if {
	policy.spec.podSelector == {}
	"Ingress" in policy.spec.policyTypes
	"Egress" in policy.spec.policyTypes
	not policy.spec.ingress
	not policy.spec.egress
}

port_in_range(port, min, max) if {
	port >= min
	port <= max
}

# SSH, Telnet, RDP, VNC and the Docker daemon (plain/TLS/legacy).
sensitive_ports := {22, 23, 3389, 5900, 2375, 2376, 4243}

is_sensitive_port(port) if port in sensitive_ports
