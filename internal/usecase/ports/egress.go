package ports

import "net/netip"

// EgressRule is one egress decision: allow or deny traffic to Net on Ports (empty Ports
// = all ports). Rules are matched in order; an EgressPolicy is default-DENY, so only
// explicit allow rules open anything and deny rules (out-of-scope) are ordered first.
type EgressRule struct {
	Allow bool
	Net   netip.Prefix
	Ports []uint16 // nil/empty = all ports
}

// DomainRule defers a hostname rule until sandbox setup resolves and pins it.
// Ports follows EgressRule semantics: empty covers every port; otherwise it
// constrains each resolved IP to the declared TCP/UDP ports. URL allows carry
// their effective port, while out-of-scope URL carve-outs use empty Ports so the
// resolved host is denied on every port.
type DomainRule struct {
	Host  string
	Ports []uint16
}

// EgressPolicy is an ordered, default-deny ruleset compiled from engagement
// scope. It lives in ports so the usecase compiler and infrastructure applier
// both depend inward on the shared contract. AllowDomains and DenyDomains remain
// for hostname-wide callers; the structured rules preserve URL port semantics
// until run-start resolution and pinning.
type EgressPolicy struct {
	Rules            []EgressRule
	AllowDomains     []string // hostname-wide in-scope domains to resolve + allow
	DenyDomains      []string // hostname-wide out-of-scope domains to resolve + deny
	AllowDomainRules []DomainRule
	DenyDomainRules  []DomainRule
}
