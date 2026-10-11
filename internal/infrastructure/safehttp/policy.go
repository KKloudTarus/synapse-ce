package safehttp

import "net/netip"

// Policy decides which destinations an outbound connection may reach. The zero value admits only
// globally reachable addresses. Every field widens or narrows that default explicitly; nothing a
// Policy allows can reach a cloud metadata endpoint or a range in neverDestination other than
// loopback.
type Policy struct {
	// AllowPrivate admits private-use addresses (RFC 1918 and RFC 4193 unique-local), for an
	// endpoint an operator placed on an internal network.
	AllowPrivate bool
	// PrivateCIDRs, when not empty, narrows AllowPrivate to these prefixes.
	PrivateCIDRs []netip.Prefix
	// AllowLoopback admits loopback. Only endpoints an operator configures, such as the SMTP relay
	// read from the environment, may set it; a tenant-configured destination never does.
	AllowLoopback bool
	// AllowHost, when set, must approve the host and port before the host is resolved. It is how
	// an operator host allowlist is enforced on every connection.
	AllowHost func(host, port string) bool
}

// AllowsAddress lets protocols that reject mixed DNS answers apply the same destination policy
// to every resolved address before dialing any of them.
func (p Policy) AllowsAddress(address netip.Addr) bool { return p.permits(address) }

// OperatorPolicy is for endpoints an operator configures outside any tenant's control. It admits
// private and loopback addresses, because such relays often run on the host or an internal
// network, and still refuses cloud metadata and every other special-purpose range.
func OperatorPolicy() Policy {
	return Policy{AllowPrivate: true, AllowLoopback: true}
}

// permitsHost reports whether the policy admits host and port before resolution.
func (p Policy) permitsHost(host, port string) bool {
	return p.AllowHost == nil || p.AllowHost(host, port)
}

// permits reports whether the policy admits a resolved address. IPv4-mapped IPv6 addresses are
// judged as the IPv4 address they carry.
func (p Policy) permits(address netip.Addr) bool {
	address = address.Unmap()
	switch {
	case !address.IsValid() || containedIn(cloudMetadata, address):
		return false
	case address.IsLoopback():
		return p.AllowLoopback
	case containedIn(neverDestination, address):
		return false
	case address.IsPrivate():
		return p.AllowPrivate && (len(p.PrivateCIDRs) == 0 || containedIn(p.PrivateCIDRs, address))
	}
	return true
}
