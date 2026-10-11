package safehttp

import "net/netip"

// neverDestination lists the IANA special-purpose ranges that are never a legitimate destination
// for an outbound connection, whatever a Policy allows: they are not globally reachable, and
// they are not the private-use ranges an operator may open with Policy.AllowPrivate. Loopback is
// listed too; only Policy.AllowLoopback, reserved for operator-configured endpoints, admits it.
//
// Sources: the IANA IPv4 and IPv6 Special-Purpose Address Registries.
var neverDestination = mustPrefixes(
	// IPv4
	"0.0.0.0/8",       // "this network"
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link local, including the 169.254.169.254 cloud metadata endpoint
	"100.64.0.0/10",   // shared address space (CGNAT), including Alibaba's 100.100.100.200 metadata
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // documentation (TEST-NET-1)
	"192.88.99.0/24",  // deprecated 6to4 relay anycast
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // documentation (TEST-NET-2)
	"203.0.113.0/24",  // documentation (TEST-NET-3)
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, including 255.255.255.255 limited broadcast
	// IPv6
	"::/96",          // unspecified, loopback and deprecated IPv4-compatible addresses
	"64:ff9b::/96",   // NAT64 well-known prefix: translates to an arbitrary IPv4 address
	"64:ff9b:1::/48", // NAT64 local-use prefix
	"100::/64",       // discard-only
	"2001::/32",      // Teredo: embeds an IPv4 address
	"2001:db8::/32",  // documentation
	"2002::/16",      // 6to4: embeds an IPv4 address
	"3fff::/20",      // documentation
	"fe80::/10",      // link local
	"fec0::/10",      // deprecated site local
	"ff00::/8",       // multicast
)

// cloudMetadata lists metadata endpoints that sit inside a private-use range and would otherwise
// be admitted by Policy.AllowPrivate. They stay blocked for every policy.
var cloudMetadata = mustPrefixes(
	"fd00:ec2::/32", // AWS instance metadata over IPv6 (fd00:ec2::254), inside fc00::/7
)

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, len(values))
	for i, value := range values {
		prefixes[i] = netip.MustParsePrefix(value)
	}
	return prefixes
}

func containedIn(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
