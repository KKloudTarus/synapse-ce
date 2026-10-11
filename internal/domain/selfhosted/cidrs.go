package selfhosted

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// privateUse are the ranges SYNAPSE_INTEGRATION_ALLOW_PRIVATE_NETWORK opens: RFC 1918 and IPv6
// unique-local. They match what safehttp treats as private.
var privateUse = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// ParsePrivateCIDRs parses the CIDRs that private-network integrations are limited to. Every CIDR
// must sit inside a private-use range: the setting only narrows the private-network switch, so a
// CIDR covering loopback, link-local, metadata or a public range is a mistake and is refused
// rather than silently ignored.
func ParsePrivateCIDRs(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := parsePrivateCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", value, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func parsePrivateCIDR(raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return netip.Prefix{}, errors.New("must be a CIDR such as 10.20.0.0/16")
	}
	if prefix.Addr().Is4In6() {
		return netip.Prefix{}, errors.New("write IPv4 ranges in IPv4 form")
	}
	prefix = prefix.Masked()
	if !insidePrivateUse(prefix) {
		return netip.Prefix{}, errors.New("must be inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or fc00::/7")
	}
	return prefix, nil
}

func insidePrivateUse(prefix netip.Prefix) bool {
	for _, private := range privateUse {
		if private.Bits() <= prefix.Bits() && private.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func isPrivateUse(address netip.Addr) bool {
	address = address.Unmap()
	for _, private := range privateUse {
		if private.Contains(address) {
			return true
		}
	}
	return false
}
