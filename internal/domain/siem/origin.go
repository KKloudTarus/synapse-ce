package siem

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Origin is a normalized https://host[:port] with no userinfo, path, query,
// or fragment. The path or index lives on the sink target, not here.
type Origin struct {
	Scheme string
	Host   string
	Port   string
}

// String returns the canonical origin.
func (o Origin) String() string {
	if o.Port == "" {
		if strings.Contains(o.Host, ":") {
			return o.Scheme + "://[" + o.Host + "]"
		}
		return o.Scheme + "://" + o.Host
	}
	return o.Scheme + "://" + net.JoinHostPort(o.Host, o.Port)
}

// Same reports whether two origins are the same scheme, host, and port.
func (o Origin) Same(other Origin) bool {
	return strings.EqualFold(o.Scheme, other.Scheme) && strings.EqualFold(o.Host, other.Host) && o.Port == other.Port
}

// ParseOrigin rejects anything that is not a public https origin. IP literals
// in private, loopback, link-local, multicast, or metadata space are rejected
// here. Name resolution is checked again at dial time by the shared HTTP guard.
func ParseOrigin(raw string) (Origin, error) {
	return parseOrigin(raw, "https", false)
}

// ParseOriginFor applies the transport required by provider.
func ParseOriginFor(provider Provider, raw string) (Origin, error) {
	if provider == ProviderSyslogTLS {
		return parseOrigin(raw, "tls", true)
	}
	return ParseOrigin(raw)
}

func parseOrigin(raw, scheme string, requirePort bool) (Origin, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return Origin{}, fmt.Errorf("%w: sink origin is not a URL", shared.ErrValidation)
	}
	if parsed.Scheme != scheme || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return Origin{}, fmt.Errorf("%w: sink origin must be %s://host[:port] without userinfo, path, query, or fragment", shared.ErrValidation, scheme)
	}
	host := parsed.Hostname()
	if host == "" || strings.Contains(host, "*") || strings.ContainsAny(host, " \t\r\n") {
		return Origin{}, fmt.Errorf("%w: sink origin host is invalid", shared.ErrValidation)
	}
	if ForbiddenHost(host) {
		return Origin{}, fmt.Errorf("%w: sink origin host is not allowed", shared.ErrValidation)
	}
	port := parsed.Port()
	if requirePort && port == "" {
		return Origin{}, fmt.Errorf("%w: sink origin port is required", shared.ErrValidation)
	}
	if port != "" {
		n := 0
		for _, r := range port {
			if r < '0' || r > '9' {
				return Origin{}, fmt.Errorf("%w: sink origin port is invalid", shared.ErrValidation)
			}
			n = n*10 + int(r-'0')
		}
		if n < 1 || n > 65535 {
			return Origin{}, fmt.Errorf("%w: sink origin port is invalid", shared.ErrValidation)
		}
	}
	return Origin{Scheme: scheme, Host: host, Port: port}, nil
}

// ForbiddenHost reports whether host is an IP or name that must never be a
// sink, including cloud metadata endpoints.
func ForbiddenHost(host string) bool {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	switch name {
	case "metadata", "metadata.google.internal", "instance-data", "instance-data.ec2.internal":
		return true
	}
	addr, err := netip.ParseAddr(name)
	if err != nil {
		return false
	}
	return BlockedAddr(addr)
}

// BlockedAddr reports whether address must not be dialed for a SIEM sink.
func BlockedAddr(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsPrivate() || address.IsInterfaceLocalMulticast() {
		return true
	}
	if carrierGradeNAT.Contains(address) || sixToFour.Contains(address) || nat64WellKnown.Contains(address) {
		return true
	}
	return false
}

var (
	carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")
	sixToFour       = netip.MustParsePrefix("2002::/16")
	nat64WellKnown  = netip.MustParsePrefix("64:ff9b::/96")
)

// HostAllowed reports whether host is on an optional exact allowlist.
// An empty allowlist does not permit private addresses; those are rejected by
// ForbiddenHost and again at dial time. Wildcards are not accepted.
func HostAllowed(host string, allow []string) error {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ForbiddenHost(host) {
		return fmt.Errorf("%w: sink host is blocked", shared.ErrValidation)
	}
	if len(allow) == 0 {
		return nil
	}
	if len(allow) > MaxAllowHosts {
		return fmt.Errorf("%w: sink host allowlist is too long", shared.ErrValidation)
	}
	for _, item := range allow {
		item = strings.TrimSpace(item)
		if item == "" || strings.Contains(item, "*") || strings.Contains(item, "/") {
			return fmt.Errorf("%w: sink host allowlist entries must be exact hosts", shared.ErrValidation)
		}
		if strings.EqualFold(strings.TrimSuffix(item, "."), host) {
			return nil
		}
	}
	return fmt.Errorf("%w: sink host is not on the allowlist", shared.ErrValidation)
}
