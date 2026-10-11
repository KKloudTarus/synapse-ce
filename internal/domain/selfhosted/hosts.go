package selfhosted

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// HostAllowlist is the set of hosts a self-hosted provider may reach. The zero value is empty and
// admits every host, which keeps the behaviour of a deployment that does not set an allowlist.
type HostAllowlist struct {
	entries []hostEntry
}

// hostEntry is one allowlist entry. host is lower-case without a trailing dot, or the canonical
// text of an IP literal. A suffix entry ("*.corp.example") matches subdomains of host but not
// host itself. An empty port matches every port.
type hostEntry struct {
	host   string
	suffix bool
	port   string
}

// ParseHostAllowlist parses entries of the form "host", "host:port", "*.domain", "*.domain:port",
// "192.0.2.10", "[2001:db8::1]:8443" or a bare IPv6 literal. An empty list gives an empty
// allowlist. Entries are validated strictly so a typo fails startup instead of silently admitting
// nothing or everything.
func ParseHostAllowlist(values []string) (HostAllowlist, error) {
	entries := make([]hostEntry, 0, len(values))
	for _, value := range values {
		entry, err := parseHostEntry(value)
		if err != nil {
			return HostAllowlist{}, fmt.Errorf("entry %q: %w", value, err)
		}
		entries = append(entries, entry)
	}
	return HostAllowlist{entries: entries}, nil
}

// Empty reports whether the allowlist has no entries and therefore admits every host.
func (a HostAllowlist) Empty() bool { return len(a.entries) == 0 }

// Permits reports whether host on port is admitted. host may be a name or an IP literal, with or
// without IPv6 brackets. Its signature matches safehttp.Policy.AllowHost.
func (a HostAllowlist) Permits(host, port string) bool {
	if a.Empty() {
		return true
	}
	host = canonicalHost(host)
	for _, entry := range a.entries {
		if entry.matches(host, port) {
			return true
		}
	}
	return false
}

func (e hostEntry) matches(host, port string) bool {
	if e.port != "" && e.port != port {
		return false
	}
	if e.suffix {
		return strings.HasSuffix(host, "."+e.host)
	}
	return host == e.host
}

func parseHostEntry(raw string) (hostEntry, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" || strings.ContainsAny(value, "/@?#") {
		return hostEntry{}, errors.New("must be a host or host:port, not a URL")
	}
	host, port, err := splitEntry(value)
	if err != nil {
		return hostEntry{}, err
	}
	if port != "" {
		if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
			return hostEntry{}, errors.New("port must be between 1 and 65535")
		}
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" {
			return hostEntry{}, errors.New("IPv6 zones are not allowed")
		}
		return hostEntry{host: address.Unmap().String(), port: port}, nil
	}
	suffix := strings.HasPrefix(host, "*.")
	host = strings.TrimSuffix(strings.TrimPrefix(host, "*."), ".")
	if !validHostname(host) {
		return hostEntry{}, errors.New("host must be a DNS name, an IP literal, or *. followed by a DNS name")
	}
	return hostEntry{host: host, suffix: suffix, port: port}, nil
}

// splitEntry separates an optional port. A value with more than one colon and no brackets is a
// bare IPv6 literal without a port.
func splitEntry(value string) (host, port string, err error) {
	switch {
	case strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]"):
		return value[1 : len(value)-1], "", nil
	case strings.HasPrefix(value, "["), strings.Count(value, ":") == 1:
		host, port, err := net.SplitHostPort(value)
		if err != nil {
			return "", "", errors.New("host:port is malformed")
		}
		return host, port, nil
	default:
		return value, "", nil
	}
}

// validHostname accepts LDH labels of 1 to 63 characters, which covers every name a provider
// endpoint can have. It rejects wildcards other than the leading "*." handled by the caller.
func validHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// canonicalHost puts a host being checked into the form entries are stored in.
func canonicalHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Unmap().String()
	}
	return host
}
