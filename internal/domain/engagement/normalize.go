package engagement

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"golang.org/x/net/idna"
)

// URLIdentity is the canonical network identity of an HTTP(S) URL. URL preserves
// the canonical URL for execution; Port is always explicit so authorization can
// distinguish http:80 from https:443 even when a URL omits its port.
type URLIdentity struct {
	URL    string
	Scheme string
	Host   string
	Port   uint16
}

// NormalizeDomain returns the canonical ASCII (IDNA lookup) representation of a
// DNS domain name. It accepts a single trailing DNS root dot, but never an IP
// literal or a wildcard pattern.
func NormalizeDomain(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", validationError("domain is required")
	}
	if hasControlCharacter(v) {
		return "", validationError("domain contains a control character")
	}
	v = strings.TrimSuffix(v, ".")
	if v == "" {
		return "", validationError("domain is required")
	}
	if _, err := netip.ParseAddr(v); err == nil {
		return "", validationError("domain must not be an IP literal")
	}

	ascii, err := idna.Lookup.ToASCII(v)
	if err != nil {
		return "", validationError("invalid internationalized domain name")
	}
	ascii = strings.ToLower(ascii)
	if err := validateASCIIDomain(ascii); err != nil {
		return "", err
	}
	return ascii, nil
}

// NormalizeDomainPattern returns a canonical domain scope pattern. Wildcards are
// restricted to a single leading "*." and are intentionally not accepted by
// NormalizeDomain, observations, or execution targets.
func NormalizeDomainPattern(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if strings.HasPrefix(v, "*.") {
		suffix, err := NormalizeDomain(v[2:])
		if err != nil {
			return "", err
		}
		return "*." + suffix, nil
	}
	if strings.Contains(v, "*") {
		return "", validationError("domain wildcard must use a leading *.")
	}
	return NormalizeDomain(v)
}

// NormalizeHost returns the canonical comparison representation of either an IP
// literal or a DNS domain. Bracketed IPv6 is accepted only as a host literal;
// endpoint parsing belongs to NormalizeEndpoint.
func NormalizeHost(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", validationError("host is required")
	}
	if hasControlCharacter(v) {
		return "", validationError("host contains a control character")
	}
	if strings.HasPrefix(v, "[") || strings.HasSuffix(v, "]") {
		if len(v) < 3 || !strings.HasPrefix(v, "[") || !strings.HasSuffix(v, "]") {
			return "", validationError("invalid bracketed host")
		}
		v = v[1 : len(v)-1]
	}
	if addr, err := netip.ParseAddr(v); err == nil {
		return addr.String(), nil
	}
	return NormalizeDomain(v)
}

// NormalizeEndpoint parses and canonicalizes a host:port endpoint. It accepts
// bracketed IPv6 only where the port makes brackets mandatory and always renders
// IPv6 with net.JoinHostPort.
func NormalizeEndpoint(raw string) (host string, port uint16, endpoint string, err error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", 0, "", validationError("endpoint is required")
	}
	if hasControlCharacter(v) {
		return "", 0, "", validationError("endpoint contains a control character")
	}

	hostPart, portPart, err := net.SplitHostPort(v)
	if err != nil || hostPart == "" || portPart == "" {
		return "", 0, "", validationError("endpoint must be an unambiguous host:port")
	}
	n, err := strconv.ParseUint(portPart, 10, 16)
	if err != nil || n == 0 {
		return "", 0, "", validationError("endpoint port must be between 1 and 65535")
	}
	host, err = NormalizeHost(hostPart)
	if err != nil {
		return "", 0, "", err
	}
	port = uint16(n)
	return host, port, net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// NormalizeURL parses an absolute HTTP(S) URL into the canonical identity used
// for scope authorization and execution. The canonical URL retains its path and
// query but canonicalizes its scheme, hostname, and explicit port spelling.
func NormalizeURL(raw string) (URLIdentity, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return URLIdentity{}, validationError("URL is required")
	}
	if hasControlCharacter(v) {
		return URLIdentity{}, validationError("URL contains a control character")
	}

	u, err := url.Parse(v)
	if err != nil || u == nil || !u.IsAbs() || u.Opaque != "" || u.Host == "" {
		return URLIdentity{}, validationError("invalid absolute URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return URLIdentity{}, validationError("URL scheme must be http or https")
	}
	if u.User != nil {
		return URLIdentity{}, validationError("URL must not include userinfo")
	}
	if u.Hostname() == "" {
		return URLIdentity{}, validationError("URL host is required")
	}

	host, err := NormalizeHost(u.Hostname())
	if err != nil {
		return URLIdentity{}, err
	}
	explicitPort, err := urlPort(u)
	if err != nil {
		return URLIdentity{}, err
	}
	port := explicitPort
	if port == 0 {
		if scheme == "http" {
			port = 80
		} else {
			port = 443
		}
	}

	u.Scheme = scheme
	u.Host = canonicalURLHost(host, explicitPort)
	return URLIdentity{URL: u.String(), Scheme: scheme, Host: host, Port: port}, nil
}

// NormalizeTarget returns a canonical target. scopeEntry controls the only
// context where a wildcard domain is valid: a stored domain scope pattern.
func NormalizeTarget(t Target, scopeEntry bool) (Target, error) {
	v := strings.TrimSpace(t.Value)
	if v == "" {
		return Target{}, validationError("scope target value is required")
	}

	out := Target{Kind: t.Kind}
	switch t.Kind {
	case TargetDomain:
		var err error
		if scopeEntry {
			out.Value, err = NormalizeDomainPattern(v)
		} else {
			out.Value, err = NormalizeDomain(v)
		}
		if err != nil {
			return Target{}, err
		}
	case TargetIP:
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return Target{}, validationError("invalid IP address %q", t.Value)
		}
		out.Value = addr.String()
	case TargetCIDR:
		pfx, err := netip.ParsePrefix(v)
		if err != nil {
			return Target{}, validationError("invalid CIDR %q", t.Value)
		}
		out.Value = pfx.Masked().String()
	case TargetURL:
		identity, err := NormalizeURL(v)
		if err != nil {
			return Target{}, err
		}
		out.Value = identity.URL
	case TargetRepo, TargetImage:
		out.Value = v
	default:
		return Target{}, validationError("unknown scope target kind %q", t.Kind)
	}
	return out, nil
}

func validateASCIIDomain(domain string) error {
	if len(domain) > 253 {
		return validationError("domain exceeds 253 bytes")
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			return validationError("domain contains an empty label")
		}
		if len(label) > 63 {
			return validationError("domain label exceeds 63 bytes")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return validationError("domain label must not begin or end with a hyphen")
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return validationError("domain contains an invalid character")
			}
		}
	}
	return nil
}

func urlPort(u *url.URL) (uint16, error) {
	portText := u.Port()
	if portText != "" {
		n, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || n == 0 {
			return 0, validationError("URL port must be between 1 and 65535")
		}
		return uint16(n), nil
	}

	// A parsed authority differs from its hostname only for a bracketed IPv6
	// literal or a valid host:port pair. net.SplitHostPort distinguishes those
	// structured forms from malformed authorities such as example.com:abc.
	if u.Host == u.Hostname() {
		return 0, nil
	}
	if _, _, err := net.SplitHostPort(u.Host); err == nil {
		return 0, validationError("URL port must be between 1 and 65535")
	}
	if strings.HasPrefix(u.Host, "[") && strings.HasSuffix(u.Host, "]") {
		if _, err := netip.ParseAddr(u.Hostname()); err == nil {
			return 0, nil
		}
	}
	return 0, validationError("invalid URL authority")
}

func canonicalURLHost(host string, explicitPort uint16) string {
	if explicitPort != 0 {
		return net.JoinHostPort(host, strconv.Itoa(int(explicitPort)))
	}
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
		return "[" + host + "]"
	}
	return host
}

func hasControlCharacter(v string) bool {
	if !utf8.ValidString(v) {
		return true
	}
	for _, r := range v {
		if r <= 0x1f || r == 0x7f {
			return true
		}
	}
	return false
}

func validationError(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{shared.ErrValidation}, args...)...)
}
