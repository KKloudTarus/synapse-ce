package selfhosted

import (
	"net/url"
	"strings"
)

// SameOrigin reports whether two URLs share scheme, host and effective port. A self-hosted
// provider follows or stores a URL from its own responses (a job link, a run link, an issue link)
// only when it has the configured endpoint's origin; otherwise a compromised or misconfigured
// server could steer the control plane, or a console link, to another host.
func SameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Hostname(), right.Hostname()) &&
		EffectivePort(left) == EffectivePort(right)
}

// EffectivePort returns the URL's port, or the scheme's default for http and https, or "".
func EffectivePort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	switch strings.ToLower(value.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}
