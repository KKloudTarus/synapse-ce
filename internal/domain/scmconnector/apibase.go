package scmconnector

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// maxAPIBaseLength bounds a stored API base. A real forge API base is far shorter.
const maxAPIBaseLength = 512

// selfHostedAPISuffix is the REST path a self-hosted forge serves its API under. GitHub Enterprise
// Server answers at https://<host>/api/v3 and self-managed GitLab at https://<host>/api/v4, optionally
// below a relative URL root (https://<host>/gitlab/api/v4). Only these providers take an API base.
var selfHostedAPISuffix = map[Provider]string{
	ProviderGitHub: "/api/v3",
	ProviderGitLab: "/api/v4",
}

// saasHosts are the public forge hosts whose API is built in. An API base on one of them would only
// redirect that host's token, so it is refused.
var saasHosts = map[string]bool{
	"github.com":    true,
	"gitlab.com":    true,
	"bitbucket.org": true,
	"dev.azure.com": true,
}

// NormalizeAPIBase validates the optional REST API base of a self-hosted forge and returns its
// canonical form. An empty value means the provider's public SaaS API and is returned as "".
//
// The base must be an https URL with no userinfo, query or fragment, a clean path ending in the
// provider's API suffix, and a host (with port) equal to the connector host. Binding the API origin
// to the connector host means the token stored for a host is only ever presented to that host.
// Whether the host is on the operator's allowlist is decided by the caller (selfhosted.Rules).
func NormalizeAPIBase(provider Provider, host, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if len(raw) > maxAPIBaseLength {
		return "", fmt.Errorf("%w: API base URL must be at most %d characters", shared.ErrValidation, maxAPIBaseLength)
	}
	switch provider {
	case ProviderGitHub, ProviderGitLab:
	case ProviderBitbucket:
		return "", fmt.Errorf("%w: Bitbucket Data Center is not supported for pull request decoration yet; leave the API base URL empty", shared.ErrValidation)
	default:
		return "", fmt.Errorf("%w: an API base URL applies only to GitHub Enterprise Server and self-managed GitLab connectors", shared.ErrValidation)
	}
	if saasHosts[host] {
		return "", fmt.Errorf("%w: %s uses its built-in API; leave the API base URL empty", shared.ErrValidation, host)
	}
	if strings.ContainsAny(raw, " \t\r\n\\") {
		return "", fmt.Errorf("%w: API base URL must not contain whitespace or backslashes", shared.ErrValidation)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" {
		return "", fmt.Errorf("%w: API base URL must be an absolute https URL", shared.ErrValidation)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", fmt.Errorf("%w: API base URL must use https", shared.ErrValidation)
	}
	if u.User != nil {
		return "", fmt.Errorf("%w: API base URL must not contain credentials", shared.ErrValidation)
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(raw, "?#") {
		return "", fmt.Errorf("%w: API base URL must not have a query or fragment", shared.ErrValidation)
	}
	apiHost, err := NormalizeHost(u.Host)
	if err != nil {
		return "", err
	}
	if apiHost != host {
		return "", fmt.Errorf("%w: API base URL host %q must match the connector host %q", shared.ErrValidation, apiHost, host)
	}
	apiPath, err := cleanAPIPath(u, selfHostedAPISuffix[provider])
	if err != nil {
		return "", err
	}
	return (&url.URL{Scheme: "https", Host: urlAuthority(apiHost), Path: apiPath}).String(), nil
}

// cleanAPIPath requires a plain, already-clean path that ends in suffix. Percent-encoding, dot
// segments and empty segments are refused rather than normalized, so what is stored is exactly
// what the operator reads back.
func cleanAPIPath(u *url.URL, suffix string) (string, error) {
	p := strings.TrimSuffix(u.Path, "/")
	if u.RawPath != "" || strings.Contains(u.EscapedPath(), "%") {
		return "", fmt.Errorf("%w: API base URL path must not be percent-encoded", shared.ErrValidation)
	}
	// A clean absolute path has no empty or dot segments. The suffix starts with "/", so it always
	// matches whole segments ("/xapi/v3" does not end in "/api/v3").
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p || !strings.HasSuffix(p, suffix) {
		return "", fmt.Errorf("%w: API base URL path must be clean and end in %s", shared.ErrValidation, suffix)
	}
	for _, segment := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if strings.ContainsAny(segment, "@;:") {
			return "", fmt.Errorf("%w: API base URL path contains an unsafe segment", shared.ErrValidation)
		}
	}
	return p, nil
}

// urlAuthority turns a NormalizeHost key back into a URL authority, bracketing a bare IPv6 literal.
func urlAuthority(hostKey string) string {
	if ip := net.ParseIP(hostKey); ip != nil && ip.To4() == nil {
		return "[" + hostKey + "]"
	}
	return hostKey
}

// SetAPIBase validates raw with NormalizeAPIBase for this connector's provider and host and stores
// the canonical form. An empty value clears the base (public SaaS API).
func (c *Connector) SetAPIBase(raw string) error {
	base, err := NormalizeAPIBase(c.Provider, c.Host, raw)
	if err != nil {
		return err
	}
	c.APIBase = base
	return nil
}
