// Package scmconnector is the aggregate for a tenant-scoped source-control credential
// binding: a git host and the username a personal access token authenticates as, so the
// server can clone a PRIVATE repository on that host. The token itself is NEVER a field
// on this type; it is sealed in the connector store (AES-256-GCM) and resolved only at
// clone time. A connector is matched to a clone URL by Host, server-side, so a scan can
// never choose which credential to present.
package scmconnector

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"golang.org/x/net/idna"
)

// Provider names the source-control system a connector authenticates against. It selects
// the sensible default git username when the operator does not set one, and drives the
// provider badge in the UI; it does not change how the token is presented (HTTP basic
// over https for every provider in v1).
type Provider string

const (
	ProviderGitHub    Provider = "github"
	ProviderGitLab    Provider = "gitlab"
	ProviderBitbucket Provider = "bitbucket"
	ProviderGeneric   Provider = "generic"
)

// Valid reports whether p is a known provider.
func (p Provider) Valid() bool {
	switch p {
	case ProviderGitHub, ProviderGitLab, ProviderBitbucket, ProviderGeneric:
		return true
	default:
		return false
	}
}

// defaultUsername is the git username a provider's token authenticates as when the
// operator leaves it blank. GitHub ignores the username for a PAT but requires it to be
// non-empty; GitLab expects "oauth2"; Bitbucket and a generic host have no safe default,
// so the operator must supply one.
func (p Provider) defaultUsername() string {
	switch p {
	case ProviderGitHub:
		return "x-access-token"
	case ProviderGitLab:
		return "oauth2"
	default:
		return ""
	}
}

// AuthKind is how the connector authenticates. v1 supports a personal access token
// (presented as the HTTP basic password over https). The type is modelled so a GitHub
// App or OAuth flow can be added later without a schema change.
type AuthKind string

const (
	AuthPAT AuthKind = "pat"
)

// Valid reports whether a is a supported auth kind.
func (a AuthKind) Valid() bool { return a == AuthPAT }

var (
	namePattern = regexp.MustCompile(`^[\w][\w .-]{0,63}$`)
	// hostPattern accepts a DNS hostname (labels of letters/digits/hyphen, dot-separated).
	// A host with no dot (a bare label) is refused: a private git host is a real FQDN, and
	// a bare label is almost always an internal name the acquirer would refuse anyway.
	hostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// Connector is a tenant-scoped source-control credential binding. The token never lives
// on this type; the store seals it separately. Matching to a clone URL is by Host.
type Connector struct {
	ID        shared.ID `json:"id"`
	TenantID  shared.ID `json:"tenant_id"`
	Name      string    `json:"name"`
	Provider  Provider  `json:"provider"`
	Host      string    `json:"host"`
	Username  string    `json:"username"`
	AuthKind  AuthKind  `json:"auth_kind"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NewConnector validates and normalizes a connector. host accepts either a bare host
// ("github.com") or an https URL ("https://github.com/org"); only the host is kept,
// lowercased and IDNA-encoded. username defaults per provider when blank. The token is
// NOT passed here; it is sealed by the store.
func NewConnector(id, tenantID shared.ID, name string, provider Provider, host, username string, authKind AuthKind, now time.Time) (*Connector, error) {
	if id.IsZero() {
		return nil, fmt.Errorf("%w: connector id is required", shared.ErrValidation)
	}
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: connector tenant is required", shared.ErrValidation)
	}
	name = strings.TrimSpace(name)
	if !namePattern.MatchString(name) {
		return nil, fmt.Errorf("%w: connector name must be 1-64 chars of letters, digits, space, dot or hyphen", shared.ErrValidation)
	}
	if !provider.Valid() {
		return nil, fmt.Errorf("%w: unknown connector provider %q", shared.ErrValidation, provider)
	}
	if !authKind.Valid() {
		return nil, fmt.Errorf("%w: unsupported connector auth kind %q", shared.ErrValidation, authKind)
	}
	normHost, err := NormalizeHost(host)
	if err != nil {
		return nil, err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		username = provider.defaultUsername()
	}
	if username == "" {
		return nil, fmt.Errorf("%w: a git username is required for a %s connector", shared.ErrValidation, provider)
	}
	if strings.ContainsAny(username, " \t\r\n:/@") {
		return nil, fmt.Errorf("%w: connector username must not contain whitespace or : / @", shared.ErrValidation)
	}
	return &Connector{
		ID: id, TenantID: tenantID, Name: name, Provider: provider,
		Host: normHost, Username: username, AuthKind: authKind,
		CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}, nil
}

// IsInternalHost reports whether a normalized host is an IP literal in a range a source-control host
// should never be: loopback, link-local, or unspecified (the cloud metadata service, 127.0.0.1, ::1).
// A DNS name returns false here; the acquirer resolves and rejects those at clone time. Used to refuse
// storing a connector whose credential could be aimed at an internal address (SSRF/exfiltration guard).
func IsInternalHost(host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// NormalizeHost reduces an operator-entered host or https URL to a canonical, lowercase,
// IDNA-encoded hostname (no scheme, port, path, or userinfo). It is the single function
// both connector creation and clone-time matching use, so a connector added as
// "GitHub.com" matches a clone of "https://github.com/org/repo.git".
func NormalizeHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("%w: connector host is required", shared.ErrValidation)
	}
	// A bare IP literal (v4 or unbracketed v6) is what gitHost yields at clone time, so canonicalize it
	// here directly: url.Parse("https://2001:db8::1") mis-reads the ":db8" as a port and fails, which would
	// leave a stored IPv6 connector unresolvable. ParseIP handles both families.
	if ip := net.ParseIP(raw); ip != nil {
		return strings.ToLower(ip.String()), nil
	}
	// Accept a full URL and keep only the host; accept a bare host by parsing it as an
	// authority. url.Parse("github.com") puts it in Path, so prepend a scheme when absent.
	candidate := raw
	if !strings.Contains(raw, "://") {
		candidate = "https://" + raw
	}
	u, err := url.Parse(candidate)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%w: connector host is not a valid hostname", shared.ErrValidation)
	}
	host := strings.ToLower(u.Hostname()) // drops any :port and userinfo
	// A self-hosted git host may be reachable only by IP literal, so accept one (v4 or a bracket-stripped
	// v6) canonicalized the same way as the bare-IP branch above, so "[2001:DB8::1]" and "2001:db8::1"
	// resolve to one key.
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("%w: connector host is not a valid hostname", shared.ErrValidation)
	}
	if !hostPattern.MatchString(ascii) {
		return "", fmt.Errorf("%w: connector host must be a fully-qualified hostname or an IP", shared.ErrValidation)
	}
	return ascii, nil
}
