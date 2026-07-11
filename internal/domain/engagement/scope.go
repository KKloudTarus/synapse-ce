package engagement

import (
	"fmt"
	"net/netip"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Scope defines what is in and out of bounds for an engagement.
// Scope is enforced in the execution layer, never as a single bypassable prompt/hook.
type Scope struct {
	InScope    []Target
	OutOfScope []Target
}

// TargetKind enumerates the kinds of assets an engagement can target.
type TargetKind string

const (
	TargetDomain TargetKind = "domain"
	TargetIP     TargetKind = "ip"
	TargetCIDR   TargetKind = "cidr"
	TargetURL    TargetKind = "url"
	TargetRepo   TargetKind = "repo"
	TargetImage  TargetKind = "image"
)

// Target is a single in-scope or out-of-scope asset.
type Target struct {
	Kind  TargetKind
	Value string
}

// Validate reports whether the target has a known kind and a non-empty value.
// Used when scope is created or edited so the gate never matches against a
// malformed entry.
func (t Target) Validate() error {
	v := strings.TrimSpace(t.Value)
	if v == "" {
		return fmt.Errorf("%w: scope target value is required", shared.ErrValidation)
	}
	switch t.Kind {
	case TargetCIDR:
		if _, err := netip.ParsePrefix(v); err != nil {
			return fmt.Errorf("%w: invalid CIDR %q", shared.ErrValidation, t.Value)
		}
	case TargetIP:
		if _, err := netip.ParseAddr(v); err != nil {
			return fmt.Errorf("%w: invalid IP address %q", shared.ErrValidation, t.Value)
		}
	case TargetDomain, TargetURL, TargetRepo, TargetImage:
		// non-empty value is sufficient for these kinds
	default:
		return fmt.Errorf("%w: unknown scope target kind %q", shared.ErrValidation, t.Kind)
	}
	return nil
}

// Allows reports whether a raw target value is permitted by this scope. It is a
// convenience for value-only callers (SCA repo/path/URL targets): the value is
// matched exactly, plus host-centric against any host/CIDR/wildcard scope entry.
// Out-of-scope matches always win. Prefer AllowsTarget for kind-aware requests.
func (s Scope) Allows(value string) bool {
	return s.AllowsTarget(Target{Value: value})
}

// AllowsTarget reports whether the requested target is permitted (host-centric,
// CIDR/wildcard-aware). Matching is value-exact first (preserves
// SCA repo/image semantics), then kind-aware against each scope entry: a CIDR
// entry contains an IP, a `*.example.com` entry matches subdomains, a domain
// entry matches its exact host, and a URL entry matches by host. Out-of-scope
// always wins over in-scope (fail closed). Enforced server-side before any tool
// runs.
func (s Scope) AllowsTarget(req Target) bool {
	if strings.TrimSpace(req.Value) == "" {
		return false
	}
	for _, t := range s.OutOfScope {
		if matchScopeTarget(t, req) {
			return false
		}
	}
	for _, t := range s.InScope {
		if matchScopeTarget(t, req) {
			return true
		}
	}
	return false
}

// matchScopeTarget reports whether a requested target matches a single scope
// entry. Exact value equality is tried first (case-insensitive, trimmed) so
// repo/image/local targets and identical entries always match regardless of
// kind; then the entry's kind drives host-centric matching.
func matchScopeTarget(scopeT, req Target) bool {
	sv := strings.TrimSpace(strings.ToLower(scopeT.Value))
	if sv == "" {
		return false
	}
	if rv := strings.TrimSpace(strings.ToLower(req.Value)); rv != "" && sv == rv {
		return true
	}
	if scopeT.Kind == TargetRepo && req.Kind == TargetRepo && localPathContains(scopeT.Value, req.Value) {
		return true
	}
	switch scopeT.Kind {
	case TargetCIDR:
		if pfx, err := netip.ParsePrefix(sv); err == nil {
			if ip, ok := addrOf(req.Value); ok && pfx.Contains(ip) {
				return true
			}
		}
	case TargetIP:
		if a, err := netip.ParseAddr(sv); err == nil {
			if b, ok := addrOf(req.Value); ok {
				return a == b
			}
		}
	case TargetDomain:
		return domainMatches(sv, hostOf(req.Value))
	case TargetURL:
		sh := hostOf(sv)
		return sh != "" && sh == hostOf(req.Value)
	}
	return false
}

func localPathContains(parent, child string) bool {
	p, ok := cleanLocalScopePath(parent)
	if !ok {
		return false
	}
	c, ok := cleanLocalScopePath(child)
	if !ok {
		return false
	}
	return c == p || strings.HasPrefix(c, strings.TrimRight(p, "/")+"/")
}

func cleanLocalScopePath(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	slash := filepath.ToSlash(v)
	abs := strings.HasPrefix(slash, "/") ||
		(len(slash) >= 3 && ((slash[0] >= 'a' && slash[0] <= 'z') || (slash[0] >= 'A' && slash[0] <= 'Z')) && slash[1] == ':' && slash[2] == '/')
	if !abs {
		return "", false
	}
	clean := path.Clean(slash)
	if len(clean) >= 2 && clean[1] == ':' {
		clean = strings.ToLower(clean)
	}
	return clean, true
}

// domainMatches reports whether host is covered by a domain scope pattern.
// A `*.example.com` pattern matches any subdomain (not the bare apex); a plain
// `example.com` pattern matches that exact host only (subdomains require `*.`).
func domainMatches(pattern, host string) bool {
	if host == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return pattern == host
}

// hostOf extracts the comparable host (lowercased, no scheme/userinfo/port/path)
// from a target value, for host-centric scope matching. URLs reduce to their
// host; a bare host/domain/IP returns itself; non-host-like values (e.g. file
// paths) return "".
func hostOf(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	if i := strings.Index(value, "://"); i >= 0 {
		value = value[i+3:]
	}
	if i := strings.LastIndex(value, "@"); i >= 0 {
		value = value[i+1:]
	}
	if i := strings.IndexAny(value, "/?#"); i >= 0 {
		value = value[:i]
	}
	return stripPort(value)
}

// stripPort removes a trailing:port (and IPv6 brackets), leaving a bare host or
// IP. A bracket-less IPv6 literal (multiple colons) is left untouched.
func stripPort(h string) string {
	if strings.HasPrefix(h, "[") { // [ipv6] or [ipv6]:port
		if j := strings.Index(h, "]"); j >= 0 {
			return h[1:j]
		}
	}
	if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h[:i], ":") {
		if _, err := strconv.Atoi(h[i+1:]); err == nil {
			return h[:i]
		}
	}
	return h
}

// addrOf parses the host of a target value as an IP address (ok=false if it is a
// hostname rather than a literal IP). Hostname<->IP reconciliation (DNS) is
// intentionally NOT done here: a pure domain matcher must not resolve names – that
// would add a DNS-rebinding / SSRF surface. Recon adapters normalize a target to
// the kind the scope expresses (resolve-then-check, with their own logging) before
// calling, so an in-scope CIDR is matched against an already-resolved IP upstream.
func addrOf(value string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(hostOf(value))
	if err != nil {
		return netip.Addr{}, false
	}
	return a, true
}
