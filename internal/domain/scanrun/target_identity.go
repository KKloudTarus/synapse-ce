package scanrun

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TargetKind identifies the classification of the evaluated scan target.
type TargetKind string

const (
	TargetRepository    TargetKind = "repository"
	TargetOCI           TargetKind = "oci"
	TargetHost          TargetKind = "host"
	TargetURL           TargetKind = "url"
	TargetCloudResource TargetKind = "cloud_resource"
)

func (k TargetKind) Valid() bool {
	switch k {
	case TargetRepository, TargetOCI, TargetHost, TargetURL, TargetCloudResource:
		return true
	default:
		return false
	}
}

// TargetIdentity is the server-derived, normalized target identity tuple (v1).
type TargetIdentity struct {
	TargetKind                  TargetKind `json:"target_kind"`
	TargetIdentitySchemaVersion int        `json:"target_identity_schema_version"`
	TargetIdentityCanonical     string     `json:"target_identity_canonical"`
	EvaluatedRevision           string     `json:"evaluated_revision"`
}

func (t TargetIdentity) Validate() error {
	if !t.TargetKind.Valid() {
		return fmt.Errorf("%w: invalid target kind %q", shared.ErrValidation, t.TargetKind)
	}
	if t.TargetIdentitySchemaVersion < 1 {
		return fmt.Errorf("%w: target identity schema version must be >= 1", shared.ErrValidation)
	}
	if strings.TrimSpace(t.TargetIdentityCanonical) == "" {
		return fmt.Errorf("%w: target identity canonical representation is required", shared.ErrValidation)
	}
	if len(t.TargetIdentityCanonical) > maxTargetIdentityLength {
		return fmt.Errorf("%w: target identity canonical representation exceeds %d bytes", shared.ErrValidation, maxTargetIdentityLength)
	}
	// Repositories and OCI targets require immutable evaluated revisions for coverage comparability
	switch t.TargetKind {
	case TargetRepository:
		if err := validateGitRevision(t.EvaluatedRevision); err != nil {
			return err
		}
	case TargetOCI:
		if err := validateOCIDigest(t.EvaluatedRevision); err != nil {
			return err
		}
	}
	return nil
}

var (
	hex40Regex = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64Regex = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

const maxTargetIdentityLength = 4096

func validateGitRevision(rev string) error {
	rev = strings.TrimSpace(strings.ToLower(rev))
	if rev == "" {
		return fmt.Errorf("%w: repository target requires an immutable commit SHA revision", shared.ErrValidation)
	}
	if !hex40Regex.MatchString(rev) && !hex64Regex.MatchString(rev) {
		return fmt.Errorf("%w: repository evaluated revision must be a full 40-hex (SHA-1) or 64-hex (SHA-256) commit digest, got %q", shared.ErrValidation, rev)
	}
	return nil
}

func validateOCIDigest(rev string) error {
	rev = strings.TrimSpace(strings.ToLower(rev))
	if rev == "" {
		return fmt.Errorf("%w: OCI target requires an immutable sha256 digest revision", shared.ErrValidation)
	}
	if !strings.HasPrefix(rev, "sha256:") {
		return fmt.Errorf("%w: OCI digest must start with 'sha256:', got %q", shared.ErrValidation, rev)
	}
	digestHex := strings.TrimPrefix(rev, "sha256:")
	if !hex64Regex.MatchString(digestHex) {
		return fmt.Errorf("%w: OCI digest hex must be 64 lowercase hex characters, got %q", shared.ErrValidation, digestHex)
	}
	return nil
}

// CanonicalizeRepositoryTarget derives a canonical TargetIdentity for a source repository.
func CanonicalizeRepositoryTarget(rawURL, rawRevision string) (TargetIdentity, error) {
	v := strings.TrimSpace(rawURL)
	if v == "" {
		return TargetIdentity{}, fmt.Errorf("%w: repository URL is required", shared.ErrValidation)
	}
	rev := strings.TrimSpace(strings.ToLower(rawRevision))
	if err := validateGitRevision(rev); err != nil {
		return TargetIdentity{}, err
	}

	// Handle scp-style SSH syntax: git@github.com:org/repo.git
	if strings.Contains(v, "@") && strings.Contains(v, ":") && !strings.Contains(v, "://") {
		parts := strings.SplitN(v, "@", 2)
		if strings.Contains(parts[0], ":") {
			return TargetIdentity{}, fmt.Errorf("%w: repository target must not contain credentials", shared.ErrValidation)
		}
		hostPath := parts[1]
		hpParts := strings.SplitN(hostPath, ":", 2)
		if len(hpParts) == 2 {
			host := strings.ToLower(strings.TrimSpace(hpParts[0]))
			repoPath := "/" + strings.TrimPrefix(strings.TrimSpace(hpParts[1]), "/")
			v = "ssh://" + host + repoPath
		}
	}

	u, err := url.Parse(v)
	if err != nil || u == nil || u.Host == "" {
		return TargetIdentity{}, fmt.Errorf("%w: invalid repository URL: %v", shared.ErrValidation, err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		scheme = "https"
	}
	if scheme != "https" && scheme != "http" && scheme != "ssh" && scheme != "git" {
		return TargetIdentity{}, fmt.Errorf("%w: unsupported repository scheme %q", shared.ErrValidation, scheme)
	}
	if u.User != nil {
		_, hasPassword := u.User.Password()
		if scheme != "ssh" || hasPassword {
			return TargetIdentity{}, fmt.Errorf("%w: repository target must not contain credentials", shared.ErrValidation)
		}
	}
	if u.RawQuery != "" || u.Fragment != "" || u.RawFragment != "" {
		return TargetIdentity{}, fmt.Errorf("%w: repository target must not contain a query or fragment", shared.ErrValidation)
	}

	normalizedHost, err := engagement.NormalizeHost(u.Hostname())
	if err != nil {
		return TargetIdentity{}, fmt.Errorf("%w: invalid repository hostname %q", shared.ErrValidation, u.Hostname())
	}

	portStr := u.Port()
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil || p <= 0 || p > 65535 {
			return TargetIdentity{}, fmt.Errorf("%w: invalid repository port %q", shared.ErrValidation, portStr)
		}
		// Strip default ports
		if (scheme == "https" && p == 443) || (scheme == "http" && p == 80) || (scheme == "ssh" && p == 22) {
			portStr = ""
		}
	}

	// Clean the escaped path so an encoded slash cannot become a path separator
	// and collapse two distinct repository identities.
	cleanPath := path.Clean("/" + strings.TrimPrefix(u.EscapedPath(), "/"))
	cleanPath = strings.TrimSuffix(cleanPath, ".git")
	cleanPath = strings.TrimSuffix(cleanPath, "/")
	if cleanPath == "." || cleanPath == "/" {
		return TargetIdentity{}, fmt.Errorf("%w: repository path is required", shared.ErrValidation)
	}

	var hostHeader string
	if portStr != "" {
		hostHeader = net.JoinHostPort(normalizedHost, portStr)
	} else if addr, parseErr := netip.ParseAddr(normalizedHost); parseErr == nil && addr.Is6() {
		hostHeader = "[" + normalizedHost + "]"
	} else {
		hostHeader = normalizedHost
	}

	canonical := scheme + "://" + hostHeader + cleanPath
	return TargetIdentity{
		TargetKind:                  TargetRepository,
		TargetIdentitySchemaVersion: 1,
		TargetIdentityCanonical:     canonical,
		EvaluatedRevision:           rev,
	}, nil
}

// CanonicalizeOCITarget derives a canonical TargetIdentity for an OCI image target.
func CanonicalizeOCITarget(rawRef string) (TargetIdentity, error) {
	v := strings.TrimSpace(rawRef)
	if v == "" {
		return TargetIdentity{}, fmt.Errorf("%w: OCI reference is required", shared.ErrValidation)
	}

	var repoPart, digestPart string
	if idx := strings.Index(v, "@"); idx != -1 {
		repoPart = v[:idx]
		digestPart = v[idx+1:]
	} else {
		return TargetIdentity{}, fmt.Errorf("%w: OCI reference must contain an immutable digest (@sha256:...)", shared.ErrValidation)
	}

	// Remove mutable tag if present before @
	if tagIdx := strings.LastIndex(repoPart, ":"); tagIdx != -1 {
		// Verify this colon isn't part of host:port
		slashIdx := strings.LastIndex(repoPart, "/")
		if tagIdx > slashIdx {
			repoPart = repoPart[:tagIdx]
		}
	}

	repoPart = strings.ToLower(strings.TrimSpace(repoPart))
	digestPart = strings.ToLower(strings.TrimSpace(digestPart))
	if repoPart == "" {
		return TargetIdentity{}, fmt.Errorf("%w: OCI repository is required", shared.ErrValidation)
	}
	if strings.ContainsAny(repoPart, " \t\r\n") {
		return TargetIdentity{}, fmt.Errorf("%w: OCI repository must not contain whitespace", shared.ErrValidation)
	}

	if err := validateOCIDigest(digestPart); err != nil {
		return TargetIdentity{}, err
	}

	canonical := repoPart + "@" + digestPart
	return TargetIdentity{
		TargetKind:                  TargetOCI,
		TargetIdentitySchemaVersion: 1,
		TargetIdentityCanonical:     canonical,
		EvaluatedRevision:           digestPart,
	}, nil
}

// CanonicalizeHostTarget derives a canonical TargetIdentity for a host/IP target.
func CanonicalizeHostTarget(rawHost string) (TargetIdentity, error) {
	v := strings.TrimSpace(rawHost)
	if v == "" {
		return TargetIdentity{}, fmt.Errorf("%w: host target is required", shared.ErrValidation)
	}

	// Check if port is specified
	if strings.Contains(v, ":") && !strings.HasPrefix(v, "[") && strings.Count(v, ":") == 1 {
		host, port, endpoint, err := engagement.NormalizeEndpoint(v)
		if err != nil {
			return TargetIdentity{}, err
		}
		_ = host
		_ = port
		return TargetIdentity{
			TargetKind:                  TargetHost,
			TargetIdentitySchemaVersion: 1,
			TargetIdentityCanonical:     endpoint,
			EvaluatedRevision:           "",
		}, nil
	}

	// Host without explicit port or IPv6 literal
	if strings.HasPrefix(v, "[") && strings.Contains(v, "]:") {
		host, port, endpoint, err := engagement.NormalizeEndpoint(v)
		if err != nil {
			return TargetIdentity{}, err
		}
		_ = host
		_ = port
		return TargetIdentity{
			TargetKind:                  TargetHost,
			TargetIdentitySchemaVersion: 1,
			TargetIdentityCanonical:     endpoint,
			EvaluatedRevision:           "",
		}, nil
	}

	normHost, err := engagement.NormalizeHost(v)
	if err != nil {
		return TargetIdentity{}, err
	}

	return TargetIdentity{
		TargetKind:                  TargetHost,
		TargetIdentitySchemaVersion: 1,
		TargetIdentityCanonical:     normHost,
		EvaluatedRevision:           "",
	}, nil
}

// CanonicalizeURLTarget derives a canonical TargetIdentity for an HTTP(S) URL target.
func CanonicalizeURLTarget(rawURL string) (TargetIdentity, error) {
	v := strings.TrimSpace(rawURL)
	if v == "" {
		return TargetIdentity{}, fmt.Errorf("%w: URL target is required", shared.ErrValidation)
	}

	norm, err := engagement.NormalizeURL(v)
	if err != nil {
		return TargetIdentity{}, err
	}

	u, err := url.Parse(norm.URL)
	if err != nil {
		return TargetIdentity{}, fmt.Errorf("%w: parse normalized URL: %v", shared.ErrValidation, err)
	}

	// Remove fragment
	u.Fragment = ""
	u.RawFragment = ""

	// Strip default ports
	host := u.Hostname()
	port := u.Port()
	if (norm.Scheme == "http" && port == "80") || (norm.Scheme == "https" && port == "443") {
		port = ""
	}

	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else {
		// IPv6 needs brackets if it's an IP literal
		if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
			u.Host = "[" + host + "]"
		} else {
			u.Host = host
		}
	}

	u.Path = path.Clean("/" + strings.TrimPrefix(u.Path, "/"))
	if u.Path == "." {
		u.Path = "/"
	}

	canonical := u.String()
	return TargetIdentity{
		TargetKind:                  TargetURL,
		TargetIdentitySchemaVersion: 1,
		TargetIdentityCanonical:     canonical,
		EvaluatedRevision:           "",
	}, nil
}

// CanonicalizeCloudResourceTarget derives a canonical TargetIdentity for a cloud resource.
func CanonicalizeCloudResourceTarget(provider, accountOrProject, resourceID string) (TargetIdentity, error) {
	p := strings.ToLower(strings.TrimSpace(provider))
	if p == "" {
		return TargetIdentity{}, fmt.Errorf("%w: cloud provider is required", shared.ErrValidation)
	}
	acct := strings.TrimSpace(accountOrProject)
	if acct == "" {
		return TargetIdentity{}, fmt.Errorf("%w: cloud account/project identifier is required", shared.ErrValidation)
	}
	res := strings.TrimSpace(resourceID)
	if res == "" {
		return TargetIdentity{}, fmt.Errorf("%w: cloud resource ID is required", shared.ErrValidation)
	}

	canonical := fmt.Sprintf("%s/%s/%s", p, url.PathEscape(acct), url.PathEscape(res))
	return TargetIdentity{
		TargetKind:                  TargetCloudResource,
		TargetIdentitySchemaVersion: 1,
		TargetIdentityCanonical:     canonical,
		EvaluatedRevision:           "",
	}, nil
}
