package ownsbom

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// A CI runner is the ordinary place a scan happens, and it has neither ~/.m2 nor mvn. Reading the local Maven
// repository closes the gap on a developer's machine; on a clean runner there is nothing to read, so a Spring
// project's tree resolves to almost nothing while a scanner that fetches POMs over HTTP resolves it fully.
// This file fetches them.
//
// It is deliberately NOT a general HTTP client for a scanner. A pom.xml is untrusted input that can name any
// URL, so every fetch is constrained:
//
//   - https only, and the resolved address must be public. A pom pointing at 169.254.169.254, a loopback
//     port or an RFC 1918 host would otherwise turn the scanner into an SSRF probe of the network it runs in.
//     SYNAPSE_MAVEN_ALLOW_PRIVATE_REPOS re-admits private addresses for an operator scanning their own code
//     against their own internal repository, which is a decision only they can make.
//   - Only the SCANNED PROJECT's <repositories> are honoured, never one declared by a third-party
//     dependency. Modern Maven discourages the latter for the same reason.
//   - A missing POM is remembered. Re-requesting a coordinate that does not exist is what earns a rate-limit
//     block: measured against a live estate, Trivy asked Maven Central for the same internal artifact once
//     per module, was answered 429 with Retry-After 1800, and lost every subsequent repository's scan to it.
//   - A 429 stops fetching from that host for the rest of the scan. It is never fatal and never sleeps.
//   - Every fetch is bounded in size, time and count, and what it returns is cached on disk so a second scan
//     needs no network at all.
//
// No credentials are ever sent, so a repository that requires authentication simply yields nothing.

const (
	maxRemotePOMBytes    = 2 << 20          // one .pom is small; the same cap the local reader uses
	remotePOMTimeout     = 15 * time.Second // per request
	maxRemotePOMRequests = 4000             // total requests for one project resolution
	maxRemoteRedirects   = 3
)

// mavenCentralURL is always an allowed repository: it is where an artifact lives unless the project says
// otherwise, and it is the one host a scan may assume.
const mavenCentralURL = "https://repo.maven.apache.org/maven2"

// DefaultPOMCacheDir is where fetched POMs are kept so a second scan of the same project needs no network.
// SYNAPSE_MAVEN_POM_CACHE overrides it; an unavailable cache directory disables caching without disabling
// fetching, because the cache is an optimisation and never a requirement.
func DefaultPOMCacheDir() string {
	if dir := strings.TrimSpace(os.Getenv("SYNAPSE_MAVEN_POM_CACHE")); dir != "" {
		return dir
	}
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		return ""
	}
	return filepath.Join(base, "synapse", "maven-poms")
}

// POMFetcher retrieves a Maven POM by coordinate. It returns ok=false for anything it could not fetch, which
// costs that subtree and never the scan.
type POMFetcher interface {
	// FetchPOM returns the POM bytes for the coordinate, trying each repository in order.
	FetchPOM(ctx context.Context, group, artifact, version string, repositories []string) ([]byte, bool)
	// Warnings reports what the fetcher could not do, so an absent subtree is never silent.
	Warnings() []string
}

// HTTPPOMFetcher is the network POMFetcher. One instance serves one scan: its caches, request budget and
// rate-limit state are per-scan, which is what keeps a blocked host from being retried all day.
type HTTPPOMFetcher struct {
	client       *http.Client
	cacheDir     string
	allowPrivate bool
	// central is the repository tried after the project's own. It is a field so a test is hermetic: a suite
	// that reached the real Maven Central would be doing the very thing this file exists to stop.
	central string
	// validate is the transport and address policy applied to every repository URL. It is a field so a test
	// can admit the loopback address its own server listens on, which the production policy refuses on
	// purpose; nothing outside this package can replace it.
	validate func(*url.URL) error

	mu        sync.Mutex
	requests  int
	missing   map[string]struct{} // coordinates a repository answered "not here": never asked twice
	blocked   map[string]string   // host -> why it stopped being used for this scan
	hostCheck map[string]error    // host -> address-policy verdict, memoised
	warned    map[string]struct{} // deduplicated warning text
	warnings  []string
}

// NewHTTPPOMFetcher builds a fetcher for one scan. cacheDir is where fetched POMs are written so a re-scan is
// offline; an empty cacheDir disables the on-disk cache without disabling fetching.
func NewHTTPPOMFetcher(cacheDir string) *HTTPPOMFetcher {
	allowPrivate := allowPrivateMavenRepos()
	f := &HTTPPOMFetcher{
		client: &http.Client{
			Timeout: remotePOMTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= maxRemoteRedirects {
					return errors.New("too many redirects")
				}
				// A redirect is a second chance to reach somewhere private, so it is checked like the first.
				return validateRepositoryURL(req.URL, allowPrivate)
			},
		},
		cacheDir:     cacheDir,
		allowPrivate: allowPrivate,
		central:      mavenCentralURL,
		missing:      map[string]struct{}{},
		blocked:      map[string]string{},
		hostCheck:    map[string]error{},
		warned:       map[string]struct{}{},
	}
	f.validate = func(u *url.URL) error { return validateRepositoryURL(u, allowPrivate) }
	return f
}

// allowPrivateMavenRepos reports whether a repository resolving to a private address may be used. It is off by
// default because a pom.xml is untrusted input; an operator scanning their own project against their own
// internal repository turns it on knowing what it admits.
func allowPrivateMavenRepos() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SYNAPSE_MAVEN_ALLOW_PRIVATE_REPOS"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// Warnings returns the deduplicated reasons the fetcher could not do its work.
func (f *HTTPPOMFetcher) Warnings() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.warnings...)
}

func (f *HTTPPOMFetcher) warn(text string) {
	if _, seen := f.warned[text]; seen {
		return
	}
	f.warned[text] = struct{}{}
	f.warnings = append(f.warnings, text)
}

// FetchPOM tries each repository in order, then Maven Central, and returns the first POM it gets.
func (f *HTTPPOMFetcher) FetchPOM(ctx context.Context, group, artifact, version string, repositories []string) ([]byte, bool) {
	if group == "" || artifact == "" || version == "" {
		return nil, false
	}
	rel := pomRelativePath(group, artifact, version)
	if data, ok := f.readCache(rel); ok {
		return data, true
	}
	for _, repo := range f.repositoryOrder(repositories) {
		data, ok := f.fetchFrom(ctx, repo, rel)
		if ok {
			f.writeCache(rel, data)
			return data, true
		}
	}
	return nil, false
}

// repositoryOrder is the order this fetcher tries, with its configured Central last.
func (f *HTTPPOMFetcher) repositoryOrder(repositories []string) []string {
	return appendCentral(repositories, f.central)
}

// appendCentral puts the project's own repositories first and Maven Central last, so an artifact that lives
// only in a private repository is asked for there rather than being demanded of a public mirror that has
// never heard of it.
func appendCentral(repositories []string, central string) []string {
	out := make([]string, 0, len(repositories)+1)
	seen := map[string]struct{}{}
	for _, repo := range repositories {
		repo = strings.TrimRight(strings.TrimSpace(repo), "/")
		if repo == "" {
			continue
		}
		if _, dup := seen[repo]; dup {
			continue
		}
		seen[repo] = struct{}{}
		out = append(out, repo)
	}
	central = strings.TrimRight(strings.TrimSpace(central), "/")
	if central != "" {
		if _, dup := seen[central]; !dup {
			out = append(out, central)
		}
	}
	return out
}

// pomRelativePath is the standard-layout path of a coordinate's .pom within any repository.
func pomRelativePath(group, artifact, version string) string {
	return strings.Join(append(strings.Split(group, "."), artifact, version, artifact+"-"+version+".pom"), "/")
}

func (f *HTTPPOMFetcher) fetchFrom(ctx context.Context, repo, rel string) ([]byte, bool) {
	target, err := url.Parse(repo + "/" + rel)
	if err != nil {
		return nil, false
	}
	key := target.Host + "/" + rel

	f.mu.Lock()
	if _, gone := f.missing[key]; gone {
		f.mu.Unlock()
		return nil, false // already answered "not here": asking again is what earns a block
	}
	if why, off := f.blocked[target.Host]; off {
		_ = why
		f.mu.Unlock()
		return nil, false
	}
	if f.requests >= maxRemotePOMRequests {
		f.warn(fmt.Sprintf("maven POM fetching stopped after %d requests; the dependency tree is a lower bound", maxRemotePOMRequests))
		f.mu.Unlock()
		return nil, false
	}
	f.requests++
	hostErr, checked := f.hostCheck[target.Host]
	f.mu.Unlock()

	if !checked {
		hostErr = f.validate(target)
		f.mu.Lock()
		f.hostCheck[target.Host] = hostErr
		if hostErr != nil {
			f.warn("maven repository " + target.Host + " not used: " + hostErr.Error())
		}
		f.mu.Unlock()
	}
	if hostErr != nil {
		return nil, false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept", "application/xml")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, false
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode == http.StatusOK:
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxRemotePOMBytes))
		if readErr != nil || len(data) == 0 {
			return nil, false
		}
		return data, true
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable:
		// Stop using this host for the rest of the scan. Retrying is what turns one throttled request into a
		// lost scan, and sleeping for the Retry-After it asks for (commonly 1800 seconds) is not a scan.
		retry := strings.TrimSpace(resp.Header.Get("Retry-After"))
		f.mu.Lock()
		f.blocked[target.Host] = retry
		detail := ""
		if retry != "" {
			detail = " (Retry-After: " + clipHeader(retry) + ")"
		}
		f.warn("maven repository " + target.Host + " rate-limited this scan" + detail +
			"; the dependency tree resolved from it is a lower bound")
		f.mu.Unlock()
		return nil, false
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		f.mu.Lock()
		f.missing[key] = struct{}{}
		f.mu.Unlock()
		return nil, false
	default:
		return nil, false
	}
}

func (f *HTTPPOMFetcher) readCache(rel string) ([]byte, bool) {
	if f.cacheDir == "" {
		return nil, false
	}
	data, err := readBounded(filepath.Join(f.cacheDir, filepath.FromSlash(rel)), maxRemotePOMBytes)
	if err != nil || len(data) == 0 {
		return nil, false
	}
	return data, true
}

// writeCache stores a fetched POM so a second scan of the same project needs no network. A write failure is
// ignored: the cache is an optimisation, never a requirement.
func (f *HTTPPOMFetcher) writeCache(rel string, data []byte) {
	if f.cacheDir == "" {
		return
	}
	path := filepath.Join(f.cacheDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return
	}
	// Write through a temporary file so a concurrent or interrupted scan never leaves a half-written POM that
	// a later scan would parse as truth.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pom-*")
	if err != nil {
		return
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	_ = os.Rename(tmp.Name(), path)
}

// clipHeader bounds a response header before it reaches a report. The value comes from a remote host, so it
// is untrusted text and must not be able to write a paragraph into a warning.
func clipHeader(s string) string {
	const max = 32
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		return s[:max]
	}
	return s
}

// validateRepositoryURL enforces the transport and address policy on a repository URL. It runs before the
// first request to a host and again on every redirect.
func validateRepositoryURL(target *url.URL, allowPrivate bool) error {
	if target == nil {
		return errors.New("no URL")
	}
	if !strings.EqualFold(target.Scheme, "https") {
		return fmt.Errorf("scheme %q is not https", target.Scheme)
	}
	if target.User != nil {
		return errors.New("the URL embeds credentials")
	}
	host := target.Hostname()
	if host == "" {
		return errors.New("no host")
	}
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		return errors.New("the host does not resolve")
	}
	for _, addr := range addrs {
		if publicUnicastIP(addr) {
			continue
		}
		if allowPrivate && addr.IsPrivate() {
			continue // an operator opted in to their own internal repository
		}
		return errors.New("the host resolves to a non-public address, which a scan will not fetch from " +
			"(set SYNAPSE_MAVEN_ALLOW_PRIVATE_REPOS=true for your own internal repository)")
	}
	return nil
}

// publicUnicastIP reports whether an address is one a scan may fetch from. Loopback, link-local (which is
// where a cloud instance-metadata service lives), multicast, unspecified and private ranges are all refused,
// because a pom.xml naming one of them is pointing the scanner at the network it runs inside.
func publicUnicastIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	return !ip.IsPrivate()
}
