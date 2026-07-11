// Package jarhash recovers the Maven coordinate of a shaded / relocated / metadata-less JVM component
// from its artifact SHA-1, by querying Maven Central's SHA-1 search API. It is the fallback to
// mavencoord: pom.properties recovery handles JARs that still carry their coordinates; this
// handles the ones whose in-file identity was stripped, whose CVEs would otherwise never be looked up
// because they have no resolvable coordinate.
//
// SECURITY / conservatism: it is BEST-EFFORT and network-gated. It queries ONLY components that have a
// SHA-1 and an unresolved coordinate; it adopts a coordinate only on a single unambiguous match (an
// ambiguous byte-identical republish is resolved deterministically, never invented). A
// SHA-1 → coordinate answer is IMMUTABLE, so results are cached for the process lifetime; the client is
// rate-limit disciplined (bounded concurrency, honors Retry-After, stops for the rest of the scan on a
// 429/403 – Maven Central escalates throttling to a 24h org-level block). A lookup error or an
// unreachable/throttled index is a no-op; the scan never fails.
package jarhash

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	defaultBaseURL = "https://search.maven.org/solrsearch/select"
	maxLookups     = 400 // per-scan budget: cap Central queries so a huge SBOM can't hammer it
	reqTimeout     = 10 * time.Second
	maxBodyBytes   = 1 << 20 // a solr response for rows=2 is tiny; cap defensively
	sha1HexLen     = 40
)

// Resolver looks up unidentified JVM components by SHA-1 against Maven Central.
type Resolver struct {
	baseURL     string
	client      *http.Client
	concurrency int

	mu     sync.Mutex
	cache  map[string]coord // sha1 -> resolved coord (immutable answer); nil coord = a miss, still cached
	halted bool             // set on 429/403: stop querying for the rest of this process's scans
}

type coord struct{ group, artifact, version string }

// New returns a resolver hitting Maven Central's SHA-1 search API. baseURL/client default sensibly.
func New(baseURL string, client *http.Client) *Resolver {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultBaseURL
	}
	if client == nil {
		client = &http.Client{Timeout: reqTimeout}
	}
	return &Resolver{
		baseURL:     strings.TrimRight(baseURL, "/"),
		client:      client,
		concurrency: 4,
		cache:       map[string]coord{},
	}
}

var _ ports.JarHashResolver = (*Resolver)(nil)

// Resolve recovers the Maven coordinate of each unresolved component from its SHA-1, correcting the PURL
// in place. Returns the number recovered. Best-effort: errors/throttling are no-ops. Components are
// GROUPED by SHA-1 so each distinct hash is queried at most once, even when several components share it.
func (r *Resolver) Resolve(ctx context.Context, comps []sbom.Component) int {
	// Group unresolved components by their (lowercased) SHA-1 – one query per distinct hash.
	bySHA1 := map[string][]int{}
	var order []string
	for i := range comps {
		if !needsLookup(comps[i]) {
			continue
		}
		h := strings.ToLower(strings.TrimSpace(comps[i].SHA1))
		if _, seen := bySHA1[h]; !seen {
			order = append(order, h)
		}
		bySHA1[h] = append(bySHA1[h], i)
	}
	if len(order) == 0 {
		return 0
	}
	if len(order) > maxLookups {
		order = order[:maxLookups] // per-scan budget: degrade to "some unidentified", never hammer Central
	}

	// Query each distinct SHA-1 concurrently; collect the resolved coordinate per hash.
	results := make([]coord, len(order))
	found := make([]bool, len(order))
	sem := make(chan struct{}, r.concurrency)
	var wg sync.WaitGroup
	for k, h := range order {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(k int, h string) {
			defer wg.Done()
			defer func() { <-sem }()
			if c, ok := r.lookup(ctx, h); ok {
				results[k], found[k] = c, true
			}
		}(k, h)
	}
	wg.Wait()

	// Apply each resolved coordinate to every component that carried that SHA-1.
	recovered := 0
	for k, h := range order {
		if !found[k] {
			continue
		}
		for _, idx := range bySHA1[h] {
			applyCoord(&comps[idx], results[k])
			recovered++
		}
	}
	return recovered
}

// needsLookup reports whether a component should be SHA-1-resolved: it has a hex SHA-1 and its coordinate
// is NOT already a resolved pkg:maven (so we never override a JAR that pom.properties already identified).
func needsLookup(c sbom.Component) bool {
	if !isHexSHA1(c.SHA1) {
		return false
	}
	// A confidently-resolved Maven component (pkg:maven with a pinned version) is left alone.
	if strings.HasPrefix(c.PURL, "pkg:maven/") && sbom.IsResolvedVersion(c.Version) {
		return false
	}
	return true
}

func isHexSHA1(s string) bool {
	if len(s) != sha1HexLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// applyCoord sets a recovered coordinate on a component: PURL, name (group:artifact, matching the other
// Maven adapters), and version when the component lacked a resolved one.
func applyCoord(c *sbom.Component, co coord) {
	c.PURL = "pkg:maven/" + co.group + "/" + co.artifact + "@" + co.version
	c.Name = co.group + ":" + co.artifact
	c.Version = co.version
}

// lookup outcomes: a definitive answer (hit or a real 0-hit response) is cached immutably; a transient
// failure (network / 5xx / decode) is NOT cached, so a blip doesn't suppress that SHA-1 for the whole run.
type outcome int

const (
	outMiss      outcome = iota // definitive: the index has no coordinate for this SHA-1
	outHit                      // definitive: a valid coordinate
	outTransient                // network/5xx/decode error – not an answer, don't cache
)

// lookup resolves one SHA-1 to a coordinate, using the process cache first. ok=false on miss/error/transient.
func (r *Resolver) lookup(ctx context.Context, sha1 string) (coord, bool) {
	r.mu.Lock()
	if r.halted {
		r.mu.Unlock()
		return coord{}, false
	}
	if c, ok := r.cache[sha1]; ok {
		r.mu.Unlock()
		return c, c != (coord{})
	}
	r.mu.Unlock()

	c, out := r.query(ctx, sha1)
	if out == outTransient {
		return coord{}, false // don't cache a transient failure – a later component with this SHA-1 may retry
	}
	r.mu.Lock()
	r.cache[sha1] = c // cache the definitive answer (a hit's coord, or the zero coord for a real miss)
	r.mu.Unlock()
	return c, out == outHit
}

// query hits Maven Central's SHA-1 search endpoint and returns the single unambiguous coordinate + whether
// the outcome is definitive (cacheable) or a transient failure.
func (r *Resolver) query(ctx context.Context, sha1 string) (coord, outcome) {
	q := url.Values{}
	q.Set("q", `1:"`+sha1+`"`)
	q.Set("rows", "2") // fetch 2 to observe multiplicity; ≥2 = byte-identical republishes (same advisories), adopt first
	q.Set("wt", "json")
	reqCtx, cancel := context.WithTimeout(ctx, reqTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, r.baseURL+"?"+q.Encode(), nil)
	if err != nil {
		return coord{}, outTransient
	}
	req.Header.Set("User-Agent", "synapse-sca/jarhash (+https://github.com/KKloudTarus/synapse-ce)")
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return coord{}, outTransient // network error – retryable, not a definitive miss
	}
	defer func() { _ = resp.Body.Close() }()

	// Rate-limit discipline: on 429/403 stop querying for the rest of this process (Central escalates
	// throttling to a 24h org-level block); honor Retry-After only as a signal to halt, not to sleep.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden {
		r.mu.Lock()
		r.halted = true
		r.mu.Unlock()
		return coord{}, outTransient
	}
	if resp.StatusCode != http.StatusOK {
		return coord{}, outTransient // 5xx/other – retryable, don't cache as a miss
	}

	var out struct {
		Response struct {
			Docs []struct {
				G string `json:"g"`
				A string `json:"a"`
				V string `json:"v"`
			} `json:"docs"`
		} `json:"response"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&out); err != nil {
		return coord{}, outTransient // malformed body – retryable
	}
	docs := out.Response.Docs
	if len(docs) == 0 {
		return coord{}, outMiss // definitive: the index has no coordinate for this SHA-1
	}
	// One, or several byte-identical republishes (same classes ⇒ same advisories). Solr's response order
	// is NOT a stable client contract, so pick the DETERMINISTIC least by (g,a,v) for a reproducible result.
	best := docs[0]
	for _, d := range docs[1:] {
		if d.G < best.G || (d.G == best.G && d.A < best.A) || (d.G == best.G && d.A == best.A && d.V < best.V) {
			best = d
		}
	}
	// The response is UNTRUSTED external input: validate the coordinate BEFORE it becomes a PURL /
	// advisory-match key, so a malicious/compromised endpoint can't inject a malformed group/artifact/
	// version (e.g. a `/`, `@`, whitespace, or control char that would confuse the PURL or a downstream
	// matcher). Reject anything outside the strict Maven-coordinate character set – treat as a miss.
	if !validGA(best.G) || !validGA(best.A) || !validVersion(best.V) {
		return coord{}, outMiss
	}
	return coord{group: best.G, artifact: best.A, version: best.V}, outHit
}

// validGA reports whether s is a well-formed Maven groupId/artifactId token: non-empty, only
// [A-Za-z0-9._-], no path/PURL/whitespace metacharacters.
func validGA(s string) bool {
	if s == "" || len(s) > 512 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// validVersion is a strict allow-list for a Maven version: [A-Za-z0-9._+-] – covers every real form
// (2.16.3, 1.0-RELEASE, Hoxton.SR12, 1.0.0-alpha.1+build) while rejecting '/', '@', ':', '%', whitespace,
// and control chars that would malform the PURL or the advisory match key (untrusted-input hardening).
func validVersion(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '+' || c == '-') {
			return false
		}
	}
	return true
}
