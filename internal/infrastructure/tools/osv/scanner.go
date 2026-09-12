// Package osv is a DetectionSource that queries OSV.dev – the primary
// vuln source (free, no auth, no rate limit). It matches SBOM components
// by PURL and maps results to raw findings for correlation.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	defaultBaseURL = "https://api.osv.dev"
	maxBatch       = 1000     // OSV querybatch limit
	maxRespBytes   = 32 << 20 // cap a single response body

	// Resilience for the live source: a transient 429/5xx or network blip is retried with bounded
	// exponential backoff (honoring Retry-After) instead of failing the request, and the per-advisory
	// detail fetch runs bounded-concurrently so latency does not scale linearly with the vuln count.
	maxRetries        = 3
	baseBackoff       = 300 * time.Millisecond
	maxBackoff        = 10 * time.Second
	detailConcurrency = 8
)

// Scanner queries OSV.dev for vulnerabilities affecting SBOM components.
type Scanner struct {
	baseURL string
	client  *http.Client
}

// New returns a scanner. baseURL defaults to OSV.dev; client defaults to 30s.
func New(baseURL string, client *http.Client) *Scanner {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultBaseURL
	}
	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
			// Defense-in-depth: don't follow redirects (OSV.dev doesn't redirect);
			// the non-2xx status check then turns any redirect into an error.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &Scanner{baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

var _ ports.DetectionSource = (*Scanner)(nil)

// Name identifies this detection source.
func (*Scanner) Name() string { return "osv" }

// isOSDistroPURL reports whether a PURL is an OS-distro package (rpm/deb/apk). Their advisory matching must
// be scoped to the distro RELEASE (redhat:9, debian:12, …); that is handled by Grype + the owned OVAL/CSAF
// feeds, not by OSV.dev's release-unaware PURL query. Excluding them from OSV removes cross-stream
// false positives without losing coverage (Grype scans every OS package).
func isOSDistroPURL(purl string) bool {
	return strings.HasPrefix(purl, "pkg:rpm/") ||
		strings.HasPrefix(purl, "pkg:deb/") ||
		strings.HasPrefix(purl, "pkg:apk/")
}

// Scan batches the components' PURLs to OSV.dev, fetches details for each unique
// advisory, and maps them to raw findings (correlation merges across sources).
func (s *Scanner) Scan(ctx context.Context, doc *sbom.SBOM) ([]vulnerability.RawFinding, error) {
	if doc == nil || len(doc.Components) == 0 {
		return nil, nil
	}

	type item struct {
		compIdx int
		purl    string
	}
	var items []item
	for i, c := range doc.Components {
		if c.PURL == "" {
			continue
		}
		// OS-distro packages (rpm/deb/apk) are matched by Grype + the owned OVAL/CSAF feeds, which scope to
		// the package's distro RELEASE. OSV.dev's PURL query is NOT release-scoped for these, so it returns
		// advisories from every stream (e.g. a RHEL-8-Satellite "el8sat" fix reported against an el9 package)
		// - a large false-positive inflation (a clean ubi9 base yielded 555 OSV RHSA matches vs Grype's 31).
		// Route OS packages to the distro-scoped sources only; OSV keeps the language ecosystems
		// (Go/npm/PyPI/Maven/…), where its PURL matching is authoritative.
		if isOSDistroPURL(c.PURL) {
			continue
		}
		// Query OSV by the versioned PURL for EVERY non-distro package, not only the ecosystems our
		// identity resolver recognizes: OSV.dev's versioned-PURL match is authoritative and covers many
		// ecosystems we do not resolve locally (Composer, Hex, Pub, Swift, Conan, …). Gating the query on
		// IdentityResolved silently dropped those ecosystems from OSV entirely (a false "not vulnerable").
		// Identity is used only to ENRICH the affected-range/fix data below, never to suppress a match.
		items = append(items, item{compIdx: i, purl: c.PURL})
	}
	if len(items) == 0 {
		return nil, nil
	}

	idToComps := map[string]map[int]bool{}
	var order []string

	for start := 0; start < len(items); start += maxBatch {
		end := min(start+maxBatch, len(items))
		chunk := items[start:end]
		queries := make([]batchQuery, len(chunk))
		for j, it := range chunk {
			queries[j] = batchQuery{Package: batchPkg{PURL: it.purl}}
		}
		results, err := s.queryBatch(ctx, queries)
		if err != nil {
			return nil, err
		}
		if len(results) != len(chunk) {
			return nil, fmt.Errorf("osv querybatch: got %d results for %d queries", len(results), len(chunk))
		}
		for j, res := range results {
			ci := chunk[j].compIdx
			for _, v := range res.Vulns {
				if idToComps[v.ID] == nil {
					idToComps[v.ID] = map[int]bool{}
					order = append(order, v.ID)
				}
				idToComps[v.ID][ci] = true
			}
		}
	}

	// Fetch every advisory's detail concurrently (bounded), so latency does not scale linearly with the
	// vuln count. Results are collected into a map and consumed in the deterministic `order` below, so
	// output ordering is unchanged. The first error cancels the rest and fails the fetch (the pipeline's
	// degrade policy then decides whether to skip OSV or abort).
	details, err := s.fetchDetails(ctx, order)
	if err != nil {
		return nil, err
	}
	var out []vulnerability.RawFinding
	for _, id := range order {
		detail := details[id]
		cis := make([]int, 0, len(idToComps[id]))
		for ci := range idToComps[id] {
			cis = append(cis, ci)
		}
		sort.Ints(cis)
		for _, ci := range cis {
			component := doc.Components[ci]
			identity := sbom.IdentityFromComponent(component)
			// Drop a match ONLY when we have a resolved identity that lets us confidently say every
			// affected block names a DIFFERENT artifact (the wrong-artifact false positive this PR fixed).
			// When our identity is unresolved (an ecosystem we do not model) we cannot make that judgement,
			// so we trust OSV's versioned-PURL match and emit the finding (with fix data left empty rather
			// than fabricated) — otherwise a whole ecosystem silently reports zero OSV vulns.
			if identity.Status == sbom.IdentityResolved && len(matchingAffected(identity, component.PURL, detail.Affected)) == 0 {
				continue
			}
			out = append(out, osvToRaw(component, detail))
		}
	}
	out = dedupRaws(out)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Component != out[j].Component {
			return out[i].Component < out[j].Component
		}
		return out[i].AdvisoryID < out[j].AdvisoryID
	})
	return out, nil
}

func (s *Scanner) queryBatch(ctx context.Context, queries []batchQuery) ([]batchResult, error) {
	body, err := json.Marshal(batchReq{Queries: queries})
	if err != nil {
		return nil, fmt.Errorf("osv querybatch: marshal: %w", err)
	}
	resp, err := s.doRetry(ctx, "osv querybatch", func() (*http.Request, error) {
		r, rerr := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/v1/querybatch", bytes.NewReader(body))
		if rerr != nil {
			return nil, rerr
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json")
		return r, nil
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv querybatch: unexpected status %d", resp.StatusCode)
	}
	var out batchResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRespBytes)).Decode(&out); err != nil {
		return nil, fmt.Errorf("osv querybatch decode: %w", err)
	}
	return out.Results, nil
}

func (s *Scanner) vulnDetail(ctx context.Context, id string) (osvVuln, error) {
	var v osvVuln
	resp, err := s.doRetry(ctx, "osv vuln "+id, func() (*http.Request, error) {
		r, rerr := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/v1/vulns/"+url.PathEscape(id), nil)
		if rerr != nil {
			return nil, rerr
		}
		r.Header.Set("Accept", "application/json")
		return r, nil
	})
	if err != nil {
		return v, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return v, fmt.Errorf("osv vuln %s: unexpected status %d", id, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRespBytes)).Decode(&v); err != nil {
		return v, fmt.Errorf("osv vuln %s decode: %w", id, err)
	}
	return v, nil
}

// doRetry runs an HTTP request with bounded exponential backoff, retrying network errors and transient
// statuses (429, 500, 502, 503, 504) and honoring Retry-After. The request is rebuilt each attempt (a
// consumed body is not reusable). A non-retryable response is returned as-is for the caller to inspect.
func (s *Scanner) doRetry(ctx context.Context, what string, mkReq func() (*http.Request, error)) (*http.Response, error) {
	backoff := baseBackoff
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
		req, err := mkReq()
		if err != nil {
			return nil, err
		}
		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if isRetryableStatus(resp.StatusCode) {
			if ra := retryAfter(resp.Header.Get("Retry-After")); ra > 0 {
				backoff = ra
			}
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("%s: transient status %d", what, resp.StatusCode)
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("%s: after %d attempts: %w", what, maxRetries+1, lastErr)
}

func isRetryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// retryAfter parses a Retry-After header expressed as an integer number of seconds, capped at maxBackoff.
func retryAfter(h string) time.Duration {
	secs, err := strconv.Atoi(strings.TrimSpace(h))
	if err != nil || secs <= 0 {
		return 0
	}
	d := time.Duration(secs) * time.Second
	if d > maxBackoff {
		return maxBackoff
	}
	return d
}

// fetchDetails resolves every advisory id's detail with bounded concurrency, returning them keyed by id.
// The first error cancels the remaining fetches and is returned, so a persistent OSV failure surfaces
// (the caller's degrade policy then decides skip-vs-abort). Ordering is the caller's concern: it consumes
// the map in a deterministic order.
func (s *Scanner) fetchDetails(ctx context.Context, ids []string) (map[string]osvVuln, error) {
	details := make(map[string]osvVuln, len(ids))
	if len(ids) == 0 {
		return details, nil
	}
	dctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu       sync.Mutex
		firstErr error
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, detailConcurrency)
	for _, id := range ids {
		mu.Lock()
		stop := firstErr != nil
		mu.Unlock()
		if stop {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			v, err := s.vulnDetail(dctx, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
					cancel()
				}
				return
			}
			details[id] = v
		}(id)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return details, nil
}

// --- OSV API JSON (minimal subset we consume) ---

type batchReq struct {
	Queries []batchQuery `json:"queries"`
}
type batchQuery struct {
	Package batchPkg `json:"package"`
}
type batchPkg struct {
	PURL string `json:"purl"`
}
type batchResp struct {
	Results []batchResult `json:"results"`
}
type batchResult struct {
	Vulns []batchVuln `json:"vulns"`
}
type batchVuln struct {
	ID string `json:"id"`
}

type osvVuln struct {
	ID               string         `json:"id"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Aliases          []string       `json:"aliases"`
	Severity         []osvSeverity  `json:"severity"`
	Affected         []osvAffected  `json:"affected"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}
type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}
type osvAffected struct {
	Package           osvPackage `json:"package"`
	Ranges            []osvRange `json:"ranges"`
	Versions          []string   `json:"versions"` // explicit affected versions (for version-scoping symbols)
	EcosystemSpecific struct {
		Imports []struct {
			Path    string   `json:"path"`
			Symbols []string `json:"symbols"`
		} `json:"imports"`
		// Affects.Functions is RustSec's affected-symbol form (already-qualified "crate::Type::method"),
		// parallel to the Go vuln DB's imports[].symbols. Read both so a crates.io finding surfaces its
		// affected functions, matching the owned offline ingester (ownadvisory.osvImportSymbols).
		Affects struct {
			Functions []string `json:"functions"`
		} `json:"affects"`
	} `json:"ecosystem_specific"`
}
type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl"`
}
type osvRange struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}

// osvToRaw maps an OSV advisory + the affected component to a raw finding,
// deriving the CVSS base score + severity from the vector. Aliases (CVE/GHSA/OSV
// ids) are kept for cross-source correlation.
func osvToRaw(comp sbom.Component, v osvVuln) vulnerability.RawFinding {
	identity := sbom.IdentityFromComponent(comp)
	matchedAffected := matchingAffected(identity, comp.PURL, v.Affected)
	fixedVersions, rejectedFixedVersions := validatedFixedVersions(identity, matchedAffected)
	out := vulnerability.RawFinding{
		Source:                "osv",
		AdvisoryID:            preferCVE(v.ID, v.Aliases),
		Aliases:               append([]string{v.ID}, v.Aliases...),
		Severity:              shared.SeverityUnknown,
		Component:             comp.Name,
		Version:               comp.Version,
		Ecosystem:             identity.Ecosystem,
		PackagePURL:           comp.PURL,
		FixedVersions:         fixedVersions,
		RejectedFixedVersions: rejectedFixedVersions,
		Description:           firstNonEmpty(v.Summary, v.Details),
	}
	if len(fixedVersions) > 0 {
		out.FixedVersion = fixedVersions[0]
		out.FixState = "fixed"
	}
	// Pick a CVSS vector – prefer v3.x (scoreable) for the base score.
	var v3vec string
	for _, sev := range v.Severity {
		if !strings.HasPrefix(sev.Type, "CVSS_V") {
			continue
		}
		if out.CVSSVector == "" {
			out.CVSSVector = sev.Score
		}
		if strings.HasPrefix(sev.Score, "CVSS:3.") {
			v3vec = sev.Score
			out.CVSSVector = sev.Score
			break
		}
	}
	if score, ok := shared.CVSSv3BaseScore(v3vec); ok {
		out.CVSSScore = score
		out.Severity = shared.SeverityFromScore(score)
	}
	// A curated database_specific label (e.g. GHSA) overrides the computed band.
	if lbl, ok := v.DatabaseSpecific["severity"].(string); ok {
		if s := mapSeverityLabel(lbl); s != shared.SeverityUnknown {
			out.Severity = s
		}
	}
	// Symbols come ONLY from the affected blocks whose range/versions actually include this component's
	// version. matchingAffected filters by package name/PURL, not version; an advisory may list the same
	// package in several blocks with different ranges and different symbols, so unioning across all of them
	// would attach another version's symbol to this finding and seed a false reachable-symbol claim. Strict
	// filtering (no fallback) keeps this on the safe side of the #1 no-false-positive bar: a missed symbol only
	// under-drives raise-only reachability, never a false suppression.
	out.AffectedSymbols = affectedSymbols(versionScopedAffected(identity, matchedAffected))
	return out
}

// versionScopedAffected narrows name/PURL-matched blocks to those whose ranges or explicit versions include the
// component version, so only version-applicable symbols reach the finding. An unresolved identity keeps the
// name-matched set (no version to scope by); this only governs which symbols attach, not whether the finding
// is emitted (that gate is upstream).
func versionScopedAffected(identity sbom.ComponentIdentity, affected []osvAffected) []osvAffected {
	if identity.Status != sbom.IdentityResolved {
		return affected
	}
	out := make([]osvAffected, 0, len(affected))
	for _, a := range affected {
		// Strict: a block contributes its symbols ONLY when its ranges or explicit versions PROVABLY include
		// the component version. A block with neither constrains nothing we can evaluate, so per OSV it does
		// not establish that this version is in scope (OSV represents "all versions" with an introduced-0
		// range, not by omitting both); attaching its symbols would reopen the cross-version leak, so it is
		// dropped. A dropped symbol only under-drives raise-only reachability, never a false suppression.
		ranges := make([]advisory.Range, 0, len(a.Ranges))
		for _, r := range a.Ranges {
			conv := advisory.Range{Type: strings.ToUpper(strings.TrimSpace(r.Type))}
			for _, e := range r.Events {
				conv.Events = append(conv.Events, advisory.Event{Introduced: e["introduced"], Fixed: e["fixed"], LastAffected: e["last_affected"], Limit: e["limit"]})
			}
			ranges = append(ranges, conv)
		}
		if advisory.Affected(identity.Ecosystem, identity.Version, ranges, a.Versions) {
			out = append(out, a)
		}
	}
	return out
}

func matchingAffected(identity sbom.ComponentIdentity, componentPURL string, affected []osvAffected) []osvAffected {
	if identity.Status != sbom.IdentityResolved {
		return nil
	}
	componentPackagePURL := packagePURL(componentPURL)
	out := make([]osvAffected, 0, len(affected))
	for _, current := range affected {
		matchesName := current.Package.Ecosystem != "" && current.Package.Name != "" &&
			strings.EqualFold(current.Package.Ecosystem, identity.Ecosystem) && strings.EqualFold(current.Package.Name, identity.Package)
		matchesPURL := current.Package.PURL != "" && componentPackagePURL != "" && packagePURL(current.Package.PURL) == componentPackagePURL
		if matchesName || matchesPURL {
			out = append(out, current)
		}
	}
	return out
}

func packagePURL(value string) string {
	value = strings.TrimSpace(value)
	if index := strings.IndexAny(value, "?#"); index >= 0 {
		value = value[:index]
	}
	if slash := strings.IndexByte(value, '/'); slash >= 0 {
		if at := strings.LastIndexByte(value, '@'); at > slash {
			value = value[:at]
		}
	}
	return value
}

func validatedFixedVersions(identity sbom.ComponentIdentity, affected []osvAffected) ([]string, []string) {
	if identity.Status != sbom.IdentityResolved {
		return nil, nil
	}
	ranges := make([]advisory.Range, 0)
	candidates := make([]string, 0)
	for _, current := range affected {
		for _, osvRange := range current.Ranges {
			converted := advisory.Range{Type: strings.ToUpper(strings.TrimSpace(osvRange.Type))}
			for _, event := range osvRange.Events {
				converted.Events = append(converted.Events, advisory.Event{
					Introduced: event["introduced"], Fixed: event["fixed"], LastAffected: event["last_affected"],
				})
				candidates = append(candidates, event["fixed"])
			}
			ranges = append(ranges, converted)
		}
	}
	valid := map[string]bool{}
	rejected := map[string]bool{}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		comparison, comparable := advisory.CompareVersions(identity.Ecosystem, identity.Version, candidate)
		if candidate == "" || !comparable || comparison >= 0 || advisory.Affected(identity.Ecosystem, candidate, ranges, nil) {
			if candidate != "" {
				rejected[candidate] = true
			}
			continue
		}
		valid[candidate] = true
	}
	return sortedKeys(valid), sortedKeys(rejected)
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// affectedSymbols collects advisory-provided affected symbols (the Go vuln DB exposes them via
// affected[].ecosystem_specific.imports[].symbols), qualified as importPath.Symbol when a path is set.
func affectedSymbols(affected []osvAffected) []string {
	var out []string
	for _, a := range affected {
		for _, imp := range a.EcosystemSpecific.Imports {
			for _, s := range imp.Symbols {
				if s == "" {
					continue
				}
				if imp.Path != "" {
					out = append(out, imp.Path+"."+s)
				} else {
					out = append(out, s)
				}
			}
		}
		// RustSec's already-qualified "crate::Type::method" functions (parallel to imports[].symbols).
		for _, fn := range a.EcosystemSpecific.Affects.Functions {
			if fn != "" {
				out = append(out, fn)
			}
		}
	}
	return out
}

func preferCVE(id string, aliases []string) string {
	if strings.HasPrefix(id, "CVE-") {
		return id
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return id
}

func mapSeverityLabel(s string) shared.Severity {
	return shared.SeverityFromLabel(s) // shared with the owned advisory parser so both agree on bands
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// dedupVulns collapses the same advisory on the same component+version (OSV often
// returns several records – e.g. GHSA and PYSEC – aliasing one CVE), keeping the
// richest record: highest severity, then a known fix, then a CVSS vector.
func dedupRaws(raws []vulnerability.RawFinding) []vulnerability.RawFinding {
	type key struct{ id, comp, ver string }
	idx := map[key]int{}
	out := make([]vulnerability.RawFinding, 0, len(raws))
	for _, v := range raws {
		k := key{v.AdvisoryID, v.Component, v.Version}
		if i, ok := idx[k]; ok {
			// Union symbols across duplicates BEFORE picking the richer record, so a RustSec advisory's
			// affected functions are not lost when a GHSA alias (which carries none) wins on severity/fix.
			merged := unionSymbols(out[i].AffectedSymbols, v.AffectedSymbols)
			if richerRaw(v, out[i]) {
				out[i] = v
			}
			out[i].AffectedSymbols = merged
			continue
		}
		idx[k] = len(out)
		out = append(out, v)
	}
	return out
}

// unionSymbols merges two affected-symbol lists, de-duplicated and order-preserving (a is kept ahead of b).
func unionSymbols(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range b {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func richerRaw(a, b vulnerability.RawFinding) bool {
	if ra, rb := sevRank(a.Severity), sevRank(b.Severity); ra != rb {
		return ra > rb
	}
	if (a.FixedVersion != "") != (b.FixedVersion != "") {
		return a.FixedVersion != ""
	}
	return a.CVSSVector != "" && b.CVSSVector == ""
}

func sevRank(s shared.Severity) int {
	switch s {
	case shared.SeverityCritical:
		return 5
	case shared.SeverityHigh:
		return 4
	case shared.SeverityMedium:
		return 3
	case shared.SeverityLow:
		return 2
	case shared.SeverityInfo:
		return 1
	default:
		return 0
	}
}
