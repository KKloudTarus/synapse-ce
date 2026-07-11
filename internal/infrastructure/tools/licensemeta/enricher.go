// Package licensemeta enriches SBOM components with license metadata from package
// registries (license recovery). Syft emits little or no license data
// when scanning un-installed source, so this fills the gap by looking each
// component up by PURL on deps.dev (one HTTP backend covering npm / PyPI / Maven /
// Go / RubyGems / Cargo / NuGet). It is best-effort: a lookup failure records an
// UnknownReason on the component rather than failing the scan. HTTP only, no
// secrets, context-bounded.
package licensemeta

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const defaultBaseURL = "https://api.deps.dev"

// maxConcurrent bounds outbound lookups so a large SBOM can't hammer the registry.
const maxConcurrent = 8

// maxResponseBytes caps the deps.dev response body we decode, so a compromised/MITM
// registry response can't drive unbounded memory use.
const maxResponseBytes = 4 << 20

// Enricher resolves missing licenses via deps.dev.
type Enricher struct {
	baseURL string
	client  *http.Client
}

// New returns an enricher. baseURL defaults to deps.dev; client defaults to 15s.
func New(baseURL string, client *http.Client) *Enricher {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultBaseURL
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &Enricher{baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

var _ ports.LicenseEnricher = (*Enricher)(nil)

// Enrich fills licenses for components that have none, in place. Components that
// already carry a license are marked source=sbom; resolved ones source=registry;
// the rest get an UnknownReason. Concurrency-bounded; results are cached per PURL
// within the call so duplicate components cost one lookup.
func (e *Enricher) Enrich(ctx context.Context, comps []sbom.Component) []sbom.Component {
	type cacheEntry struct {
		lics   []sbom.License
		reason string
	}
	cache := map[string]cacheEntry{}
	var mu sync.Mutex
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for i := range comps {
		c := &comps[i]
		if len(c.Licenses) > 0 && !onlyUnresolvedLicenseEvidence(c.Licenses) {
			if strings.TrimSpace(c.LicenseSource) == "" {
				c.LicenseSource = sbom.LicenseSourceSBOM
			}
			if strings.TrimSpace(c.LicenseConfidence) == "" {
				c.LicenseConfidence = "declared"
			}
			continue
		}
		// Only unresolved placeholder evidence (sha256:/LicenseRef-/unknown) survived – drop
		// it so a successful registry lookup replaces it cleanly (matches the chain enrichers)
		// rather than mislabeling a placeholder as a declared SBOM license.
		c.Licenses = nil
		// Classify WHY a license can't be resolved precisely, instead of
		// labeling everything "unsupported_ecosystem". First-party modules + the
		// project's own unversioned code aren't third-party gaps.
		if c.FirstParty {
			c.UnknownReason = sbom.ReasonFirstPartyModule
			c.LicenseConfidence = "unknown"
			continue
		}
		if c.PURL == "" {
			c.UnknownReason = sbom.ReasonLocalComponent
			c.LicenseConfidence = "unknown"
			continue
		}
		if !sbom.IsResolvedVersion(c.Version) {
			c.UnknownReason = sbom.ReasonNoVersion
			c.LicenseConfidence = "unknown"
			continue
		}
		sys, name, ver, ok := parsePURL(c.PURL)
		if !ok {
			c.UnknownReason = sbom.ReasonUnsupportedEco
			c.LicenseConfidence = "unknown"
			continue
		}
		wg.Add(1)
		sem <- struct{}{} // bound goroutine creation, not just in-flight HTTP, for a huge SBOM
		go func(c *sbom.Component, sys, name, ver string) {
			defer wg.Done()
			defer func() { <-sem }()

			key := sys + "/" + name + "@" + ver
			mu.Lock()
			ce, hit := cache[key]
			mu.Unlock()
			if !hit {
				lics, reason := e.lookup(ctx, sys, name, ver)
				ce = cacheEntry{lics: lics, reason: reason}
				mu.Lock()
				cache[key] = ce
				mu.Unlock()
			}
			if len(ce.lics) > 0 {
				c.Licenses = ce.lics
				c.LicenseSource = sbom.LicenseSourceRegistry
				c.LicenseConfidence = "registry"
			} else {
				c.UnknownReason = ce.reason
				c.LicenseConfidence = "unknown"
			}
		}(c, sys, name, ver)
	}
	wg.Wait()
	return comps
}

// lookup queries deps.dev for one version's licenses, returning the licenses and,
// on failure, the reason it stayed unknown.
func (e *Enricher) lookup(ctx context.Context, sys, name, ver string) ([]sbom.License, string) {
	u := fmt.Sprintf("%s/v3/systems/%s/packages/%s/versions/%s",
		e.baseURL, sys, url.PathEscape(name), url.PathEscape(ver))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, sbom.ReasonResolutionFailed
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, sbom.ReasonRegistryUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, sbom.ReasonMetadataMissing
	}
	if resp.StatusCode != http.StatusOK {
		return nil, sbom.ReasonRegistryUnavailable
	}
	var body struct {
		Licenses []string `json:"licenses"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&body); err != nil {
		return nil, sbom.ReasonResolutionFailed
	}
	if len(body.Licenses) == 0 {
		return nil, sbom.ReasonNoLicenseDeclared
	}
	var out []sbom.License
	for _, l := range body.Licenses {
		l = strings.TrimSpace(l)
		if l == "" || strings.EqualFold(l, "non-standard") {
			continue
		}
		out = append(out, sbom.License{SPDXID: l, Name: l})
	}
	if len(out) == 0 {
		return nil, sbom.ReasonNoLicenseDeclared
	}
	return out, ""
}

// parsePURL maps a PURL to a (deps.dev system, name, version) triple. Returns
// ok=false for ecosystems deps.dev does not serve.
func parsePURL(purl string) (system, name, version string, ok bool) {
	if !strings.HasPrefix(purl, "pkg:") {
		return "", "", "", false
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	// strip qualifiers (?...) and subpath (#...)
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return "", "", "", false
	}
	typ := strings.ToLower(rest[:slash])
	nameVer := rest[slash+1:]
	at := strings.LastIndex(nameVer, "@")
	if at < 0 {
		return "", "", "", false
	}
	rawName := nameVer[:at]
	version, _ = url.PathUnescape(nameVer[at+1:])
	sys, ok := systemForType[typ]
	if !ok {
		return "", "", "", false
	}
	name = registryName(typ, rawName)
	if name == "" || version == "" {
		return "", "", "", false
	}
	return sys, name, version, true
}

var systemForType = map[string]string{
	"npm":    "npm",
	"pypi":   "pypi",
	"maven":  "maven",
	"golang": "go",
	"gem":    "rubygems",
	"cargo":  "cargo",
	"nuget":  "nuget",
}

// registryName converts the PURL name (possibly namespaced) to the registry's
// package identifier. Maven uses group:artifact; npm scoped uses @scope/name.
func registryName(typ, rawName string) string {
	decoded, _ := url.PathUnescape(rawName)
	switch typ {
	case "maven":
		// pkg:maven/<group>/<artifact> -> group:artifact
		if i := strings.LastIndex(decoded, "/"); i >= 0 {
			return decoded[:i] + ":" + decoded[i+1:]
		}
		return decoded
	case "npm":
		// scoped pkg:npm/%40scope/name -> @scope/name (PathUnescape already gave @)
		return decoded
	default:
		return decoded
	}
}
