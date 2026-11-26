// Package risk enriches vulnerabilities with CISA KEV + FIRST EPSS so they can be
// ordered by real risk priority (KEV -> EPSS x CVSS). It is BEST-EFFORT: a data
// source outage degrades to unenriched vulns and never fails the scan.
package risk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	defaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	defaultEPSSURL = "https://api.first.org/data/v1/epss"
	kevTTL         = 24 * time.Hour
	epssBatch      = 100
	maxKEVBytes    = 32 << 20 // cap the KEV feed read (defensive vs a poisoned/huge mirror)
	maxEPSSBytes   = 4 << 20  // cap one EPSS batch response
)

// Enricher loads the CISA KEV catalog (cached with a TTL) and queries FIRST EPSS
// per scan for the CVE ids present.
type Enricher struct {
	kevURL  string
	epssURL string
	client  *http.Client

	mu         sync.Mutex
	kev        map[string]struct{}
	kevVersion string
	kevAt      time.Time
}

// New returns an enricher. URLs default to CISA / FIRST.org. A nil client gets a 30s safehttp
// client: public addresses only for the default endpoints, safehttp.OperatorPolicy once the
// operator configures a mirror; no redirects, no proxy.
func New(kevURL, epssURL string, client *http.Client) *Enricher {
	if client == nil {
		client = safehttp.NewClient(30*time.Second, safehttp.EndpointPolicy(kevURL, epssURL))
	}
	if strings.TrimSpace(kevURL) == "" {
		kevURL = defaultKEVURL
	}
	if strings.TrimSpace(epssURL) == "" {
		epssURL = defaultEPSSURL
	}
	return &Enricher{
		kevURL:  strings.TrimRight(kevURL, "/"),
		epssURL: strings.TrimRight(epssURL, "/"),
		client:  client,
	}
}

var _ ports.RiskEnricher = (*Enricher)(nil)

// Enrich annotates each vuln with KEV + EPSS. Best-effort: a source failure leaves
// the affected fields zero (the scan still succeeds). A KEV catalogue that could not
// be read is named in RiskResult.Unavailable so the zero is not mistaken for "no match".
func (e *Enricher) Enrich(ctx context.Context, vulns []vulnerability.Vulnerability) ports.RiskResult {
	versions := map[string]string{}
	cves := cveIDs(vulns)
	kev, kevVer, kevErr := e.loadKEV(ctx)
	if kevVer != "" {
		versions["kev-catalog"] = kevVer
	}
	// An unread catalogue leaves every vuln at KEV=false, the same as a catalogue that matched nothing, so it
	// is named in the result. With no CVE id to look up there is nothing the catalogue could have flagged.
	var unavailable map[string]string
	if kevErr != nil && len(cves) > 0 {
		unavailable = map[string]string{"kev": failureCause(kevErr)}
	}
	epss, epssDate := e.queryEPSS(ctx, cves)
	if epssDate != "" {
		versions["epss-date"] = epssDate
	}

	kevHits, epssHits := 0, 0
	out := make([]vulnerability.Vulnerability, len(vulns))
	for i, v := range vulns {
		// KEV + EPSS are CVE-keyed. The vuln's canonical id may be a GHSA, so match
		// against EVERY CVE candidate: the id plus each detection's advisory id.
		for _, cve := range cveCandidates(v) {
			if _, ok := kev[cve]; ok && !v.KEV {
				v.KEV = true
				kevHits++
			}
			if s, ok := epss[cve]; ok && s > v.EPSS {
				v.EPSS = s
			}
		}
		if v.EPSS > 0 {
			epssHits++
		}
		out[i] = v
	}
	return ports.RiskResult{
		Vulns:    out,
		Versions: versions,
		Matches:  map[string]int{"kev": kevHits, "epss": epssHits},

		Unavailable: unavailable,
	}
}

// cveCandidates returns every CVE id associated with a vuln: its canonical id (if
// a CVE) plus each detection's advisory id that is a CVE – so KEV/EPSS match even
// when the canonical id is a GHSA.
func cveCandidates(v vulnerability.Vulnerability) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(id string) {
		if !strings.HasPrefix(id, "CVE-") {
			return
		}
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	add(v.ID)
	for _, d := range v.Detections {
		add(d.AdvisoryID)
	}
	return out
}

// loadKEV returns the catalogue, refreshing it when the cache is older than kevTTL. The error is non-nil
// only when there is NO catalogue to serve: a failed refresh that still has an earlier catalogue keeps
// serving it (its date stays in the report's versions), so the caller can tell "nothing was checked" from
// "checked against an older copy".
func (e *Enricher) loadKEV(ctx context.Context) (map[string]struct{}, string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.kev != nil && time.Since(e.kevAt) < kevTTL {
		return e.kev, e.kevVersion, nil
	}
	set, ver, err := e.fetchKEV(ctx)
	if err != nil {
		if e.kev != nil {
			return e.kev, e.kevVersion, nil // keep the prior cache
		}
		return nil, "", err
	}
	e.kev, e.kevVersion, e.kevAt = set, ver, time.Now()
	return set, ver, nil // return the freshly-built map (never read e.kev outside the lock)
}

// statusError is a non-200 answer from a feed. Only the code is kept: a body can echo credentials or
// carry an operator's error page, and neither belongs in a scan report.
type statusError struct{ code int }

func (e statusError) Error() string { return fmt.Sprintf("kev: status %d", e.code) }

var (
	errMalformed = errors.New("kev: malformed catalogue")
	errBadURL    = errors.New("kev: invalid feed URL")
)

// failureCause reduces a feed error to a short class that is safe to print and to put in a report. The
// error text itself is never used: a transport error quotes the full request URL, and an operator may have
// put a token or user:password in a mirror's SYNAPSE_KEV_URL.
func failureCause(err error) string {
	var status statusError
	var netErr net.Error
	switch {
	case errors.As(err, &status):
		return "http " + strconv.Itoa(status.code)
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case errors.Is(err, errMalformed):
		return "malformed response"
	case errors.Is(err, errBadURL):
		return "invalid URL"
	default:
		return "network error"
	}
}

func (e *Enricher) fetchKEV(ctx context.Context) (map[string]struct{}, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.kevURL, nil)
	if err != nil {
		return nil, "", errBadURL // not wrapped: the parse error quotes the URL
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, "", statusError{code: resp.StatusCode}
	}
	var doc struct {
		CatalogVersion  string `json:"catalogVersion"`
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxKEVBytes)).Decode(&doc); err != nil {
		return nil, "", fmt.Errorf("%w: %w", errMalformed, err)
	}
	set := make(map[string]struct{}, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		if v.CveID != "" {
			set[v.CveID] = struct{}{}
		}
	}
	return set, doc.CatalogVersion, nil
}

func (e *Enricher) queryEPSS(ctx context.Context, cves []string) (map[string]float64, string) {
	out := make(map[string]float64)
	date := ""
	for i := 0; i < len(cves); i += epssBatch {
		end := i + epssBatch
		if end > len(cves) {
			end = len(cves)
		}
		scores, d, err := e.fetchEPSS(ctx, cves[i:end])
		if err != nil {
			continue // best-effort
		}
		if d != "" {
			date = d
		}
		for k, v := range scores {
			out[k] = v
		}
	}
	return out, date
}

func (e *Enricher) fetchEPSS(ctx context.Context, cves []string) (map[string]float64, string, error) {
	u := e.epssURL + "?cve=" + url.QueryEscape(strings.Join(cves, ","))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("epss: status %d", resp.StatusCode)
	}
	var doc struct {
		Data []struct {
			CVE  string `json:"cve"`
			EPSS string `json:"epss"`
			Date string `json:"date"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxEPSSBytes)).Decode(&doc); err != nil {
		return nil, "", err
	}
	out := make(map[string]float64, len(doc.Data))
	date := ""
	for _, d := range doc.Data {
		// clamp to the valid EPSS range [0,1]; this also drops NaN/Inf (NaN fails >= 0),
		// which would otherwise destabilize the risk sort.
		if f, err := strconv.ParseFloat(d.EPSS, 64); err == nil && f >= 0 && f <= 1 {
			out[d.CVE] = f
		}
		if d.Date != "" {
			date = d.Date
		}
	}
	return out, date, nil
}

// cveIDs returns the distinct CVE ids (KEV + EPSS are keyed by CVE; GHSA/PYSEC ids
// are skipped since neither source indexes them).
func cveIDs(vulns []vulnerability.Vulnerability) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, v := range vulns {
		for _, cve := range cveCandidates(v) {
			if _, ok := seen[cve]; !ok {
				seen[cve] = struct{}{}
				out = append(out, cve)
			}
		}
	}
	return out
}
