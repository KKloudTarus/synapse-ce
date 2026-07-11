// Package nvd backfills the severity of vulnerabilities the detection sources left UNKNOWN
// (an OSV-only distro CVE often carries no CVSS) by looking up the CVE's CVSS base score in
// the NVD CVE API. It implements ports.SeverityEnricher.
//
// Bounded + best-effort by design: NVD's per-CVE API is rate-limited (5 req / 30 s without an
// API key, 50 with one), so this NEVER blocks a scan – it works a time budget, gated by a rate
// limiter, and whatever it can't resolve in the budget stays unknown (no regression, no hang).
// It ONLY fills an unknown severity; it never overrides a severity a detection source set.
// Set SYNAPSE_NVD_API_KEY for real throughput; an empty store/outage simply backfills nothing.
package nvd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	defaultBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	defaultBudget  = 20 * time.Second
	// NVD rate windows: 5 req/30s anonymous, 50 req/30s with a key. We pace serially at the
	// sustained rate (with an immediate first request) to stay under the window without bursting.
	rateNoKey = 6 * time.Second
	rateKey   = 700 * time.Millisecond
)

// Enricher backfills unknown severities from NVD.
type Enricher struct {
	baseURL  string
	apiKey   string
	budget   time.Duration
	interval time.Duration // min gap between requests (NVD rate limit; smaller with an API key)
	client   *http.Client
}

var _ ports.SeverityEnricher = (*Enricher)(nil)

// New returns an NVD severity enricher. Empty baseURL uses the public NVD API; apiKey is the
// optional NVD API key (raises the rate limit, never logged). nil client gets a sane default.
func New(baseURL, apiKey string, client *http.Client) *Enricher {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultBaseURL
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	interval := rateNoKey
	if strings.TrimSpace(apiKey) != "" {
		interval = rateKey
	}
	return &Enricher{
		baseURL:  strings.TrimRight(baseURL, "/"),
		apiKey:   strings.TrimSpace(apiKey),
		budget:   defaultBudget,
		interval: interval,
		client:   client,
	}
}

// WithBudget overrides the total time budget for a single Enrich call (best-effort cap).
func (e *Enricher) WithBudget(d time.Duration) *Enricher {
	if d > 0 {
		e.budget = d
	}
	return e
}

// Enrich fills the severity + CVSS of vulnerabilities currently marked unknown, using NVD.
func (e *Enricher) Enrich(ctx context.Context, vulns []vulnerability.Vulnerability) ports.SeverityResult {
	res := ports.SeverityResult{Vulns: vulns, Source: "nvd"}

	// Distinct CVE ids that still need a severity. Skip everything else (most scans → no-op).
	need := make([]string, 0)
	seen := map[string]bool{}
	for _, v := range vulns {
		if v.Severity != shared.SeverityUnknown {
			continue
		}
		cve := cveID(v.ID)
		if cve == "" || seen[cve] {
			continue
		}
		seen[cve] = true
		need = append(need, cve)
	}
	if len(need) == 0 {
		return res
	}

	ctx, cancel := context.WithTimeout(ctx, e.budget)
	defer cancel()
	scores := e.fetchAll(ctx, need)
	if len(scores) == 0 {
		return res
	}

	for i := range vulns {
		if vulns[i].Severity != shared.SeverityUnknown {
			continue
		}
		s, ok := scores[cveID(vulns[i].ID)]
		if !ok {
			continue
		}
		vulns[i].Severity = shared.SeverityFromScore(s.score)
		vulns[i].CVSSScore = s.score
		vulns[i].CVSSVector = s.vector
		res.Matches++
	}
	return res
}

type cvss struct {
	score  float64
	vector string
}

// fetchAll queries NVD for each CVE serially, paced by the rate limiter, until the budget
// (ctx) expires. Whatever resolved is returned; the rest are simply left out (stay unknown).
func (e *Enricher) fetchAll(ctx context.Context, cves []string) map[string]cvss {
	out := make(map[string]cvss, len(cves))
	for i, cve := range cves {
		if i > 0 && e.interval > 0 { // pace subsequent requests; the first goes immediately
			select {
			case <-ctx.Done():
				return out
			case <-time.After(e.interval):
			}
		}
		if ctx.Err() != nil {
			return out
		}
		if c, ok := e.fetchOne(ctx, cve); ok {
			out[cve] = c
		}
	}
	return out
}

// fetchOne looks up one CVE's CVSS base score (preferring v3.1 > v3.0 > v2). Any error or a
// CVE with no published CVSS returns ok=false (best-effort: that vuln stays unknown).
func (e *Enricher) fetchOne(ctx context.Context, cve string) (cvss, bool) {
	u := e.baseURL + "?cveId=" + url.QueryEscape(cve)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return cvss{}, false
	}
	if e.apiKey != "" {
		req.Header.Set("apiKey", e.apiKey) // never logged
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return cvss{}, false
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return cvss{}, false
	}
	var body nvdResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); err != nil {
		return cvss{}, false
	}
	for _, vuln := range body.Vulnerabilities {
		m := vuln.CVE.Metrics
		for _, set := range [][]cvssMetric{m.V31, m.V30, m.V2} {
			if len(set) > 0 && set[0].CVSSData.BaseScore > 0 {
				return cvss{score: set[0].CVSSData.BaseScore, vector: set[0].CVSSData.VectorString}, true
			}
		}
	}
	return cvss{}, false
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID      string `json:"id"`
			Metrics struct {
				V31 []cvssMetric `json:"cvssMetricV31"`
				V30 []cvssMetric `json:"cvssMetricV30"`
				V2  []cvssMetric `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type cvssMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

// cveID returns the normalized CVE id (upper-cased) if s is a CVE-YYYY-NNNN, else "".
func cveID(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !strings.HasPrefix(s, "CVE-") {
		return ""
	}
	return s
}
