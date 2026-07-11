// Package risk enriches vulnerabilities with CISA KEV + FIRST EPSS so they can be
// ordered by real risk priority (KEV -> EPSS x CVSS). It is BEST-EFFORT: a data
// source outage degrades to unenriched vulns and never fails the scan.
package risk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
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

// New returns an enricher. URLs default to CISA / FIRST.org; client defaults to 30s.
func New(kevURL, epssURL string, client *http.Client) *Enricher {
	if strings.TrimSpace(kevURL) == "" {
		kevURL = defaultKEVURL
	}
	if strings.TrimSpace(epssURL) == "" {
		epssURL = defaultEPSSURL
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Enricher{
		kevURL:  strings.TrimRight(kevURL, "/"),
		epssURL: strings.TrimRight(epssURL, "/"),
		client:  client,
	}
}

var _ ports.RiskEnricher = (*Enricher)(nil)

// Enrich annotates each vuln with KEV + EPSS. Best-effort: a source failure leaves
// the affected fields zero (the scan still succeeds).
func (e *Enricher) Enrich(ctx context.Context, vulns []vulnerability.Vulnerability) ports.RiskResult {
	versions := map[string]string{}
	kev, kevVer := e.loadKEV(ctx)
	if kevVer != "" {
		versions["kev-catalog"] = kevVer
	}
	epss, epssDate := e.queryEPSS(ctx, cveIDs(vulns))
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

func (e *Enricher) loadKEV(ctx context.Context) (map[string]struct{}, string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.kev != nil && time.Since(e.kevAt) < kevTTL {
		return e.kev, e.kevVersion
	}
	set, ver, err := e.fetchKEV(ctx)
	if err != nil {
		return e.kev, e.kevVersion // keep any prior cache (possibly nil)
	}
	e.kev, e.kevVersion, e.kevAt = set, ver, time.Now()
	return set, ver // return the freshly-built map (never read e.kev outside the lock)
}

func (e *Enricher) fetchKEV(ctx context.Context) (map[string]struct{}, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.kevURL, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("kev: status %d", resp.StatusCode)
	}
	var doc struct {
		CatalogVersion  string `json:"catalogVersion"`
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxKEVBytes)).Decode(&doc); err != nil {
		return nil, "", err
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
