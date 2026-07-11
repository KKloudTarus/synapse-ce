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
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	defaultBaseURL = "https://api.osv.dev"
	maxBatch       = 1000     // OSV querybatch limit
	maxRespBytes   = 32 << 20 // cap a single response body
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
		if c.PURL != "" {
			items = append(items, item{compIdx: i, purl: c.PURL})
		}
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

	var out []vulnerability.RawFinding
	for _, id := range order {
		detail, err := s.vulnDetail(ctx, id)
		if err != nil {
			return nil, err
		}
		cis := make([]int, 0, len(idToComps[id]))
		for ci := range idToComps[id] {
			cis = append(cis, ci)
		}
		sort.Ints(cis)
		for _, ci := range cis {
			out = append(out, osvToRaw(doc.Components[ci], detail))
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv querybatch: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv querybatch: %w", err)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/v1/vulns/"+url.PathEscape(id), nil)
	if err != nil {
		return v, fmt.Errorf("osv vuln %s: new request: %w", id, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return v, fmt.Errorf("osv vuln %s: %w", id, err)
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
	Ranges            []osvRange `json:"ranges"`
	EcosystemSpecific struct {
		Imports []struct {
			Path    string   `json:"path"`
			Symbols []string `json:"symbols"`
		} `json:"imports"`
	} `json:"ecosystem_specific"`
}
type osvRange struct {
	Events []map[string]string `json:"events"`
}

// osvToRaw maps an OSV advisory + the affected component to a raw finding,
// deriving the CVSS base score + severity from the vector. Aliases (CVE/GHSA/OSV
// ids) are kept for cross-source correlation.
func osvToRaw(comp sbom.Component, v osvVuln) vulnerability.RawFinding {
	out := vulnerability.RawFinding{
		Source:       "osv",
		AdvisoryID:   preferCVE(v.ID, v.Aliases),
		Aliases:      append([]string{v.ID}, v.Aliases...),
		Severity:     shared.SeverityUnknown,
		Component:    comp.Name,
		Version:      comp.Version,
		FixedVersion: firstFixed(v.Affected),
		Description:  firstNonEmpty(v.Summary, v.Details),
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
	out.AffectedSymbols = affectedSymbols(v.Affected)
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
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return shared.SeverityCritical
	case "HIGH":
		return shared.SeverityHigh
	case "MODERATE", "MEDIUM":
		return shared.SeverityMedium
	case "LOW":
		return shared.SeverityLow
	default:
		return shared.SeverityUnknown
	}
}

func firstFixed(affected []osvAffected) string {
	for _, a := range affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if f := e["fixed"]; f != "" {
					return f
				}
			}
		}
	}
	return ""
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
			if richerRaw(v, out[i]) {
				out[i] = v
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, v)
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
