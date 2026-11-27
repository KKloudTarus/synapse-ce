package risk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

func TestEnrichAndSort(t *testing.T) {
	kev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"catalogVersion":"2026.06.20","vulnerabilities":[{"cveID":"CVE-2"}]}`))
	}))
	defer kev.Close()
	epss := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"cve":"CVE-1","epss":"0.90","date":"2026-06-20"},{"cve":"CVE-2","epss":"0.10","date":"2026-06-20"}]}`))
	}))
	defer epss.Close()

	e := New(kev.URL, epss.URL, nil)
	vulns := []vulnerability.Vulnerability{
		{ID: "CVE-1", CVSSScore: 9.0},   // high EPSS, not KEV
		{ID: "CVE-2", CVSSScore: 5.0},   // KEV (ranks first), low EPSS
		{ID: "GHSA-x", CVSSScore: 10.0}, // not a CVE → never enriched
	}
	res := e.Enrich(context.Background(), vulns)

	byID := map[string]vulnerability.Vulnerability{}
	for _, v := range res.Vulns {
		byID[v.ID] = v
	}
	if !byID["CVE-2"].KEV || byID["CVE-1"].KEV {
		t.Errorf("KEV flag wrong: CVE-1=%v CVE-2=%v", byID["CVE-1"].KEV, byID["CVE-2"].KEV)
	}
	if byID["CVE-1"].EPSS != 0.90 || byID["CVE-2"].EPSS != 0.10 {
		t.Errorf("EPSS not set: CVE-1=%v CVE-2=%v", byID["CVE-1"].EPSS, byID["CVE-2"].EPSS)
	}
	if byID["GHSA-x"].EPSS != 0 || byID["GHSA-x"].KEV {
		t.Error("non-CVE id must not be enriched")
	}
	if res.Versions["kev-catalog"] != "2026.06.20" || res.Versions["epss-date"] != "2026-06-20" {
		t.Errorf("provenance versions = %+v", res.Versions)
	}

	vulnerability.SortByRisk(res.Vulns)
	// KEV (CVE-2) first despite lower CVSS; then CVE-1 (0.9 x 9.0 = 8.1) above non-enriched GHSA-x (0).
	if res.Vulns[0].ID != "CVE-2" {
		t.Errorf("KEV must rank first, got %s", res.Vulns[0].ID)
	}
	if res.Vulns[1].ID != "CVE-1" {
		t.Errorf("CVE-1 (risk 8.1) should outrank GHSA-x, got %s", res.Vulns[1].ID)
	}
}

// regression: a vuln whose CANONICAL id is a GHSA but which carries a CVE
// in a detection must still match KEV/EPSS via that detection CVE.
func TestEnrichMatchesCVEViaDetection(t *testing.T) {
	kev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"catalogVersion":"2026.06.20","vulnerabilities":[{"cveID":"CVE-2024-1234"}]}`))
	}))
	defer kev.Close()
	epss := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"cve":"CVE-2024-1234","epss":"0.5","date":"2026-06-20"}]}`))
	}))
	defer epss.Close()

	e := New(kev.URL, epss.URL, nil)
	vulns := []vulnerability.Vulnerability{{
		ID:        "GHSA-aaaa-bbbb-cccc", // canonical is GHSA (no CVE alias chosen)
		CVSSScore: 7.0,
		Detections: []vulnerability.Detection{
			{Source: "osv", AdvisoryID: "GHSA-aaaa-bbbb-cccc"},
			{Source: "grype", AdvisoryID: "CVE-2024-1234"}, // the CVE lives here
		},
	}}
	res := e.Enrich(context.Background(), vulns)
	if !res.Vulns[0].KEV {
		t.Error("KEV must match via the detection CVE even when canonical id is GHSA")
	}
	if res.Vulns[0].EPSS != 0.5 {
		t.Errorf("EPSS via detection CVE = %v, want 0.5", res.Vulns[0].EPSS)
	}
	if res.Matches["kev"] != 1 || res.Matches["epss"] != 1 {
		t.Errorf("hit-rate = %+v", res.Matches)
	}
}

func TestEnrichBestEffort(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer down.Close()

	e := New(down.URL, down.URL, nil)
	res := e.Enrich(context.Background(), []vulnerability.Vulnerability{{ID: "CVE-1", CVSSScore: 7.0}})
	if len(res.Vulns) != 1 || res.Vulns[0].KEV || res.Vulns[0].EPSS != 0 {
		t.Errorf("source outage must degrade to unenriched, got %+v", res.Vulns)
	}
	// On outage no DB versions are recorded, and the hit-rate is honestly 0/0.
	if res.Versions["kev-catalog"] != "" || res.Versions["epss-date"] != "" {
		t.Errorf("no DB versions expected on outage, got %+v", res.Versions)
	}
	if res.Matches["kev"] != 0 || res.Matches["epss"] != 0 {
		t.Errorf("hit-rate must be 0/0 on outage, got %+v", res.Matches)
	}
}

// TestEnrichMatchesCVEViaAlias: an advisory reported under its GHSA id because it aliases two CVEs (pillow's
// GHSA-j7hp-h8jx-5ppr: CVE-2023-4863 and its rejected duplicate CVE-2023-5129) still gets the KEV flag and
// EPSS of the CVE in the catalogue.
func TestEnrichMatchesCVEViaAlias(t *testing.T) {
	kev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"catalogVersion":"2026.06.20","vulnerabilities":[{"cveID":"CVE-2023-4863"}]}`))
	}))
	defer kev.Close()
	epss := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"cve":"CVE-2023-4863","epss":"0.9","date":"2026-06-20"}]}`))
	}))
	defer epss.Close()

	e := New(kev.URL, epss.URL, nil)
	res := e.Enrich(context.Background(), []vulnerability.Vulnerability{{
		ID:         "GHSA-j7hp-h8jx-5ppr",
		Aliases:    []string{"CVE-2023-4863", "CVE-2023-5129"},
		Detections: []vulnerability.Detection{{Source: "osv", AdvisoryID: "GHSA-j7hp-h8jx-5ppr"}},
	}})
	if !res.Vulns[0].KEV || res.Vulns[0].EPSS != 0.9 {
		t.Errorf("KEV=%v EPSS=%v, want true and 0.9 via the CVE alias", res.Vulns[0].KEV, res.Vulns[0].EPSS)
	}
}
