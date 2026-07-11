package nvd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

// fakeNVD serves canned CVSS for specific CVE ids; everything else returns an empty result
// (a CVE NVD has not scored). It also records the apiKey header + call count.
func fakeNVD(t *testing.T, gotKey *string, calls *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		if gotKey != nil {
			*gotKey = r.Header.Get("apiKey")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("cveId") {
		case "CVE-2025-2361": // v3.1 high (7.5) + a v2 we must NOT pick over v3.1
			_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2025-2361","metrics":{
				"cvssMetricV31":[{"cvssData":{"baseScore":7.5,"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}}],
				"cvssMetricV2":[{"cvssData":{"baseScore":3.5,"vectorString":"AV:N/AC:M/Au:S/C:N/I:P/A:N"}}]}}}]}`))
		case "CVE-2020-0001": // only v2 (medium 5.0)
			_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2020-0001","metrics":{
				"cvssMetricV2":[{"cvssData":{"baseScore":5.0,"vectorString":"AV:N/AC:L/Au:N/C:P/I:N/A:N"}}]}}}]}`))
		default: // CVE-2021-3601 etc.: no published CVSS → empty metrics
			_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"x","metrics":{}}}]}`))
		}
	}))
}

func newTestEnricher(url string) *Enricher {
	e := New(url, "", nil)
	e.interval = 0 // no rate pacing in tests
	return e
}

func TestEnrichBackfillsUnknownSeverities(t *testing.T) {
	var calls int32
	srv := fakeNVD(t, nil, &calls)
	defer srv.Close()
	e := newTestEnricher(srv.URL)
	e.client = srv.Client()

	in := []vulnerability.Vulnerability{
		{ID: "CVE-2025-2361", Severity: shared.SeverityUnknown},              // → high via v3.1
		{ID: "CVE-2020-0001", Severity: shared.SeverityUnknown},              // → medium via v2
		{ID: "CVE-2021-3601", Severity: shared.SeverityUnknown},              // no CVSS → stays unknown
		{ID: "CVE-2019-1111", Severity: shared.SeverityHigh, CVSSScore: 8.1}, // already known → untouched, not queried
		{ID: "GHSA-aaaa-bbbb-cccc", Severity: shared.SeverityUnknown},        // not a CVE → skipped
	}
	res := e.Enrich(context.Background(), in)

	got := map[string]vulnerability.Vulnerability{}
	for _, v := range res.Vulns {
		got[v.ID] = v
	}
	if v := got["CVE-2025-2361"]; v.Severity != shared.SeverityHigh || v.CVSSScore != 7.5 || v.CVSSVector == "" {
		t.Errorf("CVE-2025-2361 backfill = %+v, want high/7.5/v3.1-vector", v)
	}
	if v := got["CVE-2020-0001"]; v.Severity != shared.SeverityMedium || v.CVSSScore != 5.0 {
		t.Errorf("CVE-2020-0001 backfill = %+v, want medium/5.0 (v2)", v)
	}
	if v := got["CVE-2021-3601"]; v.Severity != shared.SeverityUnknown {
		t.Errorf("CVE-2021-3601 has no CVSS → must stay unknown, got %s", v.Severity)
	}
	if v := got["CVE-2019-1111"]; v.Severity != shared.SeverityHigh || v.CVSSScore != 8.1 {
		t.Errorf("a KNOWN severity must never be overridden, got %+v", v)
	}
	if res.Matches != 2 {
		t.Errorf("matches = %d, want 2", res.Matches)
	}
	// Only the 3 unknown CVEs are queried – the known one and the GHSA are not.
	if calls != 3 {
		t.Errorf("NVD calls = %d, want 3 (only unknown CVE ids)", calls)
	}
}

func TestEnrichNoUnknownsIsNoOp(t *testing.T) {
	var calls int32
	srv := fakeNVD(t, nil, &calls)
	defer srv.Close()
	e := newTestEnricher(srv.URL)
	e.client = srv.Client()
	in := []vulnerability.Vulnerability{{ID: "CVE-2025-2361", Severity: shared.SeverityHigh}}
	res := e.Enrich(context.Background(), in)
	if res.Matches != 0 || calls != 0 {
		t.Errorf("no unknowns must be a no-op (0 calls), got matches=%d calls=%d", res.Matches, calls)
	}
}

func TestEnrichSendsAPIKey(t *testing.T) {
	var key string
	var calls int32
	srv := fakeNVD(t, &key, &calls)
	defer srv.Close()
	e := New(srv.URL, "secret-key", nil)
	e.interval = 0
	e.client = srv.Client()
	e.Enrich(context.Background(), []vulnerability.Vulnerability{{ID: "CVE-2025-2361", Severity: shared.SeverityUnknown}})
	if key != "secret-key" {
		t.Errorf("apiKey header = %q, want secret-key", key)
	}
}

func TestWithBudget(t *testing.T) {
	e := New("", "", nil)
	def := e.budget
	if e.WithBudget(5*time.Second).budget != 5*time.Second {
		t.Errorf("WithBudget(5s) = %v, want 5s", e.budget)
	}
	if e.WithBudget(0).budget != 5*time.Second { // non-positive is ignored, keeps the prior value
		t.Errorf("WithBudget(0) must keep the prior budget, got %v", e.budget)
	}
	if def <= 0 {
		t.Errorf("default budget must be positive, got %v", def)
	}
}

func TestEnrichBestEffortOnError(t *testing.T) {
	// An unreachable NVD must leave vulns unknown, never fail/panic.
	e := newTestEnricher("http://127.0.0.1:0") // invalid port → dial error
	in := []vulnerability.Vulnerability{{ID: "CVE-2025-2361", Severity: shared.SeverityUnknown}}
	res := e.Enrich(context.Background(), in)
	if res.Matches != 0 || res.Vulns[0].Severity != shared.SeverityUnknown {
		t.Errorf("unreachable NVD must degrade to unknown, got %+v", res.Vulns[0])
	}
}
