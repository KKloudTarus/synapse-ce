package sca

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedsbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/risk"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	log4shellKEV = `{"catalogVersion":"2026.06.20","vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`

	log4jPURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	// kevCredential stands for a token an operator put in the catalogue URL.
	kevCredential = "kev-url-credential"
)

func log4shellFinding() vulnerability.RawFinding {
	return vulnerability.RawFinding{
		Source: "static", AdvisoryID: "CVE-2021-44228", Component: "log4j-core", Version: "2.14.1",
		PackagePURL: log4jPURL, Severity: shared.SeverityCritical,
	}
}

func log4jSBOM() *sbom.SBOM {
	return &sbom.SBOM{Components: []sbom.Component{{Name: "log4j-core", Version: "2.14.1", PURL: log4jPURL}}}
}

// kevFeed serves the catalogue handler, and an empty EPSS answer, and returns an enricher reading both.
func kevFeed(t *testing.T, kev http.HandlerFunc) ports.RiskEnricher {
	t.Helper()
	kevSrv := httptest.NewServer(kev)
	t.Cleanup(kevSrv.Close)
	epssSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(epssSrv.Close)
	return risk.New(kevSrv.URL+"/kev.json?token="+kevCredential, epssSrv.URL, nil)
}

func scanLog4j(t *testing.T, enricher ports.RiskEnricher, raws ...vulnerability.RawFinding) *ScanResult {
	t.Helper()
	svc := NewService(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, nil, nil, nil, nil, nil, nil, nil,
		ports.Provenance{}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAudit{}, shared.SeverityInfo, 0,
		&fakeAcquirer{dir: t.TempDir()}, &fakeDetector{}, staticSBOM{doc: log4jSBOM()},
		[]ports.DetectionSource{staticVuln(raws)}, enricher, fakeLic{}, nil)
	res, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
	if err != nil {
		t.Fatalf("a risk feed outage must never fail the scan: %v", err)
	}
	return res
}

func kevWarnings(res *ScanResult) []string {
	var out []string
	for _, w := range res.SourceWarnings {
		if strings.Contains(w, "CISA KEV") {
			out = append(out, w)
		}
	}
	return out
}

func reportJSON(t *testing.T, res *ScanResult) string {
	t.Helper()
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// The defect: a catalogue the scan could not read produced KEV=false and a successful risk step, which
// reads as "none of these vulnerabilities is known-exploited".
func TestScanReportsAnUnreadableKEVCatalogue(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		cause   string
	}{
		{"403 from the catalogue host", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "denied", http.StatusForbidden) }, "http 403"},
		{"500", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }, "http 500"},
		{"malformed JSON", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }, "malformed response"},
	}
	baseline := scanLog4j(t, kevFeed(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(log4shellKEV)) }), log4shellFinding())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := scanLog4j(t, kevFeed(t, tc.handler), log4shellFinding())

			if got := res.RiskUnavailable["kev"]; got != tc.cause {
				t.Fatalf("RiskUnavailable[kev] = %q, want %q", got, tc.cause)
			}
			if !strings.Contains(reportJSON(t, res), `"risk_unavailable":{"kev":"`+tc.cause+`"}`) {
				t.Errorf("the JSON report lacks the machine-readable signal: %s", reportJSON(t, res))
			}
			warnings := kevWarnings(res)
			if len(warnings) != 1 || !strings.Contains(warnings[0], "CISA KEV catalogue could not be read ("+tc.cause+")") ||
				!strings.Contains(warnings[0], "not checked") || !strings.Contains(warnings[0], "SYNAPSE_KEV_URL") {
				t.Fatalf("want one warning naming the cause and the setting, got %q", warnings)
			}
			if strings.Contains(strings.Join(res.SourceWarnings, "\n"), kevCredential) || strings.Contains(reportJSON(t, res), kevCredential) {
				t.Errorf("the catalogue URL credential reached the report: %q", res.SourceWarnings)
			}
			if res.RiskMatches["kev"] != 0 || res.Vulnerabilities[0].KEV {
				t.Errorf("nothing was checked, so nothing can be flagged: %+v kev=%v", res.RiskMatches, res.Vulnerabilities[0].KEV)
			}
			// The outage is a warning, not a coverage loss: --require-complete and the exit code are unchanged.
			if res.EngineCoverage != baseline.EngineCoverage || res.Completeness.Confident != baseline.Completeness.Confident {
				t.Errorf("coverage changed by a feed outage: got %+v / %v, want %+v / %v",
					res.EngineCoverage, res.Completeness.Confident, baseline.EngineCoverage, baseline.Completeness.Confident)
			}
			if len(res.Findings) != len(baseline.Findings) {
				t.Errorf("findings changed: %d vs %d", len(res.Findings), len(baseline.Findings))
			}
		})
	}
}

func TestScanWithAReadableKEVCatalogueReportsNoOutage(t *testing.T) {
	flagged := scanLog4j(t, kevFeed(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(log4shellKEV)) }), log4shellFinding())
	missed := scanLog4j(t, kevFeed(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"catalogVersion":"2026.06.20","vulnerabilities":[{"cveID":"CVE-2000-0001"}]}`))
	}), log4shellFinding())

	if !flagged.Vulnerabilities[0].KEV || flagged.RiskMatches["kev"] != 1 {
		t.Fatalf("setup: the catalogue lists the CVE: kev=%v matches=%+v", flagged.Vulnerabilities[0].KEV, flagged.RiskMatches)
	}
	for name, res := range map[string]*ScanResult{"matched": flagged, "nothing matched": missed} {
		if len(res.RiskUnavailable) != 0 || len(kevWarnings(res)) != 0 {
			t.Errorf("%s: a catalogue that was read must not be reported unavailable: %+v %q", name, res.RiskUnavailable, res.SourceWarnings)
		}
		if strings.Contains(reportJSON(t, res), "risk_unavailable") {
			t.Errorf("%s: the field must be absent from the JSON when every feed was read", name)
		}
	}
}

// --offline builds no enricher (see egress.RiskFeeds), and a scan with no vulnerability asks nothing of the
// catalogue: neither may report an outage.
func TestScanWithoutAKEVLookupReportsNoOutage(t *testing.T) {
	forbidden := func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "denied", http.StatusForbidden) }
	cases := map[string]*ScanResult{
		"no enricher (offline)":    scanLog4j(t, nil, log4shellFinding()),
		"no vulnerabilities found": scanLog4j(t, kevFeed(t, forbidden)),
	}
	for name, res := range cases {
		if len(res.RiskUnavailable) != 0 || len(kevWarnings(res)) != 0 {
			t.Errorf("%s: no lookup was needed, yet %+v %q", name, res.RiskUnavailable, res.SourceWarnings)
		}
	}
}

// An imported SBOM goes through a second pipeline with its own result builder.
func TestImportedSBOMScanReportsAnUnreadableKEVCatalogue(t *testing.T) {
	doc := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","metadata":{"component":{"name":"product-service"}},` +
		`"components":[{"group":"org.apache.logging.log4j","name":"log4j-core","version":"2.14.1","purl":"` + log4jPURL + `"}]}`)
	store := memory.NewImportedSBOMStore()
	if err := store.SaveActive(context.Background(), importedsbom.Record{
		ID: "sbom-1", TenantID: "tenant-1", EngagementID: "e1", Filename: "SBOM.json",
		Format: importedsbom.FormatCycloneDX, SpecVersion: "1.4", TargetRef: "product-service", ComponentCount: 1,
		SHA256: hashHex(doc), RawJSON: doc, CreatedBy: "operator", CreatedAt: time.Unix(100, 0).UTC(),
	}); err != nil {
		t.Fatalf("SaveActive: %v", err)
	}
	eng := engagementWithScope(t, "myrepo")
	eng.TenantID = "tenant-1"
	svc := NewService(&fakeEngRepo{eng: eng}, nil, nil, nil, nil, nil, nil, nil,
		ports.Provenance{}, fakeClock{t: time.Unix(200, 0).UTC()}, &fakeAudit{}, shared.SeverityInfo, 0,
		&fakeAcquirer{}, &fakeDetector{}, fakeSBOM{}, []ports.DetectionSource{staticVuln{log4shellFinding()}},
		kevFeed(t, func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "denied", http.StatusForbidden) }), fakeLic{}, nil)
	svc.SetImportedSBOMStore(store)

	res, err := svc.ScanWithOptions(context.Background(), "operator", "e1", ports.AcquireRequest{}, ScanOptions{Mode: ScanModeFull})
	if err != nil {
		t.Fatalf("ScanWithOptions: %v", err)
	}

	if res.SBOM.Source != "imported-cyclonedx" || len(res.Vulnerabilities) != 1 {
		t.Fatalf("setup: this must be the imported-SBOM pipeline with one vulnerability: source=%q vulns=%d", res.SBOM.Source, len(res.Vulnerabilities))
	}
	if res.RiskUnavailable["kev"] != "http 403" || len(kevWarnings(res)) != 1 {
		t.Fatalf("imported scan: RiskUnavailable=%+v warnings=%q", res.RiskUnavailable, res.SourceWarnings)
	}
}

// The one place a feed outage changes a recorded status: an assessment lane is partial whenever the scan
// carries any source warning (the same rule the stale-catalogue warning already follows). Engine coverage,
// which --require-complete reads, is not part of that rule.
func TestAssessmentLaneIsPartialWithAnUnreadableKEVCatalogue(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	item, err := engdom.New("initial", "tenant", "Native upload", "", now)
	if err != nil {
		t.Fatal(err)
	}
	request := ports.AcquireRequest{Kind: ports.TargetUpload, Value: sourcepackage.TargetPrefix + strings.Repeat("a", 64)}
	for name, warnings := range map[string][]string{
		"catalogue read":       nil,
		"catalogue unreadable": riskUnavailableWarnings(map[string]string{"kev": "http 403"}),
	} {
		result := &ScanResult{Target: request.Value, ReproDigest: strings.Repeat("b", 64), Completeness: ports.Completeness{Confident: true},
			Manifest: ports.ScanManifest{ToolVersions: map[string]string{"scanner": "1"}}, SourceWarnings: warnings}
		_, status, err := assessmentSCALane(item, "run", now, now.Add(time.Second), request, result, "")
		want := scanrun.StatusSucceeded
		if len(warnings) > 0 {
			want = scanrun.StatusPartial
		}
		if err != nil || status != want {
			t.Errorf("%s: lane status = %s (err %v), want %s", name, status, err, want)
		}
	}
}

// A result reused for a scan that did not run vulnerabilities describes the same vulnerabilities, so the
// statement about how they were checked travels with them.
func TestCachedResultKeepsItsRiskUnavailable(t *testing.T) {
	current := &ScanResult{}
	previous := ScanResult{RiskMatches: map[string]int{"kev": 0}, RiskUnavailable: map[string]string{"kev": "http 403"}}

	mergeCachedScanResult(current, previous, ScanOptions{Mode: ScanModeLicenses})

	if current.RiskUnavailable["kev"] != "http 403" {
		t.Errorf("RiskUnavailable not carried with the cached vulnerabilities: %+v", current.RiskUnavailable)
	}
}
