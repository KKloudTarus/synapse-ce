package reachbench

import (
	"strings"
	"testing"
)

func TestOSVObservationsPreserveFixtureScopedCalledAndUncalledControls(t *testing.T) {
	observations, err := OSVObservations(DefaultCorpus(), strings.NewReader(`{
		"results":[
			{"source":{"path":"/work/go_osv_jsonparser_called/go.mod"},"packages":[{"groups":[{"ids":["GO-2026-4514"],"experimentalAnalysis":{"GO-2026-4514":{"called":true}}}]}]},
			{"source":{"path":"/work/go_osv_jsonparser_uncalled/go.mod"},"packages":[{"groups":[{"ids":["GO-2026-4514"],"experimental_analysis":{"GO-2026-4514":{"called":false}}}]}]}
		]
	}`))
	if err != nil {
		t.Fatalf("OSVObservations: %v", err)
	}
	got := observationLabels(observations)
	if got["go_osv_jsonparser_delete_called"] != Reachable || got["go_osv_jsonparser_delete_uncalled"] != PresentUnreached {
		t.Fatalf("OSV labels = %v", got)
	}
	if got["go_direct_call_reachable"] != NoAnalysis {
		t.Fatalf("unmapped case must stay no_analysis, got %v", got)
	}
}

func TestOSVObservationsRejectContradictionWithinOneFixture(t *testing.T) {
	_, err := OSVObservations(DefaultCorpus(), strings.NewReader(`{
		"results":[
			{"source":{"path":"go_osv_jsonparser_called/go.mod"},"packages":[{"groups":[{"experimentalAnalysis":{"GO-2026-4514":{"called":true}}}]}]},
			{"source":{"path":"go_osv_jsonparser_called/go.mod"},"packages":[{"groups":[{"experimentalAnalysis":{"GO-2026-4514":{"called":false}}}]}]}
		]
	}`))
	if err == nil || !strings.Contains(err.Error(), "contradictory") {
		t.Fatalf("contradictory fixture output error = %v", err)
	}
}

func TestSemgrepCEObservationsMapNativeAndSARIFResults(t *testing.T) {
	native, err := SemgrepCEObservations(DefaultCorpus(), strings.NewReader(`{
		"results":[{"check_id":"reachbench.go.jsonparser-delete-called","path":"internal/infrastructure/tools/ssacallgraph/testdata/reachbench/go_osv_jsonparser_called/main.go"}]
	}`))
	if err != nil {
		t.Fatalf("native Semgrep: %v", err)
	}
	got := observationLabels(native)
	if got["go_osv_jsonparser_delete_called"] != Reachable || got["go_osv_jsonparser_delete_uncalled"] != PresentUnreached || got["go_direct_call_reachable"] != NoAnalysis {
		t.Fatalf("native Semgrep labels = %v", got)
	}

	sarif, err := SemgrepCEObservations(DefaultCorpus(), strings.NewReader(`{
		"runs":[{"results":[{"ruleId":"reachbench.go.jsonparser-delete-called","locations":[{"physicalLocation":{"artifactLocation":{"uri":"go_osv_jsonparser_called/main.go"}}}]}]}]
	}`))
	if err != nil {
		t.Fatalf("SARIF Semgrep: %v", err)
	}
	if got := observationLabels(sarif); got["go_osv_jsonparser_delete_called"] != Reachable {
		t.Fatalf("SARIF Semgrep labels = %v", got)
	}
}

func TestSnykSampleObservationsAreExplicitAndComplete(t *testing.T) {
	observations, err := SnykSampleObservations(DefaultCorpus(), strings.NewReader(`{
		"observations":[
			{"evidence_id":"GO-2026-4514-called","label":"reachable"},
			{"evidence_id":"GO-2026-4514-uncalled","label":"present_unreached"}
		]
	}`))
	if err != nil {
		t.Fatalf("SnykSampleObservations: %v", err)
	}
	got := observationLabels(observations)
	if got["go_osv_jsonparser_delete_called"] != Reachable || got["go_osv_jsonparser_delete_uncalled"] != PresentUnreached || got["go_direct_call_reachable"] != NoAnalysis {
		t.Fatalf("Snyk sample labels = %v", got)
	}
	if _, err := SnykSampleObservations(DefaultCorpus(), strings.NewReader(`{"observations":[{"evidence_id":"GO-2026-4514-called","label":"reachable"},{"evidence_id":"GO-2026-4514-called","label":"reachable"}]}`)); err == nil {
		t.Fatal("Snyk sample must reject duplicate evidence rather than collapse it")
	}
}

func observationLabels(observations []Observation) map[string]Label {
	got := make(map[string]Label, len(observations))
	for _, item := range observations {
		got[item.Case] = item.Label
	}
	return got
}
