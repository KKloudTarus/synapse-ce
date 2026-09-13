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

// TestSemgrepCEObservationsPythonSinkPresenceIsNotReachability pins the Python head-to-head: Semgrep CE's
// os.system pattern proves a call SITE exists, not that it is reachable from an entrypoint, so a fixture
// whose sink is matched becomes reachable while one with no match stays present_unreached. The unreached
// fixtures whose sink Semgrep still matches are the owned engine's precision advantage, recorded honestly.
func TestSemgrepCEObservationsPythonSinkPresenceIsNotReachability(t *testing.T) {
	base := "internal/infrastructure/tools/astwalk/testdata/reachbench"
	observations, err := SemgrepCEObservations(DefaultCorpus(), strings.NewReader(`{"results":[
		{"check_id":"reachbench.py.os-system-call","path":"`+base+`/py_reached/app.py"},
		{"check_id":"reachbench.py.os-system-call","path":"`+base+`/py_unreached/app.py"},
		{"check_id":"reachbench.py.os-system-call","path":"`+base+`/py_crossmodule_imported_uncalled/helper.py"}
	]}`))
	if err != nil {
		t.Fatalf("SemgrepCEObservations: %v", err)
	}
	got := observationLabels(observations)
	// A matched reachable case and a matched unreached case both read reachable to Semgrep (sink present).
	if got["py_reached_via_handler"] != Reachable {
		t.Errorf("py_reached_via_handler = %v, want reachable", got["py_reached_via_handler"])
	}
	if got["py_unreached_private_function"] != Reachable {
		t.Errorf("py_unreached_private_function = %v, want reachable (Semgrep over-reports the sink presence)", got["py_unreached_private_function"])
	}
	if got["py_cross_module_imported_uncalled"] != Reachable {
		t.Errorf("py_cross_module_imported_uncalled = %v, want reachable (sink present in helper.py)", got["py_cross_module_imported_uncalled"])
	}
	// A python case with a selector but no matching result stays present_unreached, never no_analysis.
	if got["py_instance_method_reached"] != PresentUnreached {
		t.Errorf("py_instance_method_reached (no Semgrep match) = %v, want present_unreached", got["py_instance_method_reached"])
	}
}

func observationLabels(observations []Observation) map[string]Label {
	got := make(map[string]Label, len(observations))
	for _, item := range observations {
		got[item.Case] = item.Label
	}
	return got
}

// TestSemgrepSelectorsDoNotSuffixAlias locks a benchmark-integrity property of the Semgrep path matching
// (strings.HasSuffix in SemgrepCEObservations): no case's path_suffix may be a suffix of another's, or one
// Semgrep result could be attributed to two cases and mislabel one. It also requires each selector's rule id
// to be non-empty. This is a corpus-authoring guard, not a runtime path.
func TestSemgrepSelectorsDoNotSuffixAlias(t *testing.T) {
	var suffixes []string
	for _, c := range DefaultCorpus().Cases {
		if s := c.Baseline.SemgrepCE; s != nil {
			if s.RuleID == "" || s.PathSuffix == "" {
				t.Fatalf("case %q has an incomplete Semgrep selector", c.Name)
			}
			suffixes = append(suffixes, s.PathSuffix)
		}
	}
	if len(suffixes) < 2 {
		t.Skip("need at least two Semgrep selectors to check aliasing")
	}
	for i := range suffixes {
		for j := range suffixes {
			if i == j {
				continue
			}
			if strings.HasSuffix(suffixes[i], suffixes[j]) {
				t.Errorf("Semgrep path_suffix %q is a suffix of %q; a single result could mislabel both cases", suffixes[j], suffixes[i])
			}
		}
	}
}
