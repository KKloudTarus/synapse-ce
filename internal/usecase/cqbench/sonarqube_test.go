package cqbench

import (
	"strings"
	"testing"
)

func TestSonarQubeObservations(t *testing.T) {
	corpus := DefaultCorpus()
	export := `{"issues":[
	  {"component":"proj:go-todo/sample.go","line":3,"type":"CODE_SMELL","rule":"go:S1135"},
	  {"component":"proj:py-smells/sample.py","line":5,"type":"CODE_SMELL","rule":"python:S1135"},
	  {"component":"proj:py-smells/sample.py","line":6,"type":"VULNERABILITY","rule":"python:S6350"},
	  {"component":"proj:py-smells/sample.py","line":13,"type":"CODE_SMELL","rule":"python:S5754"},
	  {"component":"proj:js-smells/sample.js","line":3,"type":"SECURITY_HOTSPOT","rule":"js:S1523"},
	  {"component":"proj:js-smells/sample.js","line":7,"type":"BUG","rule":"js:S1440"},
	  {"component":"proj:py-smells","line":0,"type":"CODE_SMELL"},
	  {"component":"proj:outside/other.go","line":1,"type":"BUG"},
	  {"component":"proj:js-smells/sample.js","line":9,"type":"UNKNOWN_TYPE"}
	]}`
	obs, err := SonarQubeObservations(corpus, strings.NewReader(export))
	if err != nil {
		t.Fatalf("SonarQubeObservations: %v", err)
	}
	if len(obs) != len(corpus.Cases) {
		t.Fatalf("want one observation per case (%d), got %d", len(corpus.Cases), len(obs))
	}
	rep, err := Evaluate("sonarqube-ce", corpus, obs)
	if err != nil {
		t.Fatalf("Evaluate SonarQube: %v", err)
	}
	cells := map[string]TypeScore{}
	for _, cell := range rep.Types {
		cells[CellKey(cell.Language, cell.Type)] = cell
	}
	// SonarQube caught the bare-except (python/code_smell recall 1.0), which the owned engine misses; both
	// caught the command injection, hotspot, and loose-equality bug.
	if got := cells["python/code_smell"]; got.TP != 2 || got.Recall != 1 {
		t.Errorf("SonarQube should catch both python smells, got %+v", got)
	}
	if got := cells["python/vulnerability"]; got.TP != 1 {
		t.Errorf("SonarQube should catch the command injection, got %+v", got)
	}
	if got := cells["javascript/security_hotspot"]; got.TP != 1 {
		t.Errorf("SonarQube should catch the eval hotspot, got %+v", got)
	}
	// The line-0, outside-corpus, and unknown-type issues must all be ignored (no spurious FPs).
	for _, cell := range rep.Types {
		if cell.FP != 0 {
			t.Errorf("unexpected false positive in %s/%s: %+v", cell.Language, cell.Type, cell)
		}
	}
}

func TestSonarQubeObservationsHeadToHead(t *testing.T) {
	// A head-to-head between the reduced SonarQube baseline and a (stubbed) owned report must be corpus-bound
	// and produce comparison lines naming both engines.
	corpus := DefaultCorpus()
	sonar, err := SonarQubeObservations(corpus, strings.NewReader(`{"issues":[
	  {"component":"p:py-smells/sample.py","line":13,"type":"CODE_SMELL"}]}`))
	if err != nil {
		t.Fatalf("SonarQubeObservations: %v", err)
	}
	sonarRep, err := Evaluate("sonarqube-ce", corpus, sonar)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	// Owned observations: perfect on everything it detects (leave python bare-except missed).
	owned := make([]CaseObservation, 0, len(corpus.Cases))
	for _, c := range corpus.Cases {
		owned = append(owned, CaseObservation{Case: c.Name, Issues: c.Issues})
	}
	// Drop the python bare-except from owned to model the real gap.
	for i := range owned {
		if owned[i].Case == "python-command-injection-and-smells" {
			filtered := owned[i].Issues[:0]
			for _, iss := range owned[i].Issues {
				if !(iss.Line == 13) {
					filtered = append(filtered, iss)
				}
			}
			owned[i].Issues = filtered
		}
	}
	ownedRep, err := Evaluate("synapse-owned", corpus, owned)
	if err != nil {
		t.Fatalf("Evaluate owned: %v", err)
	}
	lines, err := CompareToBaseline(ownedRep, sonarRep)
	if err != nil {
		t.Fatalf("CompareToBaseline: %v", err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "sonarqube-ce") || !strings.Contains(joined, "python/code_smell") {
		t.Errorf("head-to-head must compare python/code_smell against sonarqube-ce: %s", joined)
	}
}
