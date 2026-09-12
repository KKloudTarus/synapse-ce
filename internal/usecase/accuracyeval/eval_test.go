package accuracyeval

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

func TestLoadEmbeddedCorpus(t *testing.T) {
	cases, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("embedded corpus is empty")
	}
	// Cases are sorted by name and every case names its ecosystem group.
	for i, c := range cases {
		if c.Name == "" {
			t.Errorf("case %d has no name", i)
		}
		if c.Group == "" {
			t.Errorf("case %q has no group", c.Name)
		}
		if i > 0 && cases[i-1].Name > c.Name {
			t.Errorf("corpus not sorted: %q before %q", cases[i-1].Name, c.Name)
		}
	}
}

// TestObserveKeyingAndReduction drives Observe through a controllable scanner to confirm the keying,
// independent of the real engine (which the SCA golden gate already exercises).
func TestObserveKeyingAndReduction(t *testing.T) {
	c := Case{
		Name:  "npm-lodash",
		Group: "npm",
		Components: []Component{
			{Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20"},
			{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}, // patched: must produce nothing
		},
		Expected: []Expected{{Component: "lodash", Version: "4.17.20", CVE: "CVE-2021-23337"}},
	}
	// A scanner that reports the vulnerable version correctly and nothing for the patched one → TP=1,FP=0,FN=0.
	scanner := stubScanner{findings: []vulnerability.RawFinding{{Component: "lodash", Version: "4.17.20", AdvisoryID: "CVE-2021-23337"}}}
	o, err := Observe(context.Background(), scanner, c)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if len(o.Expected) != 1 || o.Expected[0] != "lodash@4.17.20|CVE-2021-23337" {
		t.Errorf("expected keys = %v", o.Expected)
	}
	if len(o.Produced) != 1 || o.Produced[0] != "lodash@4.17.20|CVE-2021-23337" {
		t.Errorf("produced keys = %v", o.Produced)
	}
}

type stubScanner struct{ findings []vulnerability.RawFinding }

func (s stubScanner) ScanCase(_ context.Context, _ []advisory.Advisory, _ *sbom.SBOM) ([]vulnerability.RawFinding, error) {
	return s.findings, nil
}

func TestToRunMapsReport(t *testing.T) {
	scanner := stubScanner{findings: []vulnerability.RawFinding{{Component: "x", Version: "1", AdvisoryID: "CVE-1"}}}
	// Build a one-case corpus report by reducing a single perfect observation.
	rep, err := Evaluate(context.Background(), scanner)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	run, err := ToRun("run-1", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), rep)
	if err != nil {
		t.Fatalf("to run: %v", err)
	}
	if run.ID != "run-1" || run.CorpusVersion != CorpusVersion || run.SchemaVersion != rep.SchemaVersion {
		t.Errorf("run header mismatch: %+v", run)
	}
	if run.Cases != int(rep.Cases) {
		t.Errorf("cases = %d, want %d", run.Cases, rep.Cases)
	}
	if run.Overall.Precision != rep.Overall.Precision || run.Overall.Recall != rep.Overall.Recall {
		t.Errorf("overall metrics not mapped: %+v vs %+v", run.Overall, rep.Overall)
	}
	if len(run.Groups) != len(rep.Groups) {
		t.Errorf("groups = %d, want %d", len(run.Groups), len(rep.Groups))
	}
}
