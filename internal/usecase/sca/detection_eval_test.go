package sca

// Golden detection-accuracy gate for the OWNED advisory-store engine (ownadvisory.Source), the
// source that must stand alone without grype/trivy. The corpus, the owned-engine run, and the
// produced-vs-expected reduction all live in internal/usecase/accuracyeval (consumed here and by the
// nightly worker job, so the measured and gated corpora cannot drift); this file only pins the
// achieved precision/recall to a checked-in ratchet (testdata/detection-accuracy-debt.json) that may
// only tighten. It runs fully offline (no network, no third-party engine).

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/accuracyprobe"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/accuracyeval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

// ratchet is the checked-in accuracy floor. It may only tighten (floors only rise). The gate fails
// if the measured metric drops below any floor, catching a matcher or feed regression.
type ratchet struct {
	Comment string                  `json:"_comment,omitempty"`
	Overall ratchetFloor            `json:"overall"`
	Groups  map[string]ratchetFloor `json:"groups"`
}

type ratchetFloor struct {
	PrecisionFloor float64 `json:"precision_floor"`
	RecallFloor    float64 `json:"recall_floor"`
}

func loadRatchet(t *testing.T) ratchet {
	t.Helper()
	raw, err := os.ReadFile("testdata/detection-accuracy-debt.json")
	if err != nil {
		t.Fatalf("read ratchet: %v", err)
	}
	var r ratchet
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("decode ratchet: %v", err)
	}
	return r
}

func TestDetectionAccuracyGolden(t *testing.T) {
	ctx := context.Background()
	scanner := accuracyprobe.New()
	report, err := accuracyeval.Evaluate(ctx, scanner)
	if err != nil {
		t.Fatalf("evaluate accuracy: %v", err)
	}

	// Diagnostics: with -v, print the full report.
	if testing.Verbose() {
		var buf strings.Builder
		_ = benchmark.EncodeAccuracyReport(&buf, report)
		t.Logf("owned-engine detection accuracy over %d cases:\n%s", report.Cases, buf.String())
	}
	// Always surface the deltas that break a floor, so a regression is diagnosable from CI logs.
	printDeltas := func() {
		cases, err := accuracyeval.Load()
		if err != nil {
			t.Fatalf("load corpus: %v", err)
		}
		for _, c := range cases {
			o, err := accuracyeval.Observe(ctx, scanner, c)
			if err != nil {
				t.Fatalf("observe %q: %v", c.Name, err)
			}
			exp := map[string]bool{}
			for _, k := range o.Expected {
				exp[k] = true
			}
			prod := map[string]bool{}
			for _, k := range o.Produced {
				prod[k] = true
			}
			var missed, extra []string
			for k := range exp {
				if !prod[k] {
					missed = append(missed, k)
				}
			}
			for k := range prod {
				if !exp[k] {
					extra = append(extra, k)
				}
			}
			if len(missed) > 0 || len(extra) > 0 {
				sort.Strings(missed)
				sort.Strings(extra)
				t.Logf("case %q [%s]: FN(missed)=%v FP(extra)=%v", c.Name, c.Group, missed, extra)
			}
		}
	}

	r := loadRatchet(t)
	const eps = 1e-9
	// assertRatchet pins the committed floor TO the achieved accuracy, both directions:
	//   - measured below the floor  -> a regression (the matcher or feed got worse).
	//   - floor below the measured  -> the floor was left slack (a silent lowering to hide a future
	//     regression, or an improvement not locked in); it must be raised to the achieved value.
	assertRatchet := func(label string, m benchmark.Metrics, floor ratchetFloor) {
		if m.Precision+eps < floor.PrecisionFloor {
			printDeltas()
			t.Errorf("%s precision %.6f regressed below ratchet floor %.6f (FP=%d)", label, m.Precision, floor.PrecisionFloor, m.FalsePositives)
		}
		if m.Recall+eps < floor.RecallFloor {
			printDeltas()
			t.Errorf("%s recall %.6f regressed below ratchet floor %.6f (FN=%d)", label, m.Recall, floor.RecallFloor, m.FalseNegatives)
		}
		if floor.PrecisionFloor+eps < m.Precision {
			t.Errorf("%s precision floor %.6f is below the achieved %.6f; raise precision_floor in testdata/detection-accuracy-debt.json", label, floor.PrecisionFloor, m.Precision)
		}
		if floor.RecallFloor+eps < m.Recall {
			t.Errorf("%s recall floor %.6f is below the achieved %.6f; raise recall_floor in testdata/detection-accuracy-debt.json", label, floor.RecallFloor, m.Recall)
		}
	}
	assertRatchet("overall", report.Overall, r.Overall)
	ratchetGroups := map[string]bool{}
	for group := range r.Groups {
		ratchetGroups[group] = true
	}
	byGroup := map[string]benchmark.GroupAccuracy{}
	for _, g := range report.Groups {
		byGroup[g.Group] = g
		// Every corpus ecosystem must have a ratchet floor, so adding a new ecosystem cannot slip in
		// unmeasured (its accuracy would otherwise be gated only by the overall aggregate).
		if !ratchetGroups[g.Group] {
			t.Errorf("corpus group %q has no ratchet floor in testdata/detection-accuracy-debt.json", g.Group)
		}
	}
	for group, floor := range r.Groups {
		g, ok := byGroup[group]
		if !ok {
			t.Errorf("ratchet names group %q with no corpus cases", group)
			continue
		}
		assertRatchet("group "+group, g.Metrics, floor)
	}
}
