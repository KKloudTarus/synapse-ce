package sca

// Golden detection-accuracy gate for the OWNED advisory-store engine (ownadvisory.Source),
// the source that must stand alone without grype/trivy. Each case pairs an SBOM with a pinned
// advisory snapshot and a ground-truth label set (which (component, CVE) pairs MUST be produced
// and, by omission, which components must produce nothing). The eval runs ownadvisory.Source over
// an in-memory store built from the pinned advisories, reduces the produced-vs-expected sets with
// benchmark.EvaluateAccuracy, and gates precision/recall against a checked-in ratchet
// (testdata/detection-accuracy-debt.json) that may only tighten. This makes "the owned engine
// stands on its own" measurable and regression-proof; it runs fully offline in CI (no network,
// no third-party engine).

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownadvisory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

const goldenDir = "testdata/detection-golden-v1"

// corpusRange is one version range on an affected package.
type corpusRange struct {
	Type         string `json:"type"` // SEMVER | ECOSYSTEM | GIT
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// corpusAdvisory is a compact, authorable advisory record pinned into a case.
type corpusAdvisory struct {
	ID         string        `json:"id"`
	Aliases    []string      `json:"aliases,omitempty"`
	Summary    string        `json:"summary,omitempty"`
	CVSSScore  float64       `json:"cvss_score,omitempty"`
	CVSSVector string        `json:"cvss_vector,omitempty"`
	Ecosystem  string        `json:"ecosystem"` // OSV ecosystem / distro key (e.g. "npm", "PyPI", "Debian:11")
	Package    string        `json:"package"`
	Ranges     []corpusRange `json:"ranges,omitempty"`
	Versions   []string      `json:"versions,omitempty"`
	Fixed      string        `json:"fixed_version,omitempty"`
	Withdrawn  bool          `json:"withdrawn,omitempty"`
}

// corpusComponent is one SBOM component in a case.
type corpusComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

// corpusExpected is one ground-truth detection that MUST be produced, keyed to a specific
// component VERSION so that a false positive on a patched version of the same package is not
// masked by a true positive on the vulnerable version (they are distinct keys). CVE is the
// advisory id the source is expected to REPORT for this finding (the CVE when the advisory
// carries one, since ownadvisory.Source prefers the CVE over a GHSA/RUSTSEC primary id).
type corpusExpected struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	CVE       string `json:"cve"`
}

// corpusCase is one labeled evaluation unit.
type corpusCase struct {
	Name       string            `json:"name"`
	Group      string            `json:"group"` // ecosystem, for the per-group ratchet
	Notes      string            `json:"notes,omitempty"`
	Components []corpusComponent `json:"components"`
	Advisories []corpusAdvisory  `json:"advisories"`
	Expected   []corpusExpected  `json:"expected"`
}

// memStore is an in-memory AdvisoryStore keyed by "ecosystem|package", the same shape
// ownadvisory.Source queries via ByPackage. It mirrors the store the Postgres advisory
// repository presents to the source at scan time.
type memStore struct {
	byKey map[string][]advisory.Advisory
}

func (m memStore) ByPackage(_ context.Context, ecosystem, name string) ([]advisory.Advisory, error) {
	return m.byKey[ecosystem+"|"+name], nil
}

func toAdvisory(a corpusAdvisory) advisory.Advisory {
	ranges := make([]advisory.Range, 0, len(a.Ranges))
	for _, r := range a.Ranges {
		events := make([]advisory.Event, 0, 3)
		if r.Introduced != "" {
			events = append(events, advisory.Event{Introduced: r.Introduced})
		}
		if r.Fixed != "" {
			events = append(events, advisory.Event{Fixed: r.Fixed})
		}
		if r.LastAffected != "" {
			events = append(events, advisory.Event{LastAffected: r.LastAffected})
		}
		ranges = append(ranges, advisory.Range{Type: r.Type, Events: events})
	}
	return advisory.Advisory{
		ID: a.ID, Aliases: a.Aliases, Summary: a.Summary, CVSSScore: a.CVSSScore, CVSSVector: a.CVSSVector,
		Withdrawn: a.Withdrawn,
		Affected: []advisory.AffectedPackage{{
			Ecosystem: a.Ecosystem, Package: a.Package, Ranges: ranges, Versions: a.Versions, FixedVersion: a.Fixed,
		}},
	}
}

func buildStore(c corpusCase) memStore {
	store := memStore{byKey: map[string][]advisory.Advisory{}}
	for _, a := range c.Advisories {
		key := a.Ecosystem + "|" + a.Package
		store.byKey[key] = append(store.byKey[key], toAdvisory(a))
	}
	return store
}

func buildSBOM(c corpusCase) *sbom.SBOM {
	doc := &sbom.SBOM{}
	for _, comp := range c.Components {
		doc.Components = append(doc.Components, sbom.Component{Name: comp.Name, Version: comp.Version, PURL: comp.PURL})
	}
	return doc
}

// observe runs the owned source over one case and keys both the ground truth and the produced
// findings by "component@version|advisory-id". A produced finding is keyed STRICTLY by its own
// primary id (ownadvisory.Source reports the CVE when the advisory carries one, via preferCVE),
// with no alias rescue: a finding whose primary id is not the expected id is a false positive, so
// a wrong advisory cannot be laundered into a true positive through a shared or broad alias. The
// corpus therefore labels expected.cve as the id the source is expected to report.
func observe(t *testing.T, c corpusCase) benchmark.AccuracyObservation {
	t.Helper()
	raws, err := ownadvisory.New(buildStore(c)).Scan(context.Background(), buildSBOM(c))
	if err != nil {
		t.Fatalf("case %q: scan: %v", c.Name, err)
	}
	expKeys := make([]string, 0, len(c.Expected))
	for _, e := range c.Expected {
		expKeys = append(expKeys, e.Component+"@"+e.Version+"|"+e.CVE)
	}
	prodKeys := make([]string, 0, len(raws))
	for _, r := range raws {
		prodKeys = append(prodKeys, r.Component+"@"+r.Version+"|"+r.AdvisoryID)
	}
	return benchmark.AccuracyObservation{Case: c.Name, Group: c.Group, Expected: expKeys, Produced: prodKeys}
}

func loadCorpus(t *testing.T) []corpusCase {
	t.Helper()
	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatalf("read corpus dir: %v", err)
	}
	var cases []corpusCase
	names := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(goldenDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var fileCases []corpusCase
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&fileCases); err != nil {
			t.Fatalf("decode %s: %v", e.Name(), err)
		}
		for _, c := range fileCases {
			if names[c.Name] {
				t.Fatalf("duplicate case name %q (in %s)", c.Name, e.Name())
			}
			names[c.Name] = true
			cases = append(cases, c)
		}
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].Name < cases[j].Name })
	if len(cases) == 0 {
		t.Fatal("no corpus cases loaded")
	}
	return cases
}

// ratchet is the checked-in accuracy floor. It may only tighten (floors only rise). The gate
// fails if the measured metric drops below any floor, catching a matcher or feed regression.
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
	cases := loadCorpus(t)
	obs := make([]benchmark.AccuracyObservation, 0, len(cases))
	for _, c := range cases {
		obs = append(obs, observe(t, c))
	}
	report, err := benchmark.EvaluateAccuracy(benchmark.AccuracyInput{SchemaVersion: benchmark.AccuracyInputSchemaVersion, Observations: obs})
	if err != nil {
		t.Fatalf("evaluate accuracy: %v", err)
	}

	// Diagnostics: with -v, print the full report and every case's produced-vs-expected delta.
	if testing.Verbose() {
		var buf strings.Builder
		_ = benchmark.EncodeAccuracyReport(&buf, report)
		t.Logf("owned-engine detection accuracy over %d cases:\n%s", report.Cases, buf.String())
	}
	// Always surface the deltas that break a floor, so a regression is diagnosable from CI logs.
	printDeltas := func() {
		for _, c := range cases {
			o := observe(t, c)
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
	// Together these make the floor a genuine tighten-only ratchet: it always equals the current
	// accuracy, so it cannot be edited down without an actual, reviewed change to the corpus/matcher.
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
