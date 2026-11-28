package scabridge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchcore"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

const closureManifestPath = "../../../../docs/benchmarks/closure-manifest-v1.json"

// scorerDigest identifies the scoring pipeline by every non-test source file of the core, its control
// fixture, this bridge and the legacy key normalization it emits identities with, so a change to
// normalization, matching, validation or grading is a change of scorer.
func scorerDigest(t *testing.T) string {
	t.Helper()
	paths, err := filepath.Glob("../*.go")
	if err != nil {
		t.Fatal(err)
	}
	paths = append(paths, "../controls/known-outcome-v1.json", "bridge.go", "../../scabench/types.go")
	sort.Strings(paths)
	var all bytes.Buffer
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&all, "%s %d\n", filepath.Base(path), len(raw))
		all.Write(raw)
	}
	return benchmark.SHA256Digest(all.Bytes())
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return benchmark.SHA256Digest(raw)
}

// buildClosureManifest derives revision 1 of the closure manifest from committed inputs only. Every digest
// in it is recomputed here, so a change to the oracle, the catalog, the scorer, the matching policy or the
// control fixture fails TestClosureManifestIsFrozen until a new revision is published.
func buildClosureManifest(t *testing.T) benchcore.ClosureManifest {
	t.Helper()
	catalog, oracle := corpus(t)
	truth, err := Truth(profileID, "oracle@"+catalog.Revision, catalog, oracle)
	if err != nil {
		t.Fatal(err)
	}
	truthDigest, err := benchcore.DigestTruth(truth)
	if err != nil {
		t.Fatal(err)
	}
	catalogDigest, err := scabench.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := Capabilities(oracle)
	if err != nil {
		t.Fatal(err)
	}
	fixture, fixtureDigest, err := benchcore.KnownOutcomeFixture()
	if err != nil {
		t.Fatal(err)
	}
	expectedDigest, err := benchcore.DigestExpectedOutcomes(fixture)
	if err != nil {
		t.Fatal(err)
	}
	positives, negatives := 0, 0
	subjects := map[string]bool{}
	for _, u := range truth.Units {
		subjects[u.SubjectID] = true
		if u.Label == benchcore.LabelPositive {
			positives++
		} else {
			negatives++
		}
	}
	var enrollment []benchcore.Enrollment
	for _, engine := range scabench.Engines() {
		enrollment = append(enrollment, benchcore.Enrollment{
			EngineID:             string(engine),
			AdapterID:            "scabench-" + string(engine),
			ScoredComponent:      benchcore.ScoredComponent{ID: string(engine), Provenance: "pinned in internal/usecase/scabench/corpus/catalog.json and the capture manifests"},
			DeclaredCapabilities: capabilities[engine],
		})
	}
	kinds := []string{UnitKindPrefix + "deb", UnitKindPrefix + "rpm"}
	sort.Strings(kinds)
	return benchcore.ClosureManifest{
		SchemaVersion:       benchcore.ManifestSchemaVersion,
		ManifestID:          "synapse-benchmark-closure",
		Revision:            1,
		Claim:               "Each enrolled engine receives a standalone absolute scorecard per profile, scored by one engine-neutral core that never sees engine identity.",
		PopulationStatement: "Revision 1 enters the one profile whose truth, corpus and enrollment are frozen in the repository today: SCA component-advisory relations on three pinned container images. Every other task family enters by a later revision, disclosed through succession.",
		WorkPackages: map[string]benchcore.WorkPackage{
			"A": {Summary: "Engine-neutral contracts, core and adapter boundary", Required: true},
			"B": {Summary: "Independent truth, sealed holdout and temporal cohorts", Required: true},
			"C": {Summary: "Absolute per-engine evaluation first; optional comparison modes", Required: true},
			"D": {Summary: "Validate the benchmark itself and its failure sensitivity", Required: true},
			"E": {Summary: "Authorized live acquisition and enforcement profiles", Required: true},
			"F": {Summary: "Operational fitness, reproducibility and economics", Required: true},
			"G": {Summary: "Automated acceptance and reproducible publication", Required: true},
		},
		Profiles: []benchcore.Profile{{
			ID:             profileID,
			WorkPackages:   []string{"A", "C"},
			TaskFamily:     "sca",
			UnitKinds:      kinds,
			ClosedWorld:    false,
			Population:     benchcore.Population{Subjects: len(subjects), TruthUnits: len(truth.Units), Positives: positives, Negatives: negatives},
			SupportedScope: "OS packages (deb, rpm) of the three images in internal/usecase/scabench/corpus/catalog.json",
			Corpus:         benchcore.Identity{ID: "scabench-catalog", Version: catalog.Revision, Digest: catalogDigest},
			Truth:          benchcore.Identity{ID: "scabench-oracle", Version: truth.Version, Digest: truthDigest},
			Scorer:         benchcore.Identity{ID: "benchcore", Version: "1", Digest: scorerDigest(t)},
			MatchingPolicy: benchcore.Identity{ID: NormalizationID, Version: "1", Digest: NormalizationDigest},
			Thresholds: benchcore.Thresholds{MinimumRecall: 1, MinimumPrecision: 1, MaximumUnknown: 0,
				MarginRationale: "Every labelled relation is a published advisory fix or affected status; a pinned engine with current data has no tolerated miss or false report. The unknown ceiling does not apply to this open-world profile."},
			MinimumTruthSupport: benchcore.Support{Positives: 30, Negatives: 30,
				Rationale: "With n of n positives found, the one-sided 95% Clopper-Pearson lower bound on recall is 0.05^(1/n); n = 30 keeps it at 0.905. The bound assumes independently sampled units and holds per unit kind, not jointly across kinds; units clustered on three images are fewer independent samples than their count. Below 30 positives or 30 negatives in any unit kind the profile is descriptive."},
			RequiredEnrollment:     enrollment,
			Disposition:            benchcore.DispositionRequired,
			ExecutionAuthorization: benchcore.Authorization{Kind: "none", Status: benchcore.AuthorizationNone},
			LegacyEvidence: &benchcore.LegacyEvidence{Label: "migration/regression", SourcePath: "internal/usecase/scabench/corpus/ratchet.json", Cells: 12,
				InventoryDigestClaimed: fileDigest(t, "../../scabench/corpus/ratchet.json"), InventoryDigestVerified: true},
		}},
		ControlSuites: []benchcore.ControlSuite{
			{ID: benchcore.ControlKnownOutcome, Version: fixture.Version, WorkPackage: "D", FixtureDigest: fixtureDigest, ExpectedOutcomeDigest: expectedDigest},
			{ID: benchcore.ControlIdentityInvariance, Version: fixture.Version, WorkPackage: "D", FixtureDigest: fixtureDigest, ExpectedOutcomeDigest: expectedDigest},
		},
		Lanes: []benchcore.Lane{{ID: "offline-sca", ProfileIDs: []string{profileID}, Disposition: benchcore.DispositionRequired, AuthorizationStatus: benchcore.AuthorizationNone}},
	}
}

// TestClosureManifestIsFrozen: the committed manifest equals the one rebuilt from committed inputs, it
// validates, and its control suites pass. Regenerate with UPDATE_CLOSURE_MANIFEST=1 only together with a
// new revision number.
func TestClosureManifestIsFrozen(t *testing.T) {
	built := buildClosureManifest(t)
	if err := built.Validate(); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("UPDATE_CLOSURE_MANIFEST") == "1" {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(built.Canonical()); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(closureManifestPath, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(closureManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	committed, err := benchcore.DecodeManifest(f)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(committed.Canonical(), built.Canonical()) {
		t.Fatal("docs/benchmarks/closure-manifest-v1.json no longer matches its committed inputs; a changed oracle, catalog, scorer, matching policy or control fixture needs a new manifest revision")
	}
	results, _, err := benchcore.RunControlSuites(committed)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if !r.Passed {
			t.Fatalf("control suite %s failed against the committed manifest", r.ID)
		}
	}
}

// TestCommittedManifestGradesSCADescriptive: the SCA profile has 1 Debian and 18 RPM positives, below the
// 30 per kind the profile needs, so even a perfect engine is descriptive, never a pass.
func TestCommittedManifestGradesSCADescriptive(t *testing.T) {
	m := buildClosureManifest(t)
	catalog, oracle := corpus(t)
	truth, err := Truth(profileID, "oracle@"+catalog.Revision, catalog, oracle)
	if err != nil {
		t.Fatal(err)
	}
	byTarget := map[string][]scabench.Finding{}
	for _, c := range oracle.Cases {
		if c.Truth == scabench.TruthAffected {
			byTarget[c.TargetID] = append(byTarget[c.TargetID], scabench.Finding{Component: c.Component, AdvisoryID: c.AdvisoryID})
		}
	}
	capabilities, _ := Capabilities(oracle)
	var observations []benchcore.Observation
	for _, target := range catalog.Targets {
		o, err := Observation(profileID, legacyObservation(t, catalog, scabench.EngineOwned, target, scabench.ObservationComplete, byTarget[target.ID]), capabilities[scabench.EngineOwned])
		if err != nil {
			t.Fatal(err)
		}
		observations = append(observations, o)
	}
	receipt, err := benchcore.NewRunStartReceipt(m, benchcore.RunStart{ProfileID: profileID, RunKey: "perfect", ImplementationCommit: "test", RunnerIdentity: "test"})
	if err != nil {
		t.Fatal(err)
	}
	card, err := benchcore.BindScorecard(m, receipt, benchcore.Binding{Engine: observations[0].Engine, Truth: truth, Observations: observations})
	if err != nil {
		t.Fatal(err)
	}
	if card.Validity.Status != "valid" || card.EngineGrade != benchcore.GradeDescriptive {
		t.Fatalf("validity %+v grade %s", card.Validity, card.EngineGrade)
	}
	for _, c := range card.Cells {
		if r := c.EndToEnd.Recall(); r == nil || *r != 1 {
			t.Fatalf("a perfect engine must have recall 1 on %s: %+v", c.UnitKind, c.EndToEnd)
		}
	}
}
