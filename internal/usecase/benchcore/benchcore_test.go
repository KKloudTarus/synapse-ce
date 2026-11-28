package benchcore

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func sampleTruth() TruthSet {
	return TruthSet{SchemaVersion: TruthSchemaVersion, ProfileID: "sca.v1", Version: "1", ClosedWorld: false,
		Subjects: []Subject{{ID: "s1", Digest: "sha256:s1"}, {ID: "s2", Digest: "sha256:s2"}}, Units: []TruthUnit{
			{ID: "u1", SubjectID: "s1", UnitKind: "component-advisory", Identity: map[string]string{"purl": "pkg:npm/a@1", "advisory": "CVE-1"}, Label: LabelPositive, Provenance: "vendor", Authorship: "oracle"},
			{ID: "u2", SubjectID: "s1", UnitKind: "component-advisory", Identity: map[string]string{"purl": "pkg:npm/b@1", "advisory": "CVE-2"}, Label: LabelPositive, Provenance: "vendor", Authorship: "oracle"},
			{ID: "u3", SubjectID: "s1", UnitKind: "component-advisory", Identity: map[string]string{"purl": "pkg:npm/c@1", "advisory": "CVE-3"}, Label: LabelNegative, Provenance: "vendor", Authorship: "oracle"},
			{ID: "u4", SubjectID: "s2", UnitKind: "file-rule-line", Identity: map[string]string{"path": "a.go", "rule": "r1", "line": "7"}, Label: LabelPositive, Provenance: "authored", Authorship: "oracle"},
			{ID: "u5", SubjectID: "s1", UnitKind: "component-advisory", Identity: map[string]string{"purl": "pkg:npm/d@1", "advisory": "CVE-5"}, Label: LabelUnknown, Provenance: "backlog", Authorship: "oracle"},
		}}
}

func sampleManifest(t *testing.T) ClosureManifest {
	t.Helper()
	truthDigest, err := DigestTruth(sampleTruth())
	if err != nil {
		t.Fatal(err)
	}
	packages := map[string]WorkPackage{}
	for _, p := range []string{"A", "B", "C", "D", "E", "F", "G"} {
		packages[p] = WorkPackage{Summary: p, Required: true}
	}
	profile := func(id, kind, disposition, auth string) Profile {
		return Profile{ID: id, WorkPackages: []string{"A", "C"}, TaskFamily: "sca", UnitKinds: []string{kind}, ClosedWorld: false,
			Population: Population{Subjects: 2, TruthUnits: 5, Positives: 3, Negatives: 1}, SupportedScope: "linux",
			Corpus: Identity{ID: "corpus", Digest: "sha256:c"}, Truth: Identity{ID: "truth", Version: "1", Digest: truthDigest},
			Scorer: Identity{ID: "benchcore", Version: "1", Digest: "sha256:s"}, MatchingPolicy: Identity{ID: "exact", Digest: "sha256:m"},
			Thresholds:          Thresholds{MinimumRecall: 0.5, MinimumPrecision: 0.5, MaximumUnknown: 0.5, MarginRationale: "pilot"},
			MinimumTruthSupport: Support{Positives: 2, Negatives: 1, Rationale: "pilot"},
			RequiredEnrollment:  []Enrollment{{EngineID: "owned", AdapterID: "owned-cli", ScoredComponent: ScoredComponent{ID: "synapse-cli", Provenance: "release"}, DeclaredCapabilities: []string{kind}}, {EngineID: "other", AdapterID: "other-cli", ScoredComponent: ScoredComponent{ID: "other", Provenance: "pinned"}, DeclaredCapabilities: []string{kind}}},
			Disposition:         disposition, Trigger: "t", Rationale: "r", ExecutionAuthorization: Authorization{Kind: "none", Status: auth}}
	}
	return ClosureManifest{SchemaVersion: ManifestSchemaVersion, ManifestID: "closure", Revision: 1, Claim: "c", PopulationStatement: "p",
		WorkPackages:  packages,
		Profiles:      []Profile{profile("sca.v1", "component-advisory", DispositionRequired, AuthorizationNone), profile("dast.active.v1", "observation", DispositionRequired, AuthorizationNotObtained)},
		ControlSuites: realControlSuites(t),
		Lanes:         []Lane{{ID: "offline", ProfileIDs: []string{"sca.v1"}, Disposition: DispositionRequired, AuthorizationStatus: AuthorizationNone}}}
}

func observation(engine, subject string, findings ...Finding) Observation {
	return Observation{SchemaVersion: ObservationSchemaVersion, ProfileID: "sca.v1",
		Engine:  EngineIdentity{EngineID: engine, AdapterID: engine + "-cli", AdapterVersion: "1", ScoredComponent: ScoredComponent{ID: map[string]string{"owned": "synapse-cli", "other": "other"}[engine], Provenance: "x"}},
		Subject: Subject{ID: subject, Digest: "sha256:" + subject}, State: StateComplete, DeclaredCapabilities: []string{"component-advisory"},
		Normalization: Identity{ID: "exact", Digest: "sha256:m"}, RawEvidenceDigest: "sha256:raw", Findings: findings}
}

func find(purl, advisory string) Finding {
	return Finding{UnitKind: "component-advisory", Identity: map[string]string{"purl": purl, "advisory": advisory}}
}

func TestManifestDigestIsOrderInsensitiveAndValidates(t *testing.T) {
	m := sampleManifest(t)
	if err := m.Validate(); err != nil {
		t.Fatalf("sample manifest: %v", err)
	}
	d1, _ := DigestManifest(m)
	shuffled := m
	shuffled.Profiles = []Profile{m.Profiles[1], m.Profiles[0]}
	shuffled.Profiles[1].RequiredEnrollment = []Enrollment{m.Profiles[0].RequiredEnrollment[1], m.Profiles[0].RequiredEnrollment[0]}
	d2, _ := DigestManifest(shuffled)
	if d1 != d2 {
		t.Fatal("profile or enrollment order changed the manifest digest")
	}
	changed := m
	changed.Profiles = append([]Profile(nil), m.Profiles...)
	changed.Profiles[0].Thresholds.MinimumRecall = 0.9
	if d3, _ := DigestManifest(changed); d3 == d1 {
		t.Fatal("a threshold change left the digest unchanged")
	}
}

func TestManifestRejectsGenericDeclarations(t *testing.T) {
	cases := map[string]func(*ClosureManifest){
		"no truth digest":          func(m *ClosureManifest) { m.Profiles[0].Truth.Digest = "" },
		"no enrollment":            func(m *ClosureManifest) { m.Profiles[0].RequiredEnrollment = nil },
		"optional without trigger": func(m *ClosureManifest) { m.Profiles[0].Disposition = DispositionOptional; m.Profiles[0].Trigger = "" },
		"no support rationale":     func(m *ClosureManifest) { m.Profiles[0].MinimumTruthSupport.Rationale = "" },
		"missing work package":     func(m *ClosureManifest) { delete(m.WorkPackages, "E") },
		"duplicate profile":        func(m *ClosureManifest) { m.Profiles = append(m.Profiles, m.Profiles[0]) },
		"lane names unknown":       func(m *ClosureManifest) { m.Lanes[0].ProfileIDs = []string{"nope"} },
		"capability outside unit kinds": func(m *ClosureManifest) {
			m.Profiles[0].RequiredEnrollment[0].DeclaredCapabilities = []string{"file-rule-line"}
		},
		"no unit kinds": func(m *ClosureManifest) { m.Profiles[0].UnitKinds = nil },
		"legacy evidence mislabelled": func(m *ClosureManifest) {
			m.Profiles[0].LegacyEvidence = &LegacyEvidence{Label: "preregistered", SourcePath: "x"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := sampleManifest(t)
			mutate(&m)
			if err := m.Validate(); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("Validate = %v, want ErrInvalidManifest", err)
			}
		})
	}
}

func TestSuccessionRejectsUndisclosedDowngrade(t *testing.T) {
	prev := sampleManifest(t)
	prevDigest, _ := DigestManifest(prev)
	next := sampleManifest(t)
	next.Revision = 2
	next.Profiles = append([]Profile(nil), prev.Profiles...)
	next.Profiles[1].Disposition = DispositionOptional
	next.Supersedes = &Succession{Revision: 1, Digest: prevDigest, ScopeChangeRationale: "lab unavailable"}
	if err := ValidateSuccession(prev, next); err == nil || !strings.Contains(err.Error(), "downgraded") {
		t.Fatalf("undisclosed downgrade: %v", err)
	}
	next.Supersedes.Changes = []string{"dast.active.v1: required to optional; no authorized lab before the cutoff"}
	if err := ValidateSuccession(prev, next); err != nil {
		t.Fatalf("disclosed downgrade: %v", err)
	}
	next.Supersedes.Digest = "sha256:other"
	if err := ValidateSuccession(prev, next); err == nil {
		t.Fatal("a successor naming another digest must be refused")
	}
}

func TestReceiptAndScorecardBindToTheManifest(t *testing.T) {
	m := sampleManifest(t)
	receipt, err := NewRunStartReceipt(m, RunStart{ProfileID: "sca.v1", RunKey: "run-1", ImplementationCommit: "abc", RunnerIdentity: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.TruthDigest != m.Profiles[0].Truth.Digest || receipt.Manifest.Revision != 1 {
		t.Fatalf("receipt did not copy the frozen digests: %+v", receipt)
	}
	truth := sampleTruth()
	obs := []Observation{observation("owned", "s1", find("pkg:npm/a@1", "CVE-1"), find("pkg:npm/b@1", "CVE-2")), observation("owned", "s2")}
	engine := obs[0].Engine
	card, err := BindScorecard(m, receipt, Binding{Engine: engine, Truth: truth, Observations: obs})
	if err != nil {
		t.Fatal(err)
	}
	if card.Validity.Status != "valid" || card.EngineGrade != GradePass {
		t.Fatalf("card = validity %+v grade %s", card.Validity, card.EngineGrade)
	}
	// The cells are the scorer's, computed from the frozen capabilities: the file-rule-line unit is
	// unsupported for this enrollment, so its end-to-end recall is zero and it is not in assessed-only.
	want, err := Score(ScoringInput{Truth: truth, Observations: obs, Capabilities: []string{"component-advisory"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(card.Cells, want) {
		t.Fatalf("scorecard cells %+v, scorer %+v", card.Cells, want)
	}
	if err := ValidateScorecard(m, receipt, card); err != nil {
		t.Fatal(err)
	}
	// Tampering with the content breaks the self digest; a different manifest breaks the binding.
	forged := card
	forged.EngineGrade = GradeFail
	if err := ValidateScorecard(m, receipt, forged); !errors.Is(err, ErrInvalidScorecard) {
		t.Fatalf("forged grade: %v", err)
	}
	other := sampleManifest(t)
	other.Claim = "another claim"
	if err := ValidateScorecard(other, receipt, card); !errors.Is(err, ErrInvalidScorecard) {
		t.Fatalf("other manifest: %v", err)
	}
	// An engine that is not enrolled, a changed truth, or a changed enrollment cannot be bound.
	if _, err := BindScorecard(m, receipt, Binding{Engine: EngineIdentity{EngineID: "stranger", AdapterID: "x", ScoredComponent: ScoredComponent{ID: "y"}}, Truth: truth, Observations: nil}); !errors.Is(err, ErrInvalidScorecard) {
		t.Fatalf("unenrolled engine: %v", err)
	}
	corrected := truth
	corrected.Units = append([]TruthUnit(nil), truth.Units...)
	corrected.Units[2].Label = LabelPositive
	if _, err := BindScorecard(m, receipt, Binding{Engine: engine, Truth: corrected, Observations: obs}); !errors.Is(err, ErrInvalidScorecard) {
		t.Fatalf("corrected truth under the old manifest: %v", err)
	}
	reenrolled := m
	reenrolled.Profiles = append([]Profile(nil), m.Profiles...)
	reenrolled.Profiles[0].RequiredEnrollment = append([]Enrollment(nil), m.Profiles[0].RequiredEnrollment...)
	reenrolled.Profiles[0].UnitKinds = []string{"component-advisory", "file-rule-line"}
	reenrolled.Profiles[0].RequiredEnrollment[0].DeclaredCapabilities = []string{"component-advisory", "file-rule-line"}
	if _, err := BindScorecard(reenrolled, receipt, Binding{Engine: engine, Truth: truth, Observations: obs}); !errors.Is(err, ErrInvalidScorecard) {
		t.Fatalf("post-run capability change: %v", err)
	}
	// An observation normalized under another policy, or of another subject digest, cannot be bound.
	renormalized := append([]Observation(nil), obs...)
	renormalized[0].Normalization = Identity{ID: "other", Digest: "sha256:o"}
	if _, err := BindScorecard(m, receipt, Binding{Engine: engine, Truth: truth, Observations: renormalized}); !errors.Is(err, ErrInvalidScorecard) {
		t.Fatalf("other matching policy: %v", err)
	}
	moved := append([]Observation(nil), obs...)
	moved[0].Subject.Digest = "sha256:elsewhere"
	if _, err := BindScorecard(m, receipt, Binding{Engine: engine, Truth: truth, Observations: moved}); !errors.Is(err, ErrInvalidScorecard) {
		t.Fatalf("other subject digest: %v", err)
	}
	// Closure needs a valid card for every enrolled engine: one engine's card leaves the profile unexecuted.
	status := ClosureStatus(m, []Scorecard{card})
	if status["sca.v1"] != ProfileNotExecuted || status["dast.active.v1"] != ProfileBlocked || status["work_package:E"] != WorkPackageNotEntered || Closed(status) {
		t.Fatalf("closure status with one engine = %v", status)
	}
	otherObs := []Observation{observation("other", "s1"), observation("other", "s2")}
	otherCard, err := BindScorecard(m, receipt, Binding{Engine: otherObs[0].Engine, Truth: truth, Observations: otherObs})
	if err != nil {
		t.Fatal(err)
	}
	if otherCard.EngineGrade != GradeFail {
		t.Fatalf("an engine that reports nothing fails: %s", otherCard.EngineGrade)
	}
	if status := ClosureStatus(m, []Scorecard{card, otherCard}); status["sca.v1"] != ProfileExecuted {
		t.Fatalf("closure status with both engines = %v", status)
	}
	// A card whose content no longer matches its id, or that names another manifest digest, does not count.
	tampered := otherCard
	tampered.EngineGrade = GradePass
	if status := ClosureStatus(m, []Scorecard{card, tampered}); status["sca.v1"] != ProfileNotExecuted {
		t.Fatalf("tampered card counted: %v", status)
	}
	// An optional profile that names the missing work packages does not enter them.
	optional := m
	optional.Profiles = append([]Profile(nil), m.Profiles...)
	extra := m.Profiles[0]
	extra.ID, extra.Disposition, extra.WorkPackages = "optional.v1", DispositionOptional, []string{"B", "E", "F", "G"}
	optional.Profiles = append(optional.Profiles, extra)
	if status := ClosureStatus(optional, nil); status["work_package:E"] != WorkPackageNotEntered {
		t.Fatalf("an optional profile entered a work package: %v", status)
	}
}

func TestObservationCannotCarryTruthOrVerdict(t *testing.T) {
	doc := `{"schema_version":"synapse-benchmark-observation-v1","profile_id":"p","engine":{"engine_id":"e","adapter_id":"a","adapter_version":"1","scored_component":{"id":"c","provenance":"x"}},"subject":{"id":"s","digest":"d"},"state":"complete","truncated":false,"declared_capabilities":[],"normalization":{"id":"n","digest":"sha256:n"},"raw_evidence_digest":"sha256:r","findings":[],"true_positives":3}`
	if _, err := DecodeObservation(strings.NewReader(doc)); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("an observation with a count field must be refused: %v", err)
	}
	doc = strings.Replace(doc, `,"true_positives":3`, `,"findings":[{"unit_kind":"k","identity":{"a":"b"},"verdict":"tp"}]`, 1)
	doc = strings.Replace(doc, `"findings":[],`, ``, 1)
	if _, err := DecodeObservation(strings.NewReader(doc)); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("a finding with a verdict must be refused: %v", err)
	}
	// ScoringInput carries no engine identity by construction.
	for i := 0; i < reflect.TypeOf(ScoringInput{}).NumField(); i++ {
		if f := reflect.TypeOf(ScoringInput{}).Field(i); f.Type == reflect.TypeOf(EngineIdentity{}) || strings.Contains(strings.ToLower(f.Name), "engine") {
			t.Fatalf("ScoringInput carries engine identity in %s", f.Name)
		}
	}
}

func TestScoreIgnoresEngineIdentityAndOrder(t *testing.T) {
	truth := sampleTruth()
	a := observation("owned", "s1", find("pkg:npm/a@1", "CVE-1"), find("pkg:npm/c@1", "CVE-3"))
	b := observation("other", "s1", find("pkg:npm/c@1", "CVE-3"), find("pkg:npm/a@1", "CVE-1"))
	caps := []string{"component-advisory"}
	ca, err := Score(ScoringInput{Truth: truth, Observations: []Observation{a}, Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	cb, err := Score(ScoringInput{Truth: truth, Observations: []Observation{b}, Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ca, cb) {
		t.Fatalf("engine identity, finding order or case changed the cells:\n%+v\n%+v", ca, cb)
	}
	shuffled := truth
	shuffled.Units = []TruthUnit{truth.Units[4], truth.Units[2], truth.Units[0], truth.Units[3], truth.Units[1]}
	cc, err := Score(ScoringInput{Truth: shuffled, Observations: []Observation{a}, Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ca, cc) {
		t.Fatal("truth order changed the cells")
	}
}

// TestAlternateIdentityMatchesOnce: a finding reported under an alias matches the unit, and reporting both
// the id and the alias is still one true positive and no unknown.
func TestAlternateIdentityMatchesOnce(t *testing.T) {
	truth := sampleTruth()
	truth.Units = append([]TruthUnit(nil), truth.Units...)
	truth.Units[0].AlternateIdentities = []map[string]string{{"purl": "pkg:npm/a@1", "advisory": "GHSA-aaaa"}}
	if err := truth.Validate(); err != nil {
		t.Fatal(err)
	}
	cells, err := Score(ScoringInput{Truth: truth, Observations: []Observation{observation("owned", "s1", find("pkg:npm/a@1", "GHSA-aaaa"), find("pkg:npm/a@1", "CVE-1"))}, Capabilities: []string{"component-advisory"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cells {
		if c.UnitKind == "component-advisory" && (c.EndToEnd.TruePositives != 1 || c.EndToEnd.Unknown != 1) {
			t.Fatalf("alias match: %+v", c.EndToEnd) // the one unknown is the unknown-labelled unit u5
		}
	}
	clash := truth
	clash.Units = append([]TruthUnit(nil), truth.Units...)
	clash.Units[1].AlternateIdentities = []map[string]string{{"purl": "pkg:npm/a@1", "advisory": "CVE-1"}}
	if err := clash.Validate(); !errors.Is(err, ErrInvalidTruth) {
		t.Fatalf("an alternate identity claimed by two units must be refused: %v", err)
	}
}

// TestUnitKeyResistsSeparatorInjection: an identity value cannot forge another identity's key.
func TestUnitKeyResistsSeparatorInjection(t *testing.T) {
	a := unitKey("k", map[string]string{"a": "1\x00b=2"})
	b := unitKey("k", map[string]string{"a": "1", "b": "2"})
	if a == b {
		t.Fatal("embedded separator forged a key")
	}
}

func realControlSuites(t *testing.T) []ControlSuite {
	t.Helper()
	fixture, digest, err := KnownOutcomeFixture()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := DigestExpectedOutcomes(fixture)
	if err != nil {
		t.Fatal(err)
	}
	return []ControlSuite{
		{ID: ControlKnownOutcome, Version: fixture.Version, WorkPackage: "D", FixtureDigest: digest, ExpectedOutcomeDigest: expected},
		{ID: ControlIdentityInvariance, Version: fixture.Version, WorkPackage: "D", FixtureDigest: digest, ExpectedOutcomeDigest: expected},
	}
}

// TestClosedWorldFailsAnOutOfScopeReport: in a closed world, a report under a kind the truth does not
// contain is counted and fails the grade instead of escaping every cell.
func TestClosedWorldFailsAnOutOfScopeReport(t *testing.T) {
	m := sampleManifest(t)
	truth := sampleTruth()
	truth.ClosedWorld = true
	truth.Units = append([]TruthUnit(nil), truth.Units[:4]...) // drop the unknown-labelled unit
	digest, err := DigestTruth(truth)
	if err != nil {
		t.Fatal(err)
	}
	m.Profiles = append([]Profile(nil), m.Profiles...)
	m.Profiles[0].ClosedWorld, m.Profiles[0].Truth.Digest = true, digest
	receipt, err := NewRunStartReceipt(m, RunStart{ProfileID: "sca.v1", RunKey: "r", ImplementationCommit: "c", RunnerIdentity: "t"})
	if err != nil {
		t.Fatal(err)
	}
	stray := Finding{UnitKind: "vulnx", Identity: map[string]string{"advisory": "bogus"}}
	obs := []Observation{observation("owned", "s1", find("pkg:npm/a@1", "CVE-1"), find("pkg:npm/b@1", "CVE-2"), stray, stray), observation("owned", "s2")}
	card, err := BindScorecard(m, receipt, Binding{Engine: obs[0].Engine, Truth: truth, Observations: obs})
	if err != nil {
		t.Fatal(err)
	}
	if card.OutOfScopeFindings != 1 || card.EngineGrade != GradeFail {
		t.Fatalf("out of scope %d grade %s", card.OutOfScopeFindings, card.EngineGrade)
	}
}
