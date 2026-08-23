package rulepack

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func testSpec() RulePack {
	now := time.Unix(1_700_000_000, 0).UTC()
	rule := detection.Rule{
		ID: "det.test", Version: 2, Class: detection.ClassProcess, Title: "test", Severity: shared.SeverityHigh,
		Matcher: detection.Matcher{Class: detection.ClassProcess, All: []detection.Predicate{
			{Field: detection.FieldProcArg, Op: detection.OpContains, Value: "--danger"},
			{Field: detection.FieldProcComm, Op: detection.OpIn, Values: []string{"tool-b", "tool-a"}},
		}},
	}
	positive := detection.Event{Class: detection.ClassProcess, At: now, Host: "h1", Process: &detection.ProcessEvent{Comm: "tool-a", Args: []string{"run", "--danger"}}}
	negative := detection.Event{Class: detection.ClassProcess, At: now, Host: "h1", Process: &detection.ProcessEvent{Comm: "tool-a", Args: []string{"run", "--safe"}}}
	return RulePack{
		ID: "runtime-core", Version: 3, Rules: []detection.Rule{rule}, MinAgentVersion: "1.2.0",
		RequiredSchemaVersions: []int{2, 1},
		RequiredSensors:        []SensorRequirement{{ID: "ebpf", MinVersion: "2.0.0"}},
		RequiredFields:         []detection.Field{detection.FieldProcComm, detection.FieldProcArg},
		ATTACKMappings:         []ATTACKMapping{{RuleID: "det.test", TechniqueID: "T1059"}},
		PositiveFixtures:       []Fixture{{ID: "positive", Event: positive, ExpectedRuleIDs: []string{"det.test"}}},
		NegativeFixtures:       []Fixture{{ID: "negative", Event: negative}},
		ExpectedCost:           []RuleCostBudget{{RuleID: "det.test", MaxLatencyMicros: 100, MaxCPUMicrosPerHostDay: 1000}},
		SuppressionPolicy:      SuppressionPolicy{MaxSuppressionRateBPS: 500},
		RolloutCohort:          []string{"canary-b", "canary-a"}, RollbackVersion: 2,
	}
}

func seal(t *testing.T) RulePack {
	t.Helper()
	p, err := New(testSpec())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return *p
}

func TestDigestIsCanonicalAcrossSetOrdering(t *testing.T) {
	a := seal(t)
	spec := testSpec()
	spec.RequiredSchemaVersions = []int{1, 2}
	spec.RequiredFields = []detection.Field{detection.FieldProcArg, detection.FieldProcComm}
	spec.RolloutCohort = []string{"canary-a", "canary-b"}
	spec.Rules[0].Matcher.All[1].Values = []string{"tool-a", "tool-b"}
	b, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest != b.Digest {
		t.Fatalf("canonical order changed digest: %s != %s", a.Digest, b.Digest)
	}
}

func TestDigestChangesOnSemanticMutationAndNewDefensivelyCopies(t *testing.T) {
	spec := testSpec()
	p, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	original := p.Digest
	spec.Rules[0].Matcher.All[0].Value = "--other"
	spec.RequiredFields[0] = detection.FieldFilePath
	spec.PositiveFixtures[0].Event.Process.Args[1] = "--safe"
	if p.Digest != original {
		t.Fatal("caller mutation changed sealed pack")
	}
	mut := *p
	mut.Rules[0].Matcher.All[0].Value = "--other"
	if err := mut.Validate(); err == nil {
		t.Fatal("content mutation with stale digest must fail")
	}
}

func TestSignVerifyUsesPinnedTrustedKeyAndRejectsTamper(t *testing.T) {
	p := seal(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Sign(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(a, pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if err := Verify(a, otherPub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong trusted key err = %v", err)
	}
	a.Pack.Rules[0].Title = "tampered"
	if err := Verify(a, pub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tamper err = %v", err)
	}
}

func TestReplayExactPositiveAndNegative(t *testing.T) {
	p := seal(t)
	results, err := Replay(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d", len(results))
	}
	byID := map[string]ReplayResult{}
	for _, r := range results {
		byID[r.FixtureID] = r
	}
	if !byID["positive"].Pass || !byID["negative"].Pass {
		t.Fatalf("replay = %+v", results)
	}

	p.NegativeFixtures[0].Event.Process.Args = []string{"--danger"}
	p.Digest, _ = ComputeDigest(p)
	results, err = Replay(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.FixtureID == "negative" && r.Pass {
			t.Fatal("negative false positive must fail replay")
		}
	}
}

func TestCompatibleFailsClosedAndTransitionIsBounded(t *testing.T) {
	p := seal(t)
	d := RulePackDeployment{
		PackID: p.ID, PackVersion: p.Version, PackDigest: p.Digest,
		AgentVersion: "1.2.1", SchemaVersion: 1,
		Sensors:         []SensorRequirement{{ID: "ebpf", MinVersion: "2.1.0"}},
		AvailableFields: []detection.Field{detection.FieldProcArg, detection.FieldProcComm},
		Cohort:          "canary-a", State: DeploymentCandidate, PreviousVersion: 2,
	}
	if err := Compatible(p, d); err != nil {
		t.Fatalf("Compatible: %v", err)
	}
	canary, err := Transition(p, d, DeploymentCanary)
	if err != nil || canary.State != DeploymentCanary {
		t.Fatalf("candidate -> canary = %+v, %v", canary, err)
	}
	promoted, err := Transition(p, canary, DeploymentPromoted)
	if err != nil || promoted.State != DeploymentPromoted {
		t.Fatalf("canary -> promoted = %+v, %v", promoted, err)
	}
	rolled, err := Transition(p, promoted, DeploymentRolledBack)
	if err != nil || rolled.State != DeploymentRolledBack {
		t.Fatalf("promoted -> rollback = %+v, %v", rolled, err)
	}
	if _, err := Transition(p, d, DeploymentPromoted); err == nil {
		t.Fatal("candidate -> promoted must be refused")
	}

	bad := d
	bad.AvailableFields = []detection.Field{detection.FieldProcComm}
	if err := Compatible(p, bad); err == nil {
		t.Fatal("missing required field must fail")
	}
	bad = d
	bad.AgentVersion = "garbage"
	if err := Compatible(p, bad); err == nil {
		t.Fatal("unparseable deployment version must fail")
	}
}

func TestRequiredFieldsCannotUnderstateMatcherNeeds(t *testing.T) {
	spec := testSpec()
	spec.RequiredFields = []detection.Field{detection.FieldProcComm}
	if _, err := New(spec); err == nil {
		t.Fatal("matcher field absent from required_fields must fail")
	}
}

func TestValidationRejectsNonCanonicalAndPathologicalContent(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RulePack)
	}{
		{"pack id whitespace", func(p *RulePack) { p.ID = " core " }},
		{"agent version whitespace", func(p *RulePack) { p.MinAgentVersion = " 1.2.0" }},
		{"sensor id whitespace", func(p *RulePack) { p.RequiredSensors[0].ID = " ebpf" }},
		{"sensor version whitespace", func(p *RulePack) { p.RequiredSensors[0].MinVersion = "2.0.0 " }},
		{"fixture id whitespace", func(p *RulePack) { p.PositiveFixtures[0].ID = " positive" }},
		{"no ATTACK mapping", func(p *RulePack) { p.ATTACKMappings = nil }},
		{"duplicate in values", func(p *RulePack) { p.Rules[0].Matcher.All[1].Values = []string{"tool-a", "tool-a"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := testSpec()
			tt.mutate(&spec)
			if _, err := New(spec); err == nil {
				t.Fatalf("New should reject %s", tt.name)
			}
		})
	}
}

func TestValidationBoundsFixtureAndPredicateWork(t *testing.T) {
	spec := testSpec()
	spec.Rules[0].Matcher.All[0].Value = string(make([]byte, MaxPredicateStringBytes+1))
	if _, err := New(spec); err == nil {
		t.Fatal("oversized predicate string must fail")
	}

	spec = testSpec()
	spec.PositiveFixtures[0].Event.Process.Args = []string{string(make([]byte, MaxFixtureEventBytes+1))}
	if _, err := New(spec); err == nil {
		t.Fatal("oversized fixture event must fail")
	}
}

func TestCanaryCohortMustBeAuthorized(t *testing.T) {
	p := seal(t)
	d := RulePackDeployment{
		PackID: p.ID, PackVersion: p.Version, PackDigest: p.Digest,
		AgentVersion: "1.2.1", SchemaVersion: 1,
		Sensors:         []SensorRequirement{{ID: "ebpf", MinVersion: "2.1.0"}},
		AvailableFields: []detection.Field{detection.FieldProcArg, detection.FieldProcComm},
		Cohort:          "not-authorized", State: DeploymentCandidate, PreviousVersion: 2,
	}
	if err := Compatible(p, d); err == nil {
		t.Fatal("candidate intended for an unauthorized canary cohort must fail compatibility")
	}
	if _, err := Transition(p, d, DeploymentCanary); err == nil {
		t.Fatal("transition must not bypass cohort authorization")
	}
}
