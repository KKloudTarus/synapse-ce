package sla

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var assessmentEpoch = time.Date(2026, 8, 15, 9, 30, 0, 0, time.UTC)

func validAssessmentInput() AssessmentInput {
	return AssessmentInput{
		TenantID: "tenant-a", EngagementID: "eng-1", FindingID: "finding-1", SourceRiskAssessmentID: "risk-1",
		Risk: Inputs{
			Severity: shared.SeverityCritical, CVSSScore: 9.8, KEV: true, EPSS: 0.91,
			PublicPoC: true, Criticality: CriticalityHigh, Exposure: ExposureExternal,
			Feasibility: FeasibilityPatchAvailable,
		},
	}
}

func mustAssessment(t *testing.T) Assessment {
	t.Helper()
	item, err := Evaluate(validAssessmentInput(), DefaultConfig(), assessmentEpoch)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return item
}

func TestAssessmentEvaluateIsDeterministicAndBound(t *testing.T) {
	first := mustAssessment(t)
	second, err := Evaluate(validAssessmentInput(), DefaultConfig(), assessmentEpoch.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || first.InputHash != second.InputHash || first.ConfigHash != second.ConfigHash {
		t.Fatalf("materially identical input changed identity: first=%+v second=%+v", first, second)
	}
	if first.AssessedAt == second.AssessedAt || first.Result.RemediateBy == second.Result.RemediateBy {
		t.Fatal("candidate clocks should reflect the attempted assessment; the store preserves the original on replay")
	}
	if first.TenantID != "tenant-a" || first.EngagementID != "eng-1" || first.FindingID != "finding-1" || first.SourceRiskAssessmentID != "risk-1" {
		t.Fatalf("ownership/provenance not retained: %+v", first)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("valid assessment rejected: %v", err)
	}
}

func TestAssessmentIdentityChangesOnlyForMaterialInputOrPolicy(t *testing.T) {
	base := mustAssessment(t)
	cases := []struct {
		name  string
		input AssessmentInput
		cfg   Config
	}{
		{name: "finding", input: func() AssessmentInput { in := validAssessmentInput(); in.FindingID = "finding-2"; return in }(), cfg: DefaultConfig()},
		{name: "tenant", input: func() AssessmentInput { in := validAssessmentInput(); in.TenantID = "tenant-b"; return in }(), cfg: DefaultConfig()},
		{name: "risk", input: func() AssessmentInput { in := validAssessmentInput(); in.Risk.EPSS = 0.2; return in }(), cfg: DefaultConfig()},
		{name: "policy", input: validAssessmentInput(), cfg: func() Config { cfg := DefaultConfig(); cfg.Version = "sla-v2"; return cfg }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Evaluate(tc.input, tc.cfg, assessmentEpoch)
			if err != nil {
				t.Fatal(err)
			}
			if got.ID == base.ID {
				t.Fatalf("material change %q retained assessment id %s", tc.name, got.ID)
			}
		})
	}
}

func TestAssessmentIdentityIgnoresProvenanceOnlyRefresh(t *testing.T) {
	first := validAssessmentInput()
	second := validAssessmentInput()
	second.SourceRiskAssessmentID = "risk-2"
	left, err := Evaluate(first, DefaultConfig(), assessmentEpoch)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Evaluate(second, DefaultConfig(), assessmentEpoch.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if left.ID != right.ID || left.InputHash != right.InputHash {
		t.Fatalf("provenance-only refresh changed SLA identity: first=%+v second=%+v", left, right)
	}
	if right.SourceRiskAssessmentID != "risk-2" {
		t.Fatalf("candidate did not retain new source provenance: %+v", right)
	}
}

func TestAssessmentInputValidation(t *testing.T) {
	cases := []struct {
		name string
		edit func(*AssessmentInput)
	}{
		{name: "engagement", edit: func(in *AssessmentInput) { in.EngagementID = "" }},
		{name: "finding", edit: func(in *AssessmentInput) { in.FindingID = "" }},
		{name: "time", edit: func(*AssessmentInput) {}},
		{name: "severity", edit: func(in *AssessmentInput) { in.Risk.Severity = "urgent" }},
		{name: "cvss negative", edit: func(in *AssessmentInput) { in.Risk.CVSSScore = -0.1 }},
		{name: "cvss high", edit: func(in *AssessmentInput) { in.Risk.CVSSScore = 10.1 }},
		{name: "epss negative", edit: func(in *AssessmentInput) { in.Risk.EPSS = -0.1 }},
		{name: "epss high", edit: func(in *AssessmentInput) { in.Risk.EPSS = 1.1 }},
		{name: "exposure", edit: func(in *AssessmentInput) { in.Risk.Exposure = "partner" }},
		{name: "criticality", edit: func(in *AssessmentInput) { in.Risk.Criticality = "mission" }},
		{name: "feasibility", edit: func(in *AssessmentInput) { in.Risk.Feasibility = "eventually" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := validAssessmentInput()
			tc.edit(&input)
			now := assessmentEpoch
			if tc.name == "time" {
				now = time.Time{}
			}
			if _, err := Evaluate(input, DefaultConfig(), now); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

func TestAssessmentValidateDetectsTampering(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Assessment)
	}{
		{name: "id", edit: func(a *Assessment) { a.ID = "forged" }},
		{name: "input hash", edit: func(a *Assessment) { a.InputHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }},
		{name: "config hash", edit: func(a *Assessment) { a.ConfigHash = "short" }},
		{name: "computed at", edit: func(a *Assessment) { a.Result.ComputedAt = time.Time{} }},
		{name: "mitigate before computed", edit: func(a *Assessment) { a.Result.MitigateBy = a.Result.ComputedAt.Add(-time.Second) }},
		{name: "remediate before mitigate", edit: func(a *Assessment) { a.Result.RemediateBy = a.Result.MitigateBy.Add(-time.Second) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			item := mustAssessment(t)
			tc.edit(&item)
			if err := item.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

func TestPolicyDigestAndValidation(t *testing.T) {
	policy, err := NewPolicy("tenant-a", DefaultConfig(), "alice", assessmentEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.SHA256) != 64 || policy.CreatedAt.Location() != time.UTC {
		t.Fatalf("unexpected canonical policy: %+v", policy)
	}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	copy := policy
	copy.Config.Thresholds.High++
	if err := copy.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("tampered config should fail digest validation, got %v", err)
	}
	copy = policy
	copy.SHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if err := copy.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("tampered digest should fail, got %v", err)
	}
}

func TestNewPolicyRejectsInvalidProvenanceAndConfig(t *testing.T) {
	cases := []struct {
		name   string
		actor  string
		now    time.Time
		config Config
	}{
		{name: "actor", now: assessmentEpoch, config: DefaultConfig()},
		{name: "time", actor: "alice", config: DefaultConfig()},
		{name: "config", actor: "alice", now: assessmentEpoch, config: Config{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewPolicy("tenant-a", tc.config, tc.actor, tc.now); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}
