package slauc

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityrisk"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

type slaTestClock struct{ now time.Time }

func (c *slaTestClock) Now() time.Time { return c.now }

type slaTestIDs struct{ next int }

func (ids *slaTestIDs) NewID() shared.ID {
	ids.next++
	return shared.ID(fmt.Sprintf("event-%d", ids.next))
}

var serviceEpoch = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func newSLAService(t *testing.T) (*Service, *slaTestClock, *memory.SLAStore, context.Context) {
	t.Helper()
	clock := &slaTestClock{now: serviceEpoch}
	store := memory.NewSLAStore()
	service, err := NewService(store, clock, &slaTestIDs{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	return service, clock, store, ctx
}

func assessRequest() sla.AssessmentInput {
	return sla.AssessmentInput{
		TenantID: "tenant-a", EngagementID: "eng-1", FindingID: "finding-1",
		Risk: sla.Inputs{Severity: shared.SeverityHigh, CVSSScore: 8.1, EPSS: 0.4, Feasibility: sla.FeasibilityPatchAvailable},
	}
}

func TestNewServiceRequiresDependencies(t *testing.T) {
	store := memory.NewSLAStore()
	clock := &slaTestClock{now: serviceEpoch}
	ids := &slaTestIDs{}
	cases := []struct {
		name string
		run  func() error
	}{
		{name: "store", run: func() error { _, err := NewService(nil, clock, ids); return err }},
		{name: "clock", run: func() error { _, err := NewService(store, nil, ids); return err }},
		{name: "ids", run: func() error { _, err := NewService(store, clock, nil); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

func TestAssessInstallsDefaultPolicyAndDoesNotMoveDeadlineOnReplay(t *testing.T) {
	service, clock, _, ctx := newSLAService(t)
	first, err := service.Assess(ctx, assessRequest())
	if err != nil {
		t.Fatal(err)
	}
	if first.Assessment.Result.ConfigVersion != "sla-v1" || first.Lifecycle.Status != sla.RemediationOpen {
		t.Fatalf("unexpected first view: %+v", first)
	}
	active, err := service.ActivePolicy(ctx, "tenant-a")
	if err != nil || active.CreatedBy != builtInPolicyActor || active.Config.Version != "sla-v1" {
		t.Fatalf("default policy=%+v err=%v", active, err)
	}
	clock.now = clock.now.Add(7 * 24 * time.Hour)
	replayed, err := service.Assess(ctx, assessRequest())
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Assessment.ID != first.Assessment.ID || !replayed.Assessment.Result.RemediateBy.Equal(first.Assessment.Result.RemediateBy) {
		t.Fatalf("replay moved identity/deadline: first=%+v replay=%+v", first.Assessment, replayed.Assessment)
	}
	provenanceOnly := assessRequest()
	provenanceOnly.SourceRiskAssessmentID = "risk-refresh-with-same-sla-facts"
	clock.now = clock.now.Add(time.Hour)
	refreshed, err := service.Assess(ctx, provenanceOnly)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.Assessment.ID != first.Assessment.ID ||
		!refreshed.Assessment.Result.RemediateBy.Equal(first.Assessment.Result.RemediateBy) {
		t.Fatalf("provenance-only refresh moved SLA deadline: first=%+v refresh=%+v", first.Assessment, refreshed.Assessment)
	}
	policies, err := service.Policies(ctx, "tenant-a")
	if err != nil || len(policies) != 1 {
		t.Fatalf("policies=%+v err=%v", policies, err)
	}
}

func TestAssessmentRefreshPreservesAcceptedRisk(t *testing.T) {
	service, clock, _, ctx := newSLAService(t)
	initial, err := service.Assess(ctx, assessRequest())
	if err != nil {
		t.Fatal(err)
	}
	expires := serviceEpoch.Add(30 * 24 * time.Hour)
	accepted, err := service.Transition(ctx, "tenant-a", "eng-1", "finding-1", sla.TransitionCommand{
		To: sla.RemediationAcceptedRisk, Actor: "alice", Reason: "vendor support window",
		CompensatingControl: "WAF plus isolation", AcceptanceExpiresAt: &expires, ExpectedVersion: initial.Lifecycle.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(time.Hour)
	request := assessRequest()
	request.SourceRiskAssessmentID = "risk-new"
	request.Risk.ActiveExploitation = true
	refreshed, err := service.Assess(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.Assessment.ID == initial.Assessment.ID || refreshed.Assessment.PreviousAssessmentID != initial.Assessment.ID {
		t.Fatalf("assessment history did not advance: %+v", refreshed.Assessment)
	}
	if refreshed.Lifecycle.Status != sla.RemediationAcceptedRisk || refreshed.Lifecycle.Version != accepted.Lifecycle.Version ||
		refreshed.Lifecycle.AcceptedBy != "alice" || refreshed.Lifecycle.AssessmentID != refreshed.Assessment.ID {
		t.Fatalf("risk refresh clobbered human state: %+v", refreshed.Lifecycle)
	}
	history, err := service.AssessmentHistory(ctx, "tenant-a", "eng-1", "finding-1")
	if err != nil || len(history) != 2 {
		t.Fatalf("history=%+v err=%v", history, err)
	}
	events, err := service.LifecycleEvents(ctx, "tenant-a", "eng-1", "finding-1")
	if err != nil || len(events) != 1 || events[0].To != sla.RemediationAcceptedRisk {
		t.Fatalf("events=%+v err=%v", events, err)
	}
}

func TestActivatePolicyIsHumanOnlyAndAffectsFutureAssessment(t *testing.T) {
	service, clock, _, ctx := newSLAService(t)
	first, err := service.Assess(ctx, assessRequest())
	if err != nil {
		t.Fatal(err)
	}
	cfg := sla.DefaultConfig()
	cfg.Version = "tenant-policy-2"
	cfg.DueRanges.High.RemediateWithin = 10 * 24 * time.Hour
	if _, _, err := service.ActivatePolicy(ctx, "tenant-a", cfg, "system:policy-bot"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("machine policy activation should fail, got %v", err)
	}
	clock.now = clock.now.Add(time.Hour)
	policy, created, err := service.ActivatePolicy(ctx, "tenant-a", cfg, "security-admin@example.com")
	if err != nil || !created || policy.Config.Version != cfg.Version {
		t.Fatalf("policy=%+v created=%v err=%v", policy, created, err)
	}
	second, err := service.Assess(ctx, assessRequest())
	if err != nil {
		t.Fatal(err)
	}
	if second.Assessment.ID == first.Assessment.ID || second.Assessment.Result.ConfigVersion != cfg.Version ||
		second.Assessment.PreviousAssessmentID != first.Assessment.ID {
		t.Fatalf("new policy did not version assessment: %+v", second.Assessment)
	}
	if got := second.Assessment.Result.RemediateBy.Sub(second.Assessment.AssessedAt); got != 10*24*time.Hour {
		t.Fatalf("new due policy not applied: %v", got)
	}
	if _, created, err := service.ActivatePolicy(ctx, "tenant-a", cfg, "security-admin@example.com"); err != nil || created {
		t.Fatalf("policy replay created=%v err=%v", created, err)
	}
}

func TestTransitionUsesOptimisticVersionAndHumanPrincipal(t *testing.T) {
	service, _, _, ctx := newSLAService(t)
	initial, err := service.Assess(ctx, assessRequest())
	if err != nil {
		t.Fatal(err)
	}
	updated, err := service.Transition(ctx, "tenant-a", "eng-1", "finding-1", sla.TransitionCommand{
		To: sla.RemediationMitigating, Actor: "reviewer", Reason: "maintenance scheduled", ExpectedVersion: 1,
	})
	if err != nil || updated.Lifecycle.Version != 2 {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
	if _, err := service.Transition(ctx, "tenant-a", "eng-1", "finding-1", sla.TransitionCommand{
		To: sla.RemediationRemediated, Actor: "reviewer", Reason: "stale", ExpectedVersion: initial.Lifecycle.Version,
	}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale transition should conflict, got %v", err)
	}
	if _, err := service.Transition(ctx, "tenant-a", "eng-1", "finding-1", sla.TransitionCommand{
		To: sla.RemediationRemediated, Actor: "agent:fixer", Reason: "automated", ExpectedVersion: 2,
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("machine transition should fail, got %v", err)
	}
}

func TestListAndGetCalculateOverdueAtReadTime(t *testing.T) {
	service, clock, _, ctx := newSLAService(t)
	view, err := service.Assess(ctx, assessRequest())
	if err != nil {
		t.Fatal(err)
	}
	clock.now = view.Assessment.Result.RemediateBy
	got, err := service.Get(ctx, "tenant-a", "eng-1", "finding-1")
	if err != nil || !got.Overdue {
		t.Fatalf("get=%+v err=%v", got, err)
	}
	list, err := service.List(ctx, "tenant-a", "eng-1")
	if err != nil || len(list) != 1 || !list[0].Overdue {
		t.Fatalf("list=%+v err=%v", list, err)
	}
}

func TestServiceTenantBoundaryFailsClosed(t *testing.T) {
	service, _, _, ctx := newSLAService(t)
	if _, err := service.Assess(context.Background(), assessRequest()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant should fail, got %v", err)
	}
	request := assessRequest()
	request.TenantID = "tenant-b"
	if _, err := service.Assess(ctx, request); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("mismatch should fail, got %v", err)
	}
	if _, err := service.Get(ctx, "tenant-b", "eng-1", "finding-1"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cross tenant get should fail, got %v", err)
	}
}

func TestInputsFromFindingUsesOnlyDurableSignals(t *testing.T) {
	item := finding.Finding{
		Severity: shared.SeverityHigh, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		KEV: true, RiskScore: 4.9, FixedVersion: "2.0.0", Kind: finding.KindSCA, DedupKey: "vuln:CVE-1:pkg:1",
	}
	inputs := InputsFromFinding(item)
	if inputs.CVSSScore != 9.8 || inputs.EPSS < 0.49 || inputs.EPSS > 0.51 || !inputs.KEV || inputs.Feasibility != sla.FeasibilityPatchAvailable {
		t.Fatalf("unexpected finding inputs: %+v", inputs)
	}
	if inputs.Exposure != sla.ExposureUnknown || inputs.Criticality != sla.CriticalityUnknown || inputs.PublicPoC || inputs.ActiveExploitation {
		t.Fatalf("mapper invented unavailable context: %+v", inputs)
	}
	item.FixedVersion = ""
	if got := InputsFromFinding(item).Feasibility; got != sla.FeasibilityNoPatch {
		t.Fatalf("unfixed vulnerability feasibility=%q", got)
	}
	item.DedupKey = "license:GPL-3.0"
	if got := InputsFromFinding(item).Feasibility; got != sla.FeasibilityUnknown {
		t.Fatalf("license finding should not be treated as no-patch vulnerability: %q", got)
	}
}

func TestInputsFromRiskAssessmentRetainsThreatIntelligence(t *testing.T) {
	assessment := vulnerabilityrisk.Assessment{
		Severity: shared.SeverityCritical, CVSSScore: 9.8, KEV: true, EPSS: 0.92,
		FixedVersion: "3.1.4", ReasonCodes: []string{"public_exploit", "active_exploitation", "unrelated"},
	}
	inputs := InputsFromRiskAssessment(assessment)
	if !inputs.PublicPoC || !inputs.ActiveExploitation || !inputs.KEV || inputs.EPSS != 0.92 || inputs.Feasibility != sla.FeasibilityPatchAvailable {
		t.Fatalf("unexpected continuous-intelligence inputs: %+v", inputs)
	}
	assessment.FixedVersion = ""
	if got := InputsFromRiskAssessment(assessment).Feasibility; got != sla.FeasibilityNoPatch {
		t.Fatalf("no-fix assessment feasibility=%q", got)
	}
}
