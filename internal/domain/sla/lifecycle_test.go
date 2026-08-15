package sla

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func mustLifecycle(t *testing.T) Lifecycle {
	t.Helper()
	state, err := NewLifecycle(mustAssessment(t), assessmentEpoch)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func transition(t *testing.T, state Lifecycle, id shared.ID, to RemediationStatus, actor, reason string, expiry *time.Time, now time.Time) (Lifecycle, LifecycleEvent) {
	t.Helper()
	next, event, err := ApplyTransition(state, id, TransitionCommand{
		To: to, Actor: actor, Reason: reason, ExpectedVersion: state.Version,
		CompensatingControl: "WAF plus network isolation", AcceptanceExpiresAt: expiry,
	}, now)
	if err != nil {
		t.Fatalf("ApplyTransition: %v", err)
	}
	return next, event
}

func TestLifecycleOrdinaryTransitionsAreVersionedAndAudited(t *testing.T) {
	open := mustLifecycle(t)
	mitigating, first := transition(t, open, "event-1", RemediationMitigating, "alice", "rollout started", nil, assessmentEpoch.Add(time.Hour))
	if mitigating.Version != 2 || mitigating.UpdatedBy != "alice" || mitigating.Status != RemediationMitigating {
		t.Fatalf("unexpected mitigating state: %+v", mitigating)
	}
	if first.From != RemediationOpen || first.To != RemediationMitigating || first.BeforeVersion != 1 || first.AfterVersion != 2 {
		t.Fatalf("unexpected event: %+v", first)
	}
	remediated, second := transition(t, mitigating, "event-2", RemediationRemediated, "bob", "fix deployed and verified", nil, assessmentEpoch.Add(2*time.Hour))
	if remediated.Status != RemediationRemediated || remediated.Version != 3 || second.AssessmentID != open.AssessmentID {
		t.Fatalf("unexpected terminal state/event: %+v %+v", remediated, second)
	}
}

func TestAcceptedRiskRequiresHumanControlAndHardExpiry(t *testing.T) {
	open := mustLifecycle(t)
	expiry := assessmentEpoch.Add(30 * 24 * time.Hour)
	accepted, event := transition(t, open, "event-accept", RemediationAcceptedRisk, "risk.owner@example.com", "upgrade blocked by vendor", &expiry, assessmentEpoch)
	if accepted.AcceptedBy != "risk.owner@example.com" || accepted.AcceptedAt == nil || accepted.AcceptanceExpiresAt == nil {
		t.Fatalf("acceptance provenance missing: %+v", accepted)
	}
	if event.AcceptanceExpiresAt == nil || event.CompensatingControl == "" {
		t.Fatalf("event did not retain acceptance evidence: %+v", event)
	}
	if got := accepted.EffectiveStatus(expiry.Add(-time.Nanosecond)); got != RemediationAcceptedRisk {
		t.Fatalf("before expiry status=%q", got)
	}
	if got := accepted.EffectiveStatus(expiry); got != RemediationOpen {
		t.Fatalf("at expiry status=%q, want fail-safe open", got)
	}
	view, err := NewView(mustAssessment(t), accepted, expiry)
	if err != nil {
		t.Fatal(err)
	}
	if !view.Expired || view.EffectiveState != RemediationOpen {
		t.Fatalf("expired projection not fail-safe: %+v", view)
	}
}

func TestExpiredAcceptanceCanBeExplicitlyRearmedToOpen(t *testing.T) {
	state := mustLifecycle(t)
	expiry := assessmentEpoch.Add(time.Hour)
	accepted, _ := transition(t, state, "accept", RemediationAcceptedRisk, "alice", "temporary exception", &expiry, assessmentEpoch)
	next, event, err := ApplyTransition(accepted, "expire", TransitionCommand{
		To: RemediationOpen, Actor: "alice", Reason: "exception expired", ExpectedVersion: accepted.Version,
	}, expiry)
	if err != nil {
		t.Fatal(err)
	}
	if event.From != RemediationAcceptedRisk || next.Status != RemediationOpen || next.AcceptedAt != nil || next.AcceptanceExpiresAt != nil {
		t.Fatalf("unexpected expiry transition: next=%+v event=%+v", next, event)
	}
}

func TestLifecycleRejectsMachineActors(t *testing.T) {
	for _, actor := range []string{"", "agent:scanner", "llm:model", "mcp:tool", "system:worker", "machine:job", "bot:renovate", "service:sync"} {
		t.Run(actor, func(t *testing.T) {
			_, _, err := ApplyTransition(mustLifecycle(t), "event", TransitionCommand{
				To: RemediationMitigating, Reason: "attempt", Actor: actor, ExpectedVersion: 1,
			}, assessmentEpoch)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("machine actor %q should fail, got %v", actor, err)
			}
		})
	}
}

func TestLifecycleRejectsStaleInvalidAndTerminalChanges(t *testing.T) {
	base := mustLifecycle(t)
	expiryPast := assessmentEpoch.Add(-time.Minute)
	cases := []struct {
		name string
		cmd  TransitionCommand
		want error
	}{
		{name: "stale", cmd: TransitionCommand{To: RemediationMitigating, Actor: "alice", Reason: "x", ExpectedVersion: 2}, want: shared.ErrConflict},
		{name: "unknown", cmd: TransitionCommand{To: "paused", Actor: "alice", Reason: "x", ExpectedVersion: 1}, want: shared.ErrValidation},
		{name: "same", cmd: TransitionCommand{To: RemediationOpen, Actor: "alice", Reason: "x", ExpectedVersion: 1}, want: shared.ErrValidation},
		{name: "no reason", cmd: TransitionCommand{To: RemediationMitigating, Actor: "alice", ExpectedVersion: 1}, want: shared.ErrValidation},
		{name: "accept no expiry", cmd: TransitionCommand{To: RemediationAcceptedRisk, Actor: "alice", Reason: "x", CompensatingControl: "WAF", ExpectedVersion: 1}, want: shared.ErrValidation},
		{name: "accept no control", cmd: TransitionCommand{To: RemediationAcceptedRisk, Actor: "alice", Reason: "x", AcceptanceExpiresAt: ptrTime(assessmentEpoch.Add(time.Hour)), ExpectedVersion: 1}, want: shared.ErrValidation},
		{name: "accept past", cmd: TransitionCommand{To: RemediationAcceptedRisk, Actor: "alice", Reason: "x", CompensatingControl: "WAF", AcceptanceExpiresAt: &expiryPast, ExpectedVersion: 1}, want: shared.ErrValidation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ApplyTransition(base, "event", tc.cmd, assessmentEpoch)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
	remediated, _ := transition(t, base, "finish", RemediationRemediated, "alice", "fixed", nil, assessmentEpoch)
	if _, _, err := ApplyTransition(remediated, "reopen", TransitionCommand{
		To: RemediationOpen, Actor: "alice", Reason: "new intelligence", ExpectedVersion: remediated.Version,
	}, assessmentEpoch.Add(time.Hour)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("terminal remediation reopened: %v", err)
	}
}

func TestLifecycleValidationRejectsMalformedAcceptance(t *testing.T) {
	base := mustLifecycle(t)
	cases := []struct {
		name string
		edit func(*Lifecycle)
	}{
		{name: "version", edit: func(s *Lifecycle) { s.Version = 0 }},
		{name: "actor", edit: func(s *Lifecycle) { s.UpdatedBy = "" }},
		{name: "unknown", edit: func(s *Lifecycle) { s.Status = "paused" }},
		{name: "metadata on open", edit: func(s *Lifecycle) { s.AcceptedBy = "alice" }},
		{name: "accepted incomplete", edit: func(s *Lifecycle) { s.Status = RemediationAcceptedRisk }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := base
			tc.edit(&state)
			if err := state.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

func TestViewOwnershipAndOverdue(t *testing.T) {
	assessment := mustAssessment(t)
	state := mustLifecycle(t)
	view, err := NewView(assessment, state, assessment.Result.RemediateBy)
	if err != nil {
		t.Fatal(err)
	}
	if !view.Overdue || view.Expired || view.EffectiveState != RemediationOpen {
		t.Fatalf("unexpected overdue view: %+v", view)
	}
	state.FindingID = "other"
	if _, err := NewView(assessment, state, assessmentEpoch); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cross-owned join should fail, got %v", err)
	}
}

func ptrTime(value time.Time) *time.Time { return &value }
