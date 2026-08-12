package aitriagereview

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func validInput() Input {
	return Input{ID: "r1", TenantID: "default", EngagementID: "e1", FindingID: "f1", EvidenceRef: "ev1",
		DedupKey: "sast:key", Title: "SQL injection", Severity: shared.SeverityHigh,
		Verdict: "refuted", Driver: "sanitizer", Confidence: 91, SuspectedFP: true,
		ProposerModel: "model-a", VerifierModel: "model-b", Verified: true,
		PromptVersion: "fp-triage-v1", VerifierVerdict: "refuted", VerifierConfidence: 90, PolicyVersion: "fp-gate-v3",
		PolicyReason: "severity_requires_human", ReviewRequired: true}
}

func TestNewPendingRequiresPolicyHeldSealedCritique(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	for name, mutate := range map[string]func(*Input){
		"missing evidence": func(in *Input) { in.EvidenceRef = "" },
		"gate exempt":      func(in *Input) { in.GateExempt = true },
		"not review":       func(in *Input) { in.ReviewRequired = false },
	} {
		t.Run(name, func(t *testing.T) {
			in := validInput()
			mutate(&in)
			if _, err := NewPending(in, now); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

func TestNewPendingCurrentAndFuturePoliciesRequireCompleteIndependenceMetadata(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	for _, version := range []string{"fp-gate-v4", "fp-gate-v5", "fp-gate-v6", "fp-gate-future"} {
		t.Run(version, func(t *testing.T) {
			valid := validInput()
			valid.PolicyVersion = version
			valid.ProposerProvider, valid.ProposerModelFamily = "openai", "model-a"
			valid.VerifierProvider, valid.VerifierModelFamily = "anthropic", "model-b"
			valid.IndependencePolicy = "provider"
			if _, err := NewPending(valid, now); err != nil {
				t.Fatalf("complete %s identity rejected: %v", version, err)
			}
			for name, mutate := range map[string]func(*Input){
				"missing proposer provider": func(in *Input) { in.ProposerProvider = "" },
				"missing proposer family":   func(in *Input) { in.ProposerModelFamily = "" },
				"missing verifier provider": func(in *Input) { in.VerifierProvider = "" },
				"missing verifier family":   func(in *Input) { in.VerifierModelFamily = "" },
				"missing policy":            func(in *Input) { in.IndependencePolicy = "" },
			} {
				t.Run(name, func(t *testing.T) {
					in := valid
					mutate(&in)
					if _, err := NewPending(in, now); !errors.Is(err, shared.ErrValidation) {
						t.Fatalf("want validation error, got %v", err)
					}
				})
			}
		})
	}
}

func TestNewPendingExplicitLegacyPolicyRemainsCompatible(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	for _, version := range []string{"fp-gate-v1", "fp-gate-v2", "fp-gate-v3"} {
		in := validInput()
		in.PolicyVersion = version
		if _, err := NewPending(in, now); err != nil {
			t.Fatalf("legacy %s review rejected: %v", version, err)
		}
	}
}

func TestDecisionRequiresHumanRationaleAndKeepsClosedLifecycle(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	r, err := NewPending(validInput(), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []string{"llm:model-a", "agent:runner", "mcp:bot", "model-a", "MODEL-B"} {
		if _, err := r.Decide(DecisionAccept, actor, "reviewed evidence", 1, now.Add(time.Second)); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("machine/model actor %q must be rejected, got %v", actor, err)
		}
	}
	r, err = r.Claim("reviewer", 1, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Decide(DecisionReject, "reviewer", "x", 2, now.Add(2*time.Second)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("short rationale: %v", err)
	}
	updated, err := r.Decide(DecisionReject, "reviewer", "source is reachable", 2, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if updated.State != StateRejected || updated.DecidedBy != "reviewer" || updated.Version != 3 {
		t.Fatalf("unexpected decision: %+v", updated)
	}
	if _, err := updated.Decide(DecisionAccept, "other", "changed mind", 3, now.Add(3*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("terminal review changed: %v", err)
	}
}

func TestClaimAssignsOnlyHumanReviewer(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	r, err := NewPending(validInput(), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Claim("agent:bot", 1, now.Add(time.Second)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("machine claim: %v", err)
	}
	claimed, err := r.Claim("reviewer", 1, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Owner != "reviewer" || claimed.Version != 2 {
		t.Fatalf("unexpected claim: %+v", claimed)
	}
	if _, err := claimed.Claim("other-reviewer", 2, now.Add(2*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("owned review was taken over: %v", err)
	}
}

// TestDecideRefusesEveryMachinePrincipalFamily pins the second line of the separation-of-duties check.
// RBAC is the first line and machine roles hold no human-API permission, but in-process callers do not
// pass through it -- so this must cover the prefixes the codebase actually mints. "system:" is the
// largest family (system:dast-engine, system:taint-scan, system:cross-check, ...) and was missing, which
// left the widest class of machine principal able to decide a human review.
func TestDecideRefusesEveryMachinePrincipalFamily(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	base, err := NewPending(validInput(), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []string{
		"system:dast-engine", "system:taint-scan", "system:cross-check",
		"machine:worker", "bot:triage", "service:scanner",
		"SYSTEM:DAST-ENGINE", "  system:dast-engine  ",
	} {
		if _, err := base.Decide(DecisionAccept, actor, "reviewed evidence", 1, now.Add(time.Second)); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("machine actor %q must be rejected as a machine, got %v", actor, err)
		}
	}
	claimed, err := base.Claim("alice", 1, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := claimed.Decide(DecisionAccept, "alice", "verified unreachable", claimed.Version, now.Add(2*time.Second)); err != nil {
		t.Fatalf("a human owner must be able to decide: %v", err)
	}
}
