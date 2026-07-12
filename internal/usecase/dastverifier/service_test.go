package dastverifier

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type fakeJudgmentVerifier struct {
	calls []verifyCall
	err   error
}

type verifyCall struct {
	verifier                 string
	engagementID, judgmentID shared.ID
	score                    int
	rationale                string
	expectedVersion          int
}

func (f *fakeJudgmentVerifier) VerifyRuntime(_ context.Context, verifier string, engagementID, judgmentID shared.ID, score int, rationale string, expectedVersion int) (judgment.Judgment, error) {
	f.calls = append(f.calls, verifyCall{verifier: verifier, engagementID: engagementID, judgmentID: judgmentID, score: score, rationale: rationale, expectedVersion: expectedVersion})
	if f.err != nil {
		return judgment.Judgment{}, f.err
	}
	return judgment.Judgment{ID: judgmentID, EngagementID: engagementID, Capability: judgment.CapSAST, State: judgment.StateConfirmed, EvidenceScore: score}, nil
}

func TestApplyDelegatesToJudgmentGate(t *testing.T) {
	fv := &fakeJudgmentVerifier{}
	svc, err := NewService(fv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.Apply(context.Background(), "eng-1", Result{
		JudgmentID:      "j-1",
		Verifier:        "human:verifier",
		Score:           85,
		ProofClass:      ProofClassRuntimeConfirmed,
		Rationale:       "safe canary callback observed; no sensitive data extracted",
		ExpectedVersion: 3,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got.ID != "j-1" || got.EvidenceScore != 85 {
		t.Fatalf("unexpected judgment: %+v", got)
	}
	if len(fv.calls) != 1 {
		t.Fatalf("want one downstream verify call, got %d", len(fv.calls))
	}
	call := fv.calls[0]
	if call.verifier != "human:verifier" || call.engagementID != "eng-1" || call.judgmentID != "j-1" || call.score != 85 || call.expectedVersion != 3 {
		t.Fatalf("downstream verify call lost custody fields: %+v", call)
	}
	if !strings.Contains(call.rationale, "proof_class=runtime_confirmed") || !strings.Contains(call.rationale, "safe canary") {
		t.Fatalf("rationale should preserve proof class + verifier summary: %q", call.rationale)
	}
}

func TestApplyFailClosedValidation(t *testing.T) {
	fv := &fakeJudgmentVerifier{}
	svc, _ := NewService(fv)
	cases := []Result{
		{JudgmentID: "", Verifier: "human:v", Score: 80, ProofClass: ProofClassRuntimeConfirmed, Rationale: "x"},
		{JudgmentID: "j", Verifier: "", Score: 80, ProofClass: ProofClassRuntimeConfirmed, Rationale: "x"},
		{JudgmentID: "j", Verifier: "human:v", Score: 80, ProofClass: ProofClass("payload_here"), Rationale: "x"},
		{JudgmentID: "j", Verifier: "human:v", Score: 80, ProofClass: ProofClassRuntimeConfirmed, Rationale: ""},
	}
	for _, tc := range cases {
		if _, err := svc.Apply(context.Background(), "eng-1", tc); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("Apply(%+v): want ErrValidation, got %v", tc, err)
		}
	}
	if len(fv.calls) != 0 {
		t.Fatalf("invalid verifier results must not reach analysis.Verify: %+v", fv.calls)
	}
}

// A proof_class and a score that DISAGREE are rejected before anything is sealed, so the sealed evidence
// is never internally inconsistent (e.g. a "refuted" rationale on a bar-clearing verdict that then confirms).
func TestApplyRejectsProofClassScoreMismatch(t *testing.T) {
	fv := &fakeJudgmentVerifier{}
	svc, _ := NewService(fv)
	bad := []Result{
		{JudgmentID: "j", Verifier: "human:v", Score: 40, ProofClass: ProofClassRuntimeConfirmed, Rationale: "x"}, // confirmed but sub-bar
		{JudgmentID: "j", Verifier: "human:v", Score: 90, ProofClass: ProofClassRuntimeRefuted, Rationale: "x"},   // refuted but bar-clearing
		{JudgmentID: "j", Verifier: "human:v", Score: 80, ProofClass: ProofClassNeedsMoreProof, Rationale: "x"},   // needs-more but bar-clearing
	}
	for _, tc := range bad {
		if _, err := svc.Apply(context.Background(), "eng-1", tc); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("Apply(%+v): want ErrValidation for proof_class/score mismatch, got %v", tc, err)
		}
	}
	if len(fv.calls) != 0 {
		t.Fatalf("a contradictory result must not reach the gate: %+v", fv.calls)
	}
	// Consistent pairs are accepted and reach the gate.
	good := []Result{
		{JudgmentID: "j", Verifier: "human:v", Score: 85, ProofClass: ProofClassRuntimeConfirmed, Rationale: "x"}, // confirmed >= bar
		{JudgmentID: "j", Verifier: "human:v", Score: 30, ProofClass: ProofClassRuntimeRefuted, Rationale: "x"},   // refuted < bar
		{JudgmentID: "j", Verifier: "human:v", Score: 74, ProofClass: ProofClassNeedsMoreProof, Rationale: "x"},   // needs-more < bar
	}
	for _, tc := range good {
		if _, err := svc.Apply(context.Background(), "eng-1", tc); err != nil {
			t.Fatalf("Apply(%+v): a consistent pair must be accepted, got %v", tc, err)
		}
	}
	if len(fv.calls) != len(good) {
		t.Fatalf("consistent pairs must reach the gate, got %d calls want %d", len(fv.calls), len(good))
	}
}

func TestApplyPreservesDownstreamGateErrors(t *testing.T) {
	fv := &fakeJudgmentVerifier{err: shared.ErrValidation} // e.g. self-confirm or ungated judgment rejected by analysis.Verify
	svc, _ := NewService(fv)
	_, err := svc.Apply(context.Background(), "eng-1", Result{
		JudgmentID: "j-1", Verifier: "agent:s1", Score: 90, ProofClass: ProofClassRuntimeConfirmed, Rationale: "should be distinct", ExpectedVersion: 1,
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("downstream gate error should be preserved, got %v", err)
	}
	if len(fv.calls) != 1 {
		t.Fatalf("valid-shape result should reach downstream gate once, got %+v", fv.calls)
	}
}

func TestNewServiceValidates(t *testing.T) {
	if _, err := NewService(nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil verifier: want ErrValidation, got %v", err)
	}
}
