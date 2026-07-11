package analysis

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
)

type fakeSASTRecorder struct {
	calls    []judgment.Judgment
	verifier string
	err      error
}

func (f *fakeSASTRecorder) RecordConfirmedSAST(_ context.Context, verifier string, j judgment.Judgment) error {
	f.verifier = verifier
	f.calls = append(f.calls, j)
	return f.err
}

func sastClaim() judgment.Claim {
	return judgment.SASTClaim{CWE: "CWE-89", Location: "app.dao", Rule: "taint-sqli"}
}

// Confirming a CapSAST judgment fires the confirmed-sast recorder (the auto-emit hook) with the judgment.
func TestVerifyConfirmedSASTEmitsFinding(t *testing.T) {
	svc, _, _, _ := newSvc()
	rec := &fakeSASTRecorder{}
	svc.SetSASTRecorder(rec)
	j, _ := svc.Propose(context.Background(), "system:taint-scan", "e1", judgment.CapSAST, judgment.SubjectDataFlow, "flow1", sastClaim())
	if _, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 80, "real injection", j.Version); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(rec.calls) != 1 || rec.calls[0].Capability != judgment.CapSAST || rec.calls[0].SubjectID != "flow1" {
		t.Fatalf("a confirmed CapSAST must emit exactly one finding for the subject: %+v", rec.calls)
	}
	if rec.verifier != "human:bob" {
		t.Errorf("the verifier must be threaded to the recorder (audit attribution), got %q", rec.verifier)
	}
}

// A non-sast confirm must NOT touch the sast recorder.
func TestVerifyConfirmedNonSASTDoesNotEmit(t *testing.T) {
	svc, _, _, _ := newSvc()
	rec := &fakeSASTRecorder{}
	svc.SetSASTRecorder(rec)
	j, _ := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapReachability, judgment.SubjectFinding, "f1", reach())
	if _, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 80, "holds", j.Version); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("a non-sast confirm must NOT emit a sast finding: %+v", rec.calls)
	}
}

// A verdict BELOW the bar REFUTES the gated judgment – no finding emitted (only a confirmed one promotes).
func TestVerifyRefutedSASTDoesNotEmit(t *testing.T) {
	svc, _, _, _ := newSvc()
	rec := &fakeSASTRecorder{}
	svc.SetSASTRecorder(rec)
	j, _ := svc.Propose(context.Background(), "system:taint-scan", "e1", judgment.CapSAST, judgment.SubjectDataFlow, "flow1", sastClaim())
	if _, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 40, "false positive", j.Version); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("a refuted (sub-bar) CapSAST must NOT emit a finding: %+v", rec.calls)
	}
}

// The emit is BEST-EFFORT – a recorder failure leaves the judgment confirmed and the failure is audited.
func TestVerifySASTEmitFailureDoesNotRollback(t *testing.T) {
	svc, _, _, audit := newSvc()
	svc.SetSASTRecorder(&fakeSASTRecorder{err: errors.New("repo down")})
	j, _ := svc.Propose(context.Background(), "system:taint-scan", "e1", judgment.CapSAST, judgment.SubjectDataFlow, "flow1", sastClaim())
	got, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 80, "real", j.Version)
	if err != nil {
		t.Fatalf("a failed sast-finding emit must NOT fail the already-confirmed verify: %v", err)
	}
	if got.State != judgment.StateConfirmed {
		t.Fatalf("the judgment must still be confirmed, got %s", got.State)
	}
	found := false
	for _, a := range audit.actions {
		if a == "sast_finding.emit_failed" {
			found = true
		}
	}
	if !found {
		t.Errorf("a failed emit must be audited (best-effort, not silent), got %v", audit.actions)
	}
}
