package analysis

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
)

type fakeDASTRecorder struct {
	calls    []judgment.Judgment
	verifier string
	err      error
}

func (f *fakeDASTRecorder) RecordConfirmedDAST(_ context.Context, verifier string, j judgment.Judgment) error {
	f.verifier = verifier
	f.calls = append(f.calls, j)
	return f.err
}

// VerifyRuntime confirming a CapSAST judgment fires the DAST recorder (runtime-proven), NOT the SAST one.
func TestVerifyRuntimeConfirmedSASTEmitsDASTNotSAST(t *testing.T) {
	svc, _, _, _ := newSvc()
	dast := &fakeDASTRecorder{}
	sast := &fakeSASTRecorder{}
	svc.SetDASTRecorder(dast)
	svc.SetSASTRecorder(sast)
	j, _ := svc.Propose(context.Background(), "system:taint-scan", "e1", judgment.CapSAST, judgment.SubjectDataFlow, "flow1", sastClaim())
	if _, err := svc.VerifyRuntime(context.Background(), "human:bob", "e1", j.ID, 85, "proof_class=runtime_confirmed; safe canary callback observed", j.Version); err != nil {
		t.Fatalf("verify runtime: %v", err)
	}
	if len(dast.calls) != 1 || dast.calls[0].Capability != judgment.CapSAST || dast.calls[0].SubjectID != "flow1" {
		t.Fatalf("a runtime-confirmed CapSAST must emit exactly one DAST finding: %+v", dast.calls)
	}
	if len(sast.calls) != 0 {
		t.Fatalf("a runtime confirmation must NOT also emit a SAST finding (no duplicate): %+v", sast.calls)
	}
	if dast.verifier != "human:bob" {
		t.Errorf("the verifier must be threaded to the DAST recorder (audit attribution), got %q", dast.verifier)
	}
}

// The STATIC path (Verify) confirming a CapSAST judgment fires the SAST recorder, NOT the DAST one — proving
// the two paths are cleanly separated and neither double-emits.
func TestVerifyStaticConfirmedSASTEmitsSASTNotDAST(t *testing.T) {
	svc, _, _, _ := newSvc()
	dast := &fakeDASTRecorder{}
	sast := &fakeSASTRecorder{}
	svc.SetDASTRecorder(dast)
	svc.SetSASTRecorder(sast)
	j, _ := svc.Propose(context.Background(), "system:taint-scan", "e1", judgment.CapSAST, judgment.SubjectDataFlow, "flow1", sastClaim())
	if _, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 85, "static source-to-sink verified", j.Version); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(sast.calls) != 1 {
		t.Fatalf("a static-confirmed CapSAST must emit exactly one SAST finding: %+v", sast.calls)
	}
	if len(dast.calls) != 0 {
		t.Fatalf("a static confirmation must NOT emit a DAST finding: %+v", dast.calls)
	}
}

// A runtime verdict BELOW the bar REFUTES the gated judgment — no DAST finding (only a confirmed one promotes).
func TestVerifyRuntimeRefutedDoesNotEmit(t *testing.T) {
	svc, _, _, _ := newSvc()
	dast := &fakeDASTRecorder{}
	svc.SetDASTRecorder(dast)
	j, _ := svc.Propose(context.Background(), "system:taint-scan", "e1", judgment.CapSAST, judgment.SubjectDataFlow, "flow1", sastClaim())
	if _, err := svc.VerifyRuntime(context.Background(), "human:bob", "e1", j.ID, 40, "proof_class=needs_more_proof; inconclusive", j.Version); err != nil {
		t.Fatalf("verify runtime: %v", err)
	}
	if len(dast.calls) != 0 {
		t.Fatalf("a refuted (sub-bar) runtime verification must NOT emit a DAST finding: %+v", dast.calls)
	}
}

// The DAST emit is BEST-EFFORT — a recorder failure leaves the judgment confirmed and audits the failure.
func TestVerifyRuntimeDASTEmitFailureDoesNotRollback(t *testing.T) {
	svc, _, _, audit := newSvc()
	svc.SetDASTRecorder(&fakeDASTRecorder{err: errors.New("repo down")})
	j, _ := svc.Propose(context.Background(), "system:taint-scan", "e1", judgment.CapSAST, judgment.SubjectDataFlow, "flow1", sastClaim())
	got, err := svc.VerifyRuntime(context.Background(), "human:bob", "e1", j.ID, 85, "proof_class=runtime_confirmed; observed", j.Version)
	if err != nil {
		t.Fatalf("a failed dast-finding emit must NOT fail the already-confirmed verify: %v", err)
	}
	if got.State != judgment.StateConfirmed {
		t.Fatalf("the judgment must still be confirmed, got %s", got.State)
	}
	found := false
	for _, a := range audit.actions {
		if a == "dast_finding.emit_failed" {
			found = true
		}
	}
	if !found {
		t.Errorf("a failed DAST emit must be audited (best-effort, not silent), got %v", audit.actions)
	}
}
