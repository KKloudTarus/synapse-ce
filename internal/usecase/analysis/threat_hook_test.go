package analysis

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
)

type fakeThreatRecorder struct {
	calls    []judgment.Judgment
	verifier string
	err      error
}

func (f *fakeThreatRecorder) RecordConfirmedThreat(_ context.Context, verifier string, j judgment.Judgment) error {
	f.verifier = verifier
	f.calls = append(f.calls, j)
	return f.err
}

func threatClaim() judgment.Claim { return judgment.ThreatClaim{Category: judgment.Spoofing} }

// TestVerifyConfirmedThreatEmitsFinding: ratifying a threat judgment fires the confirmed-threat recorder
// (the auto-emit hook) with the confirmed judgment.
func TestVerifyConfirmedThreatEmitsFinding(t *testing.T) {
	svc, _, _, _ := newSvc()
	rec := &fakeThreatRecorder{}
	svc.SetThreatRecorder(rec)
	j, _ := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapThreat, judgment.SubjectComponent, "api", threatClaim())
	if _, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 80, "real threat", j.Version); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(rec.calls) != 1 || rec.calls[0].Capability != judgment.CapThreat || rec.calls[0].SubjectID != "api" {
		t.Fatalf("a confirmed threat must emit exactly one finding for the subject: %+v", rec.calls)
	}
	if rec.verifier != "human:bob" {
		t.Errorf("the human verifier must be threaded to the recorder (audit attribution), got %q", rec.verifier)
	}
}

// TestVerifyConfirmedNonThreatDoesNotEmit: confirming a non-threat judgment must NOT touch the recorder.
func TestVerifyConfirmedNonThreatDoesNotEmit(t *testing.T) {
	svc, _, _, _ := newSvc()
	rec := &fakeThreatRecorder{}
	svc.SetThreatRecorder(rec)
	j, _ := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapReachability, judgment.SubjectFinding, "f1", reach())
	if _, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 80, "holds", j.Version); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("a non-threat confirm must NOT emit a threat finding: %+v", rec.calls)
	}
}

// TestVerifyThreatEmitFailureDoesNotRollback: the emit is BEST-EFFORT – a recorder failure leaves the
// judgment confirmed (the human's ratification stands) and the failure is audited, not silent.
func TestVerifyThreatEmitFailureDoesNotRollback(t *testing.T) {
	svc, _, _, audit := newSvc()
	svc.SetThreatRecorder(&fakeThreatRecorder{err: errors.New("repo down")})
	j, _ := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapThreat, judgment.SubjectComponent, "api", threatClaim())
	got, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 80, "real", j.Version)
	if err != nil {
		t.Fatalf("a failed threat-finding emit must NOT fail the already-confirmed verify: %v", err)
	}
	if got.State != judgment.StateConfirmed {
		t.Fatalf("the judgment must still be confirmed, got %s", got.State)
	}
	found := false
	for _, a := range audit.actions {
		if a == "threat_finding.emit_failed" {
			found = true
		}
	}
	if !found {
		t.Errorf("a failed emit must be audited (best-effort, not silent), got %v", audit.actions)
	}
}
