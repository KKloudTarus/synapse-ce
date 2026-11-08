package dastrun

import (
	"testing"
	"time"
)

func TestScanCompletionRequiresSealedResultAndNeverVerdict(t *testing.T) {
	r, err := NewScanRun("run", "tenant", "eng", "action", "actor", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	if err := r.Succeed("confirmed", 200, "proof", time.Unix(2, 0)); err == nil {
		t.Fatal("scan accepted verifier completion")
	}
	if err := r.CompleteScan("", false, time.Unix(2, 0)); err == nil {
		t.Fatal("scan accepted missing evidence")
	}
	if err := r.CompleteScan("result", true, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if r.Status != RunIncomplete || !r.Status.Terminal() || r.Verdict != "" {
		t.Fatalf("invalid incomplete result: %+v", r)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	r.Verdict = "confirmed"
	if err := r.Validate(); err == nil {
		t.Fatal("scan accepted fake verdict")
	}
}

func TestVerifierRejectsScanCompletion(t *testing.T) {
	r, err := NewRun("run", "tenant", "eng", "action", "actor", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	if err := r.CompleteScan("result", false, time.Unix(2, 0)); err == nil {
		t.Fatal("verifier accepted scan completion")
	}
}
