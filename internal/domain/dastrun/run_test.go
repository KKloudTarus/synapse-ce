package dastrun

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var now = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func TestNewRunValidation(t *testing.T) {
	if _, err := NewRun("", "t", "e", "a", "actor", now); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty id accepted")
	}
	if _, err := NewRun("id", "t", "e", "a", "", now); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty actor accepted")
	}
	r, err := NewRun("id", "t", "e", "a", "actor", now)
	if err != nil || r.Status != RunQueued {
		t.Fatalf("valid run: %v status=%s", err, r.Status)
	}
}

func TestRunLifecycle(t *testing.T) {
	r, _ := NewRun("id", "t", "e", "a", "actor", now)
	if err := r.Validate(); err != nil {
		t.Fatalf("queued run invalid: %v", err)
	}
	// Cannot succeed before starting.
	if err := r.Succeed("confirmed", 200, "ev", now); !errors.Is(err, shared.ErrConflict) {
		t.Errorf("succeed-before-start allowed")
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); !errors.Is(err, shared.ErrConflict) {
		t.Errorf("double start allowed")
	}
	if err := r.Succeed("confirmed", 200, "ev", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if r.Status != RunSucceeded || r.FinishedAt == nil || r.Verdict != "confirmed" {
		t.Fatalf("succeeded state wrong: %+v", r)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("succeeded run invalid: %v", err)
	}
}

func TestRunFailIsTerminal(t *testing.T) {
	r, _ := NewRun("id", "t", "e", "a", "actor", now)
	_ = r.Start()
	r.Fail("forbidden", now.Add(time.Second))
	if r.Status != RunFailed || r.ErrorCode != "forbidden" || r.FinishedAt == nil {
		t.Fatalf("failed state wrong: %+v", r)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("failed run invalid: %v", err)
	}
}
