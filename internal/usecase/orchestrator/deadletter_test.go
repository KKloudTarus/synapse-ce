package orchestrator_test

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator"
)

// TestFailStrandedJobFinalizesRunningSession proves the worker's DeadLetterer hook breaks the
// re-drive livelock: finalizing a dead-lettered Drive job drives its RUNNING session to terminal
// `failed`, so the reconciler (which only re-enqueues stranded running sessions) stops re-driving
// it and the job/session states no longer permanently disagree.
func TestFailStrandedJobFinalizesRunningSession(t *testing.T) {
	orch, _, sessions := newOrch(t, loadLLM{}, &fakeExecutor{}, agent.ModeAuto, orchestrator.Config{MaxSteps: 4})
	ctx := context.Background()
	if err := sessions.SaveSession(ctx, agent.Session{ID: "s1", EngagementID: "eng-1", InitiatedBy: "alice", Goal: "g", Status: agent.StatusRunning}); err != nil {
		t.Fatal(err)
	}
	payload, err := orchestrator.DriveJob("s1")
	if err != nil {
		t.Fatal(err)
	}
	if err := orch.FailStrandedJob(ctx, payload, errors.New("boom")); err != nil {
		t.Fatalf("FailStrandedJob: %v", err)
	}
	got, err := sessions.GetSession(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != agent.StatusFailed {
		t.Fatalf("a stranded running session must be finalized failed, got %q", got.Status)
	}
}

// TestFailStrandedJobNoOpsOnTerminal proves a dead-letter finalize never clobbers a session that
// already reached a terminal state (e.g. a concurrent delivery succeeded before the dead-letter).
func TestFailStrandedJobNoOpsOnTerminal(t *testing.T) {
	orch, _, sessions := newOrch(t, loadLLM{}, &fakeExecutor{}, agent.ModeAuto, orchestrator.Config{MaxSteps: 4})
	ctx := context.Background()
	if err := sessions.SaveSession(ctx, agent.Session{ID: "s1", EngagementID: "eng-1", InitiatedBy: "alice", Status: agent.StatusSucceeded}); err != nil {
		t.Fatal(err)
	}
	payload, _ := orchestrator.DriveJob("s1")
	if err := orch.FailStrandedJob(ctx, payload, errors.New("boom")); err != nil {
		t.Fatalf("FailStrandedJob: %v", err)
	}
	got, _ := sessions.GetSession(ctx, "s1")
	if got.Status != agent.StatusSucceeded {
		t.Fatalf("a terminal session must not be clobbered, got %q", got.Status)
	}
}

// TestFailStrandedJobIdempotent proves repeated finalize calls are safe – at-least-once delivery
// plus the reconciler can re-present the same dead-letter – leaving the session failed, no error.
func TestFailStrandedJobIdempotent(t *testing.T) {
	orch, _, sessions := newOrch(t, loadLLM{}, &fakeExecutor{}, agent.ModeAuto, orchestrator.Config{MaxSteps: 4})
	ctx := context.Background()
	if err := sessions.SaveSession(ctx, agent.Session{ID: "s1", EngagementID: "eng-1", InitiatedBy: "alice", Status: agent.StatusRunning}); err != nil {
		t.Fatal(err)
	}
	payload, _ := orchestrator.DriveJob("s1")
	for i := 0; i < 2; i++ {
		if err := orch.FailStrandedJob(ctx, payload, errors.New("boom")); err != nil {
			t.Fatalf("FailStrandedJob #%d: %v", i+1, err)
		}
	}
	got, _ := sessions.GetSession(ctx, "s1")
	if got.Status != agent.StatusFailed {
		t.Fatalf("want failed after idempotent finalize, got %q", got.Status)
	}
}
