package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestHaltAgentsCancelsTheTrackedRun pins the layer of the kill switch that reaches the agent loop.
//
// An agent run holds no work order and is not an exploitation chain, so before this registry an
// operator halt stopped every other offensive path and left the LLM loop deciding what to do next.
// Cancelling the run's context ends the in-flight provider call, and the loop stops before it can
// propose or execute another action.
func TestHaltAgentsCancelsTheTrackedRun(t *testing.T) {
	registry := NewRunRegistry()
	ctx := shared.WithTenant(context.Background(), "tenant-a")

	runCtx, release := registry.Track(ctx, "session-1")
	defer release()

	select {
	case <-runCtx.Done():
		t.Fatal("the run context was already cancelled before any halt")
	default:
	}

	halted, err := registry.HaltAgents(context.Background(), "tenant-a", "operator", "incident")
	if err != nil {
		t.Fatalf("halt: %v", err)
	}
	if halted != 1 {
		t.Fatalf("halted %d runs, want 1", halted)
	}
	select {
	case <-runCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the run context was not cancelled by the halt")
	}
}

// TestHaltAgentsIsTenantScoped keeps one tenant's halt from stopping another tenant's run.
func TestHaltAgentsIsTenantScoped(t *testing.T) {
	registry := NewRunRegistry()
	otherCtx, releaseOther := registry.Track(shared.WithTenant(context.Background(), "tenant-b"), "session-b")
	defer releaseOther()

	halted, err := registry.HaltAgents(context.Background(), "tenant-a", "operator", "incident")
	if err != nil {
		t.Fatalf("halt: %v", err)
	}
	if halted != 0 {
		t.Fatalf("halting tenant-a reached %d of tenant-b's runs, want 0", halted)
	}
	select {
	case <-otherCtx.Done():
		t.Fatal("another tenant's run was cancelled")
	default:
	}
}

// TestReleaseUnregistersTheRun keeps a finished run from being counted by a later halt, which would
// report reaching runs that no longer exist.
func TestReleaseUnregistersTheRun(t *testing.T) {
	registry := NewRunRegistry()
	_, release := registry.Track(shared.WithTenant(context.Background(), "tenant-a"), "session-1")
	release()

	halted, err := registry.HaltAgents(context.Background(), "tenant-a", "operator", "incident")
	if err != nil {
		t.Fatalf("halt: %v", err)
	}
	if halted != 0 {
		t.Fatalf("a released run was still halted (%d); the registry leaked it", halted)
	}
}

// TestTrackWithoutARegistryIsInert keeps the optional wiring optional: an orchestrator with no registry
// must run normally rather than panic.
func TestTrackWithoutARegistryIsInert(t *testing.T) {
	var registry *RunRegistry
	ctx, release := registry.Track(context.Background(), "session-1")
	release()
	if ctx == nil {
		t.Fatal("Track returned a nil context")
	}
	if halted, err := registry.HaltAgents(context.Background(), "tenant-a", "operator", "incident"); err != nil || halted != 0 {
		t.Fatalf("HaltAgents on a nil registry = %d, %v", halted, err)
	}
}
