package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestFleetDesiredStoreRejectsDuplicatePolicyIDWithinTenant(t *testing.T) {
	ctx := context.Background()
	store := NewFleetDesiredStore()
	now := time.Date(2026, 8, 19, 4, 0, 0, 0, time.UTC)
	first := desiredStoreState("tenant", "asset-a", "policy-shared", []string{"process"}, 1, now)
	second := desiredStoreState("tenant", "asset-b", "policy-shared", []string{"network"}, 1, now)
	if err := store.Put(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, second); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate PolicyID error=%v, want ErrConflict", err)
	}
	if _, err := store.Get(ctx, "tenant", "asset-b"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("conflicting policy was stored: %v", err)
	}
	got, err := store.Get(ctx, "tenant", "asset-a")
	if err != nil {
		t.Fatal(err)
	}
	if got.PolicyID != "policy-shared" || got.Capabilities[0] != "process" {
		t.Fatalf("existing policy changed after conflict: %+v", got)
	}

	// Policy IDs are tenant-scoped: the same opaque identifier in another tenant does not collide.
	otherTenant := desiredStoreState("other", "asset-x", "policy-shared", []string{"file"}, 1, now)
	if err := store.Put(ctx, otherTenant); err != nil {
		t.Fatalf("cross-tenant PolicyID reuse unexpectedly conflicted: %v", err)
	}
}

func TestFleetDesiredStoreDeleteRecreateRejectsStaleLifecycleDelete(t *testing.T) {
	ctx := context.Background()
	store := NewFleetDesiredStore()
	now := time.Date(2026, 8, 19, 5, 0, 0, 0, time.UTC)
	old := desiredStoreState("tenant", "asset", "policy-old", []string{"process"}, 1, now)
	if err := store.Put(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, "tenant", "asset", "policy-old", 1); err != nil {
		t.Fatal(err)
	}
	fresh := desiredStoreState("tenant", "asset", "policy-new", []string{"network"}, 1, now.Add(time.Minute))
	if err := store.Put(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, "tenant", "asset", "policy-old", 1); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale lifecycle delete error=%v, want ErrConflict", err)
	}
	got, err := store.Get(ctx, "tenant", "asset")
	if err != nil {
		t.Fatal(err)
	}
	if got.PolicyID != "policy-new" || got.Version != 1 || got.Capabilities[0] != "network" {
		t.Fatalf("stale delete removed or changed recreated lifecycle: %+v", got)
	}
}

func TestFleetDesiredStoreConcurrentCASAllowsExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	store := NewFleetDesiredStore()
	now := time.Date(2026, 8, 19, 6, 0, 0, 0, time.UTC)

	createResults := make(chan error, 2)
	startCreate := make(chan struct{})
	for _, state := range []*fleetdesired.State{
		desiredStoreState("tenant", "asset", "policy-a", []string{"process"}, 1, now),
		desiredStoreState("tenant", "asset", "policy-b", []string{"network"}, 1, now),
	} {
		state := state
		go func() {
			<-startCreate
			createResults <- store.Put(ctx, state)
		}()
	}
	close(startCreate)
	assertOneCASWinner(t, createResults)

	current, err := store.Get(ctx, "tenant", "asset")
	if err != nil {
		t.Fatal(err)
	}
	if current.Version != 1 || current.PolicyID.IsZero() {
		t.Fatalf("concurrent create stored invalid winner: %+v", current)
	}

	updateResults := make(chan error, 2)
	startUpdate := make(chan struct{})
	for _, caps := range [][]string{{"file"}, {"privilege"}} {
		state := desiredStoreState("tenant", "asset", current.PolicyID.String(), caps, 2, now.Add(time.Minute))
		state.Audit.CreatedAt = now
		go func(state *fleetdesired.State) {
			<-startUpdate
			updateResults <- store.Put(ctx, state)
		}(state)
	}
	close(startUpdate)
	assertOneCASWinner(t, updateResults)

	current, err = store.Get(ctx, "tenant", "asset")
	if err != nil {
		t.Fatal(err)
	}
	if current.Version != 2 || current.PolicyID.IsZero() || len(current.Capabilities) != 1 {
		t.Fatalf("concurrent update stored invalid winner: %+v", current)
	}
}

func TestFleetDesiredStoreConcurrentUpdateAndClearAllowsExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	store := NewFleetDesiredStore()
	now := time.Date(2026, 8, 19, 7, 0, 0, 0, time.UTC)
	base := desiredStoreState("tenant", "asset", "policy-race", []string{"process"}, 1, now)
	if err := store.Put(ctx, base); err != nil {
		t.Fatal(err)
	}
	update := desiredStoreState("tenant", "asset", "policy-race", []string{"network"}, 2, now.Add(time.Minute))
	update.Audit.CreatedAt = now

	type result struct {
		op  string
		err error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	go func() {
		<-start
		results <- result{op: "update", err: store.Put(ctx, update)}
	}()
	go func() {
		<-start
		results <- result{op: "clear", err: store.Delete(ctx, "tenant", "asset", "policy-race", 1)}
	}()
	close(start)
	first, second := <-results, <-results
	outcomes := map[string]error{first.op: first.err, second.op: second.err}
	wins, conflicts := 0, 0
	for _, result := range []result{first, second} {
		switch {
		case result.err == nil:
			wins++
		case errors.Is(result.err, shared.ErrConflict):
			conflicts++
		default:
			t.Fatalf("%s returned unexpected error: %v", result.op, result.err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatalf("update/clear race wins=%d conflicts=%d, want one each: %+v", wins, conflicts, outcomes)
	}
	got, err := store.Get(ctx, "tenant", "asset")
	if outcomes["update"] == nil {
		if err != nil || got.Version != 2 || len(got.Capabilities) != 1 || got.Capabilities[0] != "network" {
			t.Fatalf("winning update not preserved: got=%+v err=%v outcomes=%+v", got, err, outcomes)
		}
		return
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("winning clear left policy behind: got=%+v err=%v outcomes=%+v", got, err, outcomes)
	}
}

func assertOneCASWinner(t *testing.T, results <-chan error) {
	t.Helper()
	successes := 0
	conflicts := 0
	for i := 0; i < 2; i++ {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, shared.ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected CAS result: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("CAS results successes=%d conflicts=%d, want exactly one of each", successes, conflicts)
	}
}
