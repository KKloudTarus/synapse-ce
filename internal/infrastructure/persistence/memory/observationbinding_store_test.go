package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/observationbinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func bindingAt(id shared.ID, findingID shared.ID, version int, at time.Time) observationbinding.Binding {
	return observationbinding.Binding{
		ID: id, TenantID: "t1", EngagementID: "eng1",
		Scope: "semgrep", ExternalIdentity: "fingerprint:abc",
		FindingID: findingID, ObservationID: "o1", Version: version,
		DecidedBy: "human:alice", Reason: "same issue", DecidedAt: at,
	}
}

func TestAdoptIsIdempotentForTheSameFinding(t *testing.T) {
	t.Parallel()
	store := NewObservationBindingStore()
	at := time.Unix(1700000000, 0).UTC()

	first, err := store.Adopt(context.Background(), "t1", bindingAt("b1", "f1", 1, at))
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	// A retried request must not mint a second version of an unchanged decision.
	second, err := store.Adopt(context.Background(), "t1", bindingAt("b2", "f1", 1, at.Add(time.Minute)))
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("retry created binding %s, want the existing %s", second.ID, first.ID)
	}
	all, err := store.ListByEngagement(context.Background(), "t1", "eng1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("%d versions after a retry, want 1", len(all))
	}
}

func TestAdoptingADifferentFindingIsAConflictAndNeverAReplacement(t *testing.T) {
	t.Parallel()
	store := NewObservationBindingStore()
	at := time.Unix(1700000000, 0).UTC()
	if _, err := store.Adopt(context.Background(), "t1", bindingAt("b1", "f1", 1, at)); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	// Changing which workflow owns an observation is a decision, not a side effect of the second request.
	_, err := store.Adopt(context.Background(), "t1", bindingAt("b2", "f2", 1, at.Add(time.Minute)))
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("adopting a second finding = %v, want a conflict", err)
	}
	current, err := store.Current(context.Background(), "t1", "eng1", observationbinding.Identity{Scope: "semgrep", ExternalIdentity: "fingerprint:abc"})
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	if current.FindingID != "f1" {
		t.Fatalf("the refused adoption replaced the binding in force: %+v", current)
	}
}

func TestConcurrentAdoptionCannotCreateTwoBindings(t *testing.T) {
	t.Parallel()
	store := NewObservationBindingStore()
	at := time.Unix(1700000000, 0).UTC()

	const racers = 16
	var wg sync.WaitGroup
	results := make([]error, racers)
	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func(index int) {
			defer wg.Done()
			// Each racer adopts a DIFFERENT finding, so at most one can legitimately win.
			_, results[index] = store.Adopt(context.Background(), "t1",
				bindingAt(shared.ID("b"+string(rune('a'+index))), shared.ID("f"+string(rune('a'+index))), 1, at))
		}(i)
	}
	wg.Wait()

	won := 0
	for index, err := range results {
		switch {
		case err == nil:
			won++
		case errors.Is(err, shared.ErrConflict):
		default:
			t.Fatalf("racer %d failed with an unexpected error: %v", index, err)
		}
	}
	if won != 1 {
		t.Fatalf("%d racers believed they owned the binding, want exactly 1", won)
	}
	all, err := store.ListByEngagement(context.Background(), "t1", "eng1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("%d bindings after the race, want 1", len(all))
	}
}

func TestSupersedeKeepsTheReplacedVersion(t *testing.T) {
	t.Parallel()
	store := NewObservationBindingStore()
	at := time.Unix(1700000000, 0).UTC()
	identity := observationbinding.Identity{Scope: "semgrep", ExternalIdentity: "fingerprint:abc"}

	if _, err := store.Adopt(context.Background(), "t1", bindingAt("b1", "f1", 1, at)); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	later := at.Add(time.Hour)
	if _, err := store.Supersede(context.Background(), "t1", 1, bindingAt("b2", "f2", 2, later)); err != nil {
		t.Fatalf("supersede: %v", err)
	}

	current, err := store.Current(context.Background(), "t1", "eng1", identity)
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	if current.ID != "b2" || current.Version != 2 || current.FindingID != "f2" {
		t.Fatalf("binding in force = %+v, want version 2 on f2", current)
	}
	all, err := store.ListByEngagement(context.Background(), "t1", "eng1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// The replaced version is the record of what the workflow used to believe. Dropping it would make a
	// wrong decision unauditable.
	if len(all) != 2 {
		t.Fatalf("%d versions after superseding, want both kept", len(all))
	}
	for _, binding := range all {
		if binding.ID == "b1" && binding.Current() {
			t.Fatal("the replaced version is still reported as in force")
		}
	}
}

func TestSupersedingAStaleVersionIsRefused(t *testing.T) {
	t.Parallel()
	store := NewObservationBindingStore()
	at := time.Unix(1700000000, 0).UTC()
	if _, err := store.Adopt(context.Background(), "t1", bindingAt("b1", "f1", 1, at)); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if _, err := store.Supersede(context.Background(), "t1", 1, bindingAt("b2", "f2", 2, at.Add(time.Hour))); err != nil {
		t.Fatalf("supersede: %v", err)
	}
	// A second person decided against the version they could see. Applying it would silently discard the
	// decision made in between.
	_, err := store.Supersede(context.Background(), "t1", 1, bindingAt("b3", "f3", 2, at.Add(2*time.Hour)))
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("superseding a stale version = %v, want a conflict", err)
	}
}

func TestSupersedingNothingIsNotFound(t *testing.T) {
	t.Parallel()
	store := NewObservationBindingStore()
	_, err := store.Supersede(context.Background(), "t1", 1, bindingAt("b1", "f1", 2, time.Unix(1700000000, 0).UTC()))
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("superseding with nothing in force = %v, want not found", err)
	}
}

func TestAStoreRefusesABindingStampedWithAnotherTenant(t *testing.T) {
	t.Parallel()
	store := NewObservationBindingStore()
	binding := bindingAt("b1", "f1", 1, time.Unix(1700000000, 0).UTC())
	binding.TenantID = "t2"
	if _, err := store.Adopt(context.Background(), "t1", binding); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a binding stamped t2 was written into t1: %v", err)
	}
}

func TestCurrentIsNotFoundBeforeAnyDecision(t *testing.T) {
	t.Parallel()
	store := NewObservationBindingStore()
	_, err := store.Current(context.Background(), "t1", "eng1", observationbinding.Identity{Scope: "semgrep", ExternalIdentity: "fingerprint:abc"})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("an unadopted observation = %v, want not found", err)
	}
}

func TestCurrentByEngagementOmitsRetiredVersions(t *testing.T) {
	t.Parallel()
	store := NewObservationBindingStore()
	at := time.Unix(1700000000, 0).UTC()
	if _, err := store.Adopt(context.Background(), "t1", bindingAt("b1", "f1", 1, at)); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if _, err := store.Supersede(context.Background(), "t1", 1, bindingAt("b2", "f2", 2, at.Add(time.Hour))); err != nil {
		t.Fatalf("supersede: %v", err)
	}

	// The page-load path folds this straight into a map and never looks at history, so a retired version
	// reaching it would overwrite the one in force depending on iteration order.
	current, err := store.CurrentByEngagement(context.Background(), "t1", "eng1")
	if err != nil {
		t.Fatalf("current by engagement: %v", err)
	}
	if len(current) != 1 || current[0].ID != "b2" {
		t.Fatalf("current = %+v, want only the version in force", current)
	}
	all, err := store.ListByEngagement(context.Background(), "t1", "eng1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("the lineage read lost a version: %+v", all)
	}
}
