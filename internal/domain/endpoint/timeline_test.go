package endpoint

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func entry(eventID string, occ time.Time) TimelineEntry {
	return TimelineEntry{
		OccurredAt: occ, TenantID: testTenant, AssetID: testAsset,
		EntityKind: EntityProcess, EntityID: shared.ID("pe_" + eventID),
		Kind: TimelineProcessExec, EventID: shared.ID(eventID), Summary: eventID,
	}
}

func TestTimelineOrdersByEventTimeNotInsertionOrder(t *testing.T) {
	tl := newStateTimeline()
	// Append out of event-time order.
	tl.append(entry("c", base.Add(3*time.Second)))
	tl.append(entry("a", base.Add(1*time.Second)))
	tl.append(entry("b", base.Add(2*time.Second)))
	got := tl.Entries()
	want := []string{"a", "b", "c"}
	if len(got) != 3 {
		t.Fatalf("want 3 entries, got %d", len(got))
	}
	for i, w := range want {
		if string(got[i].EventID) != w {
			t.Fatalf("position %d: got %s want %s", i, got[i].EventID, w)
		}
	}
}

func TestTimelineDedupesByEventID(t *testing.T) {
	tl := newStateTimeline()
	if _, ok := tl.append(entry("a", base)); !ok {
		t.Fatal("first append must succeed")
	}
	if _, ok := tl.append(entry("a", base.Add(time.Hour))); ok {
		t.Fatal("duplicate EventID must not append again")
	}
	if tl.Len() != 1 {
		t.Fatalf("timeline must hold one entry, got %d", tl.Len())
	}
	if !tl.has("a") || tl.has("z") {
		t.Fatal("has() must reflect recorded event ids")
	}
}

func TestTimelineEqualTimestampsTiebreakByEventIDNotInsertionOrder(t *testing.T) {
	tl := newStateTimeline()
	// Three entries at the SAME instant, appended out of EventID order. The tiebreak is EventID, NOT
	// insertion order — so the result is reorder-invariant even when timestamps collide.
	tl.append(entry("c", base))
	tl.append(entry("a", base))
	tl.append(entry("b", base))
	got := tl.Entries()
	want := []string{"a", "b", "c"}
	for i, w := range want {
		if string(got[i].EventID) != w {
			t.Fatalf("equal-timestamp tiebreak not by EventID at %d: got %s want %s", i, got[i].EventID, w)
		}
	}
}
