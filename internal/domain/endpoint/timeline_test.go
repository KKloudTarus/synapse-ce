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

func TestTimelineEqualTimestampsKeepInsertionOrder(t *testing.T) {
	tl := newStateTimeline()
	// Three entries at the SAME instant: the deterministic tiebreak is insertion order (Seq).
	tl.append(entry("first", base))
	tl.append(entry("second", base))
	tl.append(entry("third", base))
	got := tl.Entries()
	want := []string{"first", "second", "third"}
	for i, w := range want {
		if string(got[i].EventID) != w {
			t.Fatalf("equal-timestamp tiebreak broke determinism at %d: got %s want %s", i, got[i].EventID, w)
		}
	}
	// Seq must be assigned in insertion order.
	if got[0].Seq != 0 || got[1].Seq != 1 || got[2].Seq != 2 {
		t.Fatalf("seq assignment wrong: %d %d %d", got[0].Seq, got[1].Seq, got[2].Seq)
	}
}
