package fleetagent

import (
	"errors"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func pos(pr DeliveryPriority, epoch, seq uint64) StreamPosition {
	return StreamPosition{Priority: pr, Epoch: epoch, Sequence: seq, Session: "sess-1", Boot: "boot-1"}
}

func TestDeliveryPriority(t *testing.T) {
	for _, p := range []DeliveryPriority{PriorityP0, PriorityP1, PriorityP2, PriorityP3} {
		if !p.Valid() {
			t.Errorf("%d must be valid", p)
		}
	}
	if (DeliveryPriority(4)).Valid() || (DeliveryPriority(-1)).Valid() {
		t.Error("out-of-range priorities must be invalid")
	}
	if PriorityP0.String() != "P0" || PriorityP3.String() != "P3" {
		t.Error("priority labels must be P0..P3")
	}
}

func TestStreamPositionValidate(t *testing.T) {
	if err := pos(PriorityP1, 1, 1).Validate(); err != nil {
		t.Fatalf("a well-formed position must validate: %v", err)
	}
	bad := map[string]StreamPosition{
		"bad priority": {Priority: 9, Epoch: 1, Sequence: 1, Session: "s", Boot: "b"},
		"zero epoch":   {Priority: PriorityP1, Epoch: 0, Sequence: 1, Session: "s", Boot: "b"},
		"zero seq":     {Priority: PriorityP1, Epoch: 1, Sequence: 0, Session: "s", Boot: "b"},
		"no session":   {Priority: PriorityP1, Epoch: 1, Sequence: 1, Boot: "b"},
		"no boot":      {Priority: PriorityP1, Epoch: 1, Sequence: 1, Session: "s"},
	}
	for name, p := range bad {
		t.Run(name, func(t *testing.T) {
			if err := p.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

func TestClassifyDelivery(t *testing.T) {
	cases := []struct {
		name           string
		last, incoming StreamPosition
		wantClass      DeliveryClass
		wantMissing    uint64
	}{
		{"first ever", StreamPosition{}, pos(PriorityP1, 1, 1), DeliveryNewIncarnation, 0},
		{"expected next", pos(PriorityP1, 1, 4), pos(PriorityP1, 1, 5), DeliveryOK, 0},
		{"forward gap", pos(PriorityP1, 1, 4), pos(PriorityP1, 1, 7), DeliveryForwardGap, 2},
		{"replay equal", pos(PriorityP1, 1, 5), pos(PriorityP1, 1, 5), DeliveryReplay, 0},
		{"replay lower", pos(PriorityP1, 1, 5), pos(PriorityP1, 1, 3), DeliveryReplay, 0},
		// The headline acceptance: a reboot resets Sequence to 1 but advances Epoch — NOT a replay.
		{"reboot reset to 1", pos(PriorityP1, 1, 9), pos(PriorityP1, 2, 1), DeliveryNewIncarnation, 0},
		{"reboot with loss", pos(PriorityP1, 1, 9), pos(PriorityP1, 2, 3), DeliveryNewIncarnation, 2},
		{"stale incarnation", pos(PriorityP1, 3, 2), pos(PriorityP1, 2, 8), DeliveryStaleIncarnation, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyDelivery(c.last, c.incoming)
			if got.Class != c.wantClass || got.Missing != c.wantMissing {
				t.Fatalf("got %+v, want class %s missing %d", got, c.wantClass, c.wantMissing)
			}
			// Progress/loss helpers stay consistent with the class.
			if (got.Missing > 0) != got.HasGap() {
				t.Errorf("HasGap must track Missing>0")
			}
			wantProgress := c.wantClass == DeliveryOK || c.wantClass == DeliveryForwardGap || c.wantClass == DeliveryNewIncarnation
			if got.IsProgress() != wantProgress {
				t.Errorf("IsProgress=%v, want %v for %s", got.IsProgress(), wantProgress, c.wantClass)
			}
		})
	}
}

func TestDeliveryKeyIdentity(t *testing.T) {
	base := pos(PriorityP1, 1, 5)
	k := DeliveryKey("agent:1", base, 2)
	// A resend of the SAME (agent, incarnation, stream, sequence, index) is the same idempotency key.
	if k != DeliveryKey("agent:1", base, 2) {
		t.Fatal("the same event must produce the same key")
	}
	// Every distinguishing field changes the key — especially the epoch, so the same (seq,index) in a new
	// incarnation is a DISTINCT event, never collapsed into the pre-restart one.
	newEpoch := base
	newEpoch.Epoch = 2
	for name, other := range map[string]string{
		"agent":    DeliveryKey("agent:2", base, 2),
		"epoch":    DeliveryKey("agent:1", newEpoch, 2),
		"index":    DeliveryKey("agent:1", base, 3),
		"priority": DeliveryKey("agent:1", pos(PriorityP2, 1, 5), 2),
	} {
		if other == k {
			t.Errorf("%s must change the delivery key", name)
		}
	}
}

func TestDeliveryKeyResistsBoundaryForgery(t *testing.T) {
	// Length-prefixing means a free-form agent id — even one crammed with delimiter-ish bytes — cannot
	// shift field boundaries to alias a different (agent, position, index) tuple.
	a := DeliveryKey(shared.ID("a\x1e1:2:3"), pos(PriorityP1, 1, 5), 2)
	b := DeliveryKey(shared.ID("a"), pos(PriorityP1, 1, 5), 2)
	if a == b {
		t.Fatal("a crafted agent id must not alias a different agent's key")
	}
	// Distinct priorities must never collapse to one key (they must not both render to a display fallback).
	if DeliveryKey("agent:1", pos(PriorityP2, 1, 5), 0) == DeliveryKey("agent:1", pos(PriorityP3, 1, 5), 0) {
		t.Fatal("distinct priorities must produce distinct keys")
	}
}

func TestAckLedgerContiguousAndDuplicates(t *testing.T) {
	l := NewAckLedger()
	if l.HighestContiguous() != 0 {
		t.Fatal("empty ledger ACKs 0")
	}
	for _, s := range []uint64{1, 2, 3} {
		if !l.Observe(s) {
			t.Fatalf("first sight of %d must record", s)
		}
	}
	if l.HighestContiguous() != 3 {
		t.Fatalf("contiguous 1..3 must ACK 3, got %d", l.HighestContiguous())
	}
	// Duplicates and 0 are idempotent no-ops.
	if l.Observe(2) || l.Observe(0) {
		t.Error("a duplicate or zero sequence must be a no-op")
	}
	if len(l.Gaps()) != 0 {
		t.Errorf("a fully contiguous run has no gaps, got %+v", l.Gaps())
	}
}

func TestAckLedgerOutOfOrderAndGaps(t *testing.T) {
	l := NewAckLedger()
	// Receive 1, then 4 and 6 out of order: ACK stays at 1, gaps are {2-3, 5}.
	l.Observe(1)
	l.Observe(4)
	l.Observe(6)
	if l.HighestContiguous() != 1 {
		t.Fatalf("a hole above 1 must keep the ACK at 1, got %d", l.HighestContiguous())
	}
	got := l.Gaps()
	want := []SeqRange{{From: 2, To: 3}, {From: 5, To: 5}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gaps = %+v, want %+v", got, want)
	}
	// A re-observe of an out-of-order sequence already held is a duplicate (false); a genuine fill below
	// the high-water is first-seen (true) — this is why the ingest path gates on Observe, not IsProgress.
	if l.Observe(4) {
		t.Error("re-observing a pending sequence must be a duplicate (false)")
	}
	if !l.Observe(3) {
		t.Error("a first-seen gap-fill below the high-water must return true, not be dropped as a replay")
	}
	// Fill 2: the ACK jumps to 4 (absorbing the now-contiguous 3,4), leaving only the {5} gap.
	l.Observe(2)
	if l.HighestContiguous() != 4 {
		t.Fatalf("filling 2,3 must advance the ACK to 4, got %d", l.HighestContiguous())
	}
	if got := l.Gaps(); !reflect.DeepEqual(got, []SeqRange{{From: 5, To: 5}}) {
		t.Fatalf("after filling 2,3 the only gap is {5}, got %+v", got)
	}
	// Fill 5: 6 is absorbed, everything contiguous, no gaps.
	l.Observe(5)
	if l.HighestContiguous() != 6 || len(l.Gaps()) != 0 {
		t.Fatalf("filling 5 must ACK 6 with no gaps, got ack=%d gaps=%+v", l.HighestContiguous(), l.Gaps())
	}
}
