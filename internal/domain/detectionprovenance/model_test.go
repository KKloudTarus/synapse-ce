package detectionprovenance

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func testReceivedTransition() Transition {
	return Transition{
		TenantID:     "tenant-1",
		EngagementID: "engagement-1",
		DetectionID:  "detection-1",
		Sequence:     1,
		Kind:         Received,
		Status:       StatusPending,
		AgentID:      "agent-1",
		AssetID:      "asset-1",
		TelemetryRefs: []fleetagent.TelemetryReference{
			{StreamID: "stream-2", Epoch: 2, Sequence: 3, EventID: "event-2", Digest: "digest-2"},
			{StreamID: "stream-1", Epoch: 1, Sequence: 2, EventID: "event-1", Digest: "digest-1"},
		},
		OccurredAt: time.Date(2026, 8, 27, 12, 0, 0, 123_456_789, time.UTC),
	}
}

func TestTransitionHashIsCanonical(t *testing.T) {
	transition := testReceivedTransition()
	want := ComputeHash(transition)
	if len(want) != 64 {
		t.Fatalf("hash length = %d, want 64 hex characters", len(want))
	}

	reordered := transition
	reordered.TelemetryRefs = []fleetagent.TelemetryReference{
		transition.TelemetryRefs[1],
		transition.TelemetryRefs[0],
	}
	reordered.OccurredAt = transition.OccurredAt.In(time.FixedZone("offset", 7*60*60)).Add(210 * time.Nanosecond)
	if got := ComputeHash(reordered); got != want {
		t.Fatalf("canonical hash changed for equivalent reference order or sub-microsecond timestamp: got %s want %s", got, want)
	}

	changed := transition
	changed.OccurredAt = changed.OccurredAt.Add(time.Microsecond)
	if got := ComputeHash(changed); got == want {
		t.Fatal("hash did not commit to normalized microsecond timestamp")
	}
}

func TestVerifyChainDetectsTamperingAndBrokenLinks(t *testing.T) {
	first := SealTransition(testReceivedTransition(), "")
	second := SealTransition(Transition{
		TenantID: first.TenantID, EngagementID: first.EngagementID, DetectionID: first.DetectionID,
		Sequence: 2, Kind: TelemetryDurable, Status: StatusPending,
		Reason: "telemetry durable", OccurredAt: first.OccurredAt.Add(time.Second),
	}, first.Hash)
	third := SealTransition(Transition{
		TenantID: first.TenantID, EngagementID: first.EngagementID, DetectionID: first.DetectionID,
		Sequence: 3, Kind: CommitmentPending, Status: StatusPending,
		OccurredAt: first.OccurredAt.Add(2 * time.Second),
	}, second.Hash)
	chain := []Transition{first, second, third}
	if err := VerifyChain(chain); err != nil {
		t.Fatalf("VerifyChain() valid chain error = %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func([]Transition)
	}{
		{name: "immutable content", mutate: func(candidate []Transition) { candidate[1].Reason = "tampered" }},
		{name: "missing link", mutate: func(candidate []Transition) { candidate[2].PreviousHash = first.Hash }},
		{name: "sequence discontinuity", mutate: func(candidate []Transition) { candidate[1].Sequence = 4 }},
		{name: "missing hash", mutate: func(candidate []Transition) { candidate[1].Hash = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := append([]Transition(nil), chain...)
			tc.mutate(candidate)
			if err := VerifyChain(candidate); !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("VerifyChain() error = %v, want conflict", err)
			}
		})
	}
}

func TestEquivalentTransitionIgnoresDerivedChainMetadata(t *testing.T) {
	plain := testReceivedTransition()
	sealed := SealTransition(plain, "")
	if !EquivalentTransition(plain, sealed) {
		t.Fatal("semantic retry differs only because persistence derived chain metadata")
	}

	changed := plain
	changed.AssetID = "other-asset"
	if EquivalentTransition(sealed, changed) {
		t.Fatal("semantic transition equivalence ignored immutable attribution change")
	}
}
