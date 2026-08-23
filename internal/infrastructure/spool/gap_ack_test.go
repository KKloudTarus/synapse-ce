package spool

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestAckGapDeletesOnlyExactDurableSnapshot(t *testing.T) {
	cfg := testConfig(t)
	now := testNow
	cfg.Now = func() time.Time { return now }
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	if err := s.appendUnknownGapLocked(fleetagent.PriorityP3, s.state.CurrentEpoch, ports.SpoolGapQuotaEviction); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()

	first, err := s.Gaps(context.Background())
	if err != nil || len(first) != 1 {
		t.Fatalf("first gap snapshot = %+v err=%v", first, err)
	}
	if first[0].Count != 1 || first[0].FromAt.IsZero() || first[0].ToAt.IsZero() {
		t.Fatalf("new gap must carry a concrete time span: %+v", first[0])
	}

	// Simulate a second local loss arriving while the first report is in flight.
	now = now.Add(2 * time.Minute)
	s.mu.Lock()
	if err := s.recordP3LossLocked(ports.SpoolGapQuotaEviction); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()

	deleted, err := s.AckGap(context.Background(), first[0])
	if err != nil {
		t.Fatalf("stale gap ACK: %v", err)
	}
	if deleted {
		t.Fatal("stale snapshot ACK must not delete a gap that coalesced more loss")
	}
	latest, err := s.Gaps(context.Background())
	if err != nil || len(latest) != 1 {
		t.Fatalf("latest gap = %+v err=%v", latest, err)
	}
	if latest[0].ID != first[0].ID || latest[0].Count != 2 {
		t.Fatalf("coalesced gap identity/count = %+v; want same ID and count=2", latest[0])
	}
	if !latest[0].FromAt.Equal(first[0].FromAt) || !latest[0].ToAt.Equal(now) {
		t.Fatalf("coalesced gap span = %s..%s; want %s..%s", latest[0].FromAt, latest[0].ToAt, first[0].FromAt, now)
	}

	deleted, err = s.AckGap(context.Background(), latest[0])
	if err != nil || !deleted {
		t.Fatalf("exact gap ACK deleted=%t err=%v", deleted, err)
	}
	if gaps, err := s.Gaps(context.Background()); err != nil || len(gaps) != 0 {
		t.Fatalf("acknowledged gap still present: %+v err=%v", gaps, err)
	}
	// Idempotent duplicate server ACK is harmless.
	if deleted, err := s.AckGap(context.Background(), latest[0]); err != nil || !deleted {
		t.Fatalf("duplicate gap ACK deleted=%t err=%v", deleted, err)
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	if gaps, err := reopened.Gaps(context.Background()); err != nil || len(gaps) != 0 {
		t.Fatalf("gap journal resurrected acknowledged gap after restart: %+v err=%v", gaps, err)
	}
}

func TestLegacySpoolGapTimeBoundsFallbackToOccurredAt(t *testing.T) {
	gap := ports.SpoolGap{
		ID: "legacy-gap", Priority: fleetagent.PriorityP3, Epoch: 1,
		KnownSequence: false, Reason: ports.SpoolGapIOFailure, Count: 1,
		OccurredAt: testNow,
	}
	if err := gap.Validate(); err != nil {
		t.Fatalf("legacy journal gap must remain valid: %v", err)
	}
	fromAt, toAt := gap.TimeBounds()
	if !fromAt.Equal(testNow) || !toAt.Equal(testNow) {
		t.Fatalf("legacy bounds = %s..%s; want occurred-at %s", fromAt, toAt, testNow)
	}
}
