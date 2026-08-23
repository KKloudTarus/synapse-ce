package spool

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func quotaConfig(t *testing.T) Config {
	cfg := testConfig(t)
	cfg.MaxBytes = 6 << 10
	cfg.MaxGapBytes = 4 << 10
	cfg.SegmentBytes = 1200
	cfg.MaxRecordBytes = 600
	cfg.Sync[fleetagent.PriorityP3] = SyncAlways
	return cfg
}

func TestQuotaEvictsP3BeforeNeverShedLanes(t *testing.T) {
	cfg := quotaConfig(t)
	s := mustOpen(t, cfg)
	p3a := mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "background-a", 500))
	p3b := mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "background-b", 500))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP2, "critical-a", 500))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP2, "critical-b", 500))

	records := mustPeek(t, s)
	ids := map[string]bool{}
	for _, record := range records {
		ids[record.EventID.String()] = true
	}
	if !ids["critical-a"] || !ids["critical-b"] {
		t.Fatalf("never-shed records evicted: %v", ids)
	}
	if ids["background-a"] && ids["background-b"] {
		t.Fatalf("quota did not evict P3: %v", ids)
	}
	gaps, _ := s.Gaps(context.Background())
	if !ids["background-a"] {
		assertGapCovers(t, gaps, ports.SpoolGapQuotaEviction, p3a.Epoch, p3a.Sequence)
	}
	if !ids["background-b"] {
		assertGapCovers(t, gaps, ports.SpoolGapQuotaEviction, p3b.Epoch, p3b.Sequence)
	}
	stats, _ := s.Stats(context.Background())
	if stats.TotalBytes > cfg.MaxBytes || stats.EvictedRecords == 0 {
		t.Fatalf("quota stats = %#v", stats)
	}
}

func TestNeverShedSaturationBackpressuresWithoutClaimingLoss(t *testing.T) {
	cfg := quotaConfig(t)
	s := mustOpen(t, cfg)
	for n := 0; ; n++ {
		_, err := s.Enqueue(context.Background(), testItem(fleetagent.PriorityP2, fmt.Sprintf("critical-%d", n), 220))
		if err == nil {
			continue
		}
		if !errors.Is(err, ErrSaturated) {
			t.Fatalf("enqueue error = %v", err)
		}
		var detail *SaturatedError
		if !errors.As(err, &detail) || detail.MaxBytes != cfg.MaxBytes || detail.RequiredBytes == 0 {
			t.Fatalf("saturation detail = %#v", detail)
		}
		break
	}
	gaps, err := s.Gaps(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, gap := range gaps {
		if gap.Priority == fleetagent.PriorityP2 && gap.Reason == ports.SpoolGapQuotaBackpressure && !gap.KnownSequence {
			t.Fatalf("backpressured item was falsely reported lost: %#v", gap)
		}
	}
}

func TestRepeatedBackpressureDoesNotCreateLossGaps(t *testing.T) {
	cfg := quotaConfig(t)
	s := mustOpen(t, cfg)
	for n := 0; ; n++ {
		_, err := s.Enqueue(context.Background(), testItem(fleetagent.PriorityP2, fmt.Sprintf("fill-%d", n), 220))
		if errors.Is(err, ErrSaturated) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	item := testItem(fleetagent.PriorityP2, "same-retry", 220)
	before := len(mustGaps(t, s))
	for attempt := 0; attempt < 5; attempt++ {
		if _, err := s.Enqueue(context.Background(), item); !errors.Is(err, ErrSaturated) {
			t.Fatalf("attempt %d error = %v", attempt, err)
		}
	}
	after := len(mustGaps(t, s))
	if after != before {
		t.Fatalf("retryable backpressure added %d false loss gaps", after-before)
	}
}

func TestFrameLargerThanPermanentCapacityIsNotRetryable(t *testing.T) {
	s := mustOpen(t, quotaConfig(t))
	s.mu.Lock()
	err := s.ensureCapacityLocked(s.walMaxBytesLocked()+1, fleetagent.PriorityP2)
	s.mu.Unlock()
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversized frame error = %v, want validation error", err)
	}
	if errors.Is(err, ErrSaturated) {
		t.Fatalf("oversized frame was classified as retryable saturation: %v", err)
	}
}

func TestDistinctP3SaturationCoalescesWithinGapBudget(t *testing.T) {
	cfg := quotaConfig(t)
	s := mustOpen(t, cfg)
	for n := 0; ; n++ {
		_, err := s.Enqueue(context.Background(), testItem(fleetagent.PriorityP2, fmt.Sprintf("fill-%d", n), 500))
		if errors.Is(err, ErrSaturated) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	before, err := s.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	const dropped = 1000
	for n := 0; n < dropped; n++ {
		_, err := s.Enqueue(context.Background(), testItem(fleetagent.PriorityP3, fmt.Sprintf("raw-drop-%d", n), 600))
		if !errors.Is(err, ErrSaturated) {
			t.Fatalf("drop %d error = %v", n, err)
		}
	}
	gaps := mustGaps(t, s)
	if len(gaps) != 1 || gaps[0].Priority != fleetagent.PriorityP3 || gaps[0].KnownSequence || gaps[0].Count != dropped {
		t.Fatalf("coalesced gaps = %#v", gaps)
	}
	stats, err := s.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalBytes > cfg.MaxBytes || stats.GapBytes > cfg.MaxGapBytes/2 {
		t.Fatalf("bounded stats = %#v, quota=%d gap_budget=%d", stats, cfg.MaxBytes, cfg.MaxGapBytes)
	}
	if delta := stats.FsyncCount - before.FsyncCount; delta > 5 {
		t.Fatalf("P3 saturation caused %d fsyncs for %d drops", delta, dropped)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	recoveredGaps := mustGaps(t, recovered)
	if len(recoveredGaps) != 1 || recoveredGaps[0].Count != dropped {
		t.Fatalf("recovered coalesced gaps = %#v", recoveredGaps)
	}
}

func TestP3SaturationNeverDeletesHigherPriority(t *testing.T) {
	cfg := quotaConfig(t)
	cfg.MaxBytes = 8 << 10
	s := mustOpen(t, cfg)
	mustEnqueue(t, s, testItem(fleetagent.PriorityP0, "health", 220))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP1, "detection", 220))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP2, "critical", 220))
	for n := 0; n < 10; n++ {
		_, _ = s.Enqueue(context.Background(), testItem(fleetagent.PriorityP3, fmt.Sprintf("raw-%d", n), 220))
	}
	ids := map[string]bool{}
	for _, record := range mustPeek(t, s) {
		ids[record.EventID.String()] = true
	}
	for _, id := range []string{"health", "detection", "critical"} {
		if !ids[id] {
			t.Fatalf("%s was shed while accepting P3: %v", id, ids)
		}
	}
}

func TestEvictionEvidenceSurvivesRestart(t *testing.T) {
	cfg := quotaConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	positions := make(map[string]fleetagent.StreamPosition)
	for n := 0; n < 8; n++ {
		id := fmt.Sprintf("raw-%d", n)
		position, enqueueErr := s.Enqueue(context.Background(), testItem(fleetagent.PriorityP3, id, 220))
		if enqueueErr == nil {
			positions[id] = position
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	present := make(map[uint64]bool)
	for _, record := range mustPeek(t, recovered) {
		present[record.Position.Sequence] = true
	}
	covered := make(map[uint64]bool)
	for _, gap := range mustGaps(t, recovered) {
		if gap.Priority != fleetagent.PriorityP3 || !gap.KnownSequence {
			continue
		}
		for sequence := gap.FromSequence; sequence <= gap.ToSequence; sequence++ {
			covered[sequence] = true
		}
	}
	for id, position := range positions {
		if !present[position.Sequence] && !covered[position.Sequence] {
			t.Errorf("accepted %s at sequence %d is neither recoverable nor a durable gap", id, position.Sequence)
		}
	}
}

// This deterministic property exercise crosses rotations, P3 evictions,
// never-shed backpressure, and restart. The invariant is the delivery contract:
// every successful enqueue is still readable or is covered by durable gap evidence.
func TestPropertyNoAcceptedRecordSilentlyDisappears(t *testing.T) {
	cfg := quotaConfig(t)
	cfg.MaxBytes = 7 << 10
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	type accepted struct {
		id       string
		position fleetagent.StreamPosition
	}
	var all []accepted
	for n := 0; n < 120; n++ {
		priority := fleetagent.PriorityP3
		if n%11 == 0 {
			priority = fleetagent.PriorityP2
		}
		id := fmt.Sprintf("event-%03d", n)
		position, enqueueErr := s.Enqueue(context.Background(), testItem(priority, id, 180+(n%5)*9))
		if enqueueErr == nil {
			all = append(all, accepted{id, position})
			continue
		}
		if !errors.Is(enqueueErr, ErrSaturated) {
			t.Fatalf("enqueue %d: %v", n, enqueueErr)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	present := make(map[string]bool)
	for _, record := range mustPeek(t, s) {
		present[fmt.Sprintf("%d:%d:%d", record.Position.Priority, record.Position.Epoch, record.Position.Sequence)] = true
	}
	gapped := make(map[string]bool)
	for _, gap := range mustGaps(t, s) {
		if !gap.KnownSequence {
			continue
		}
		for sequence := gap.FromSequence; sequence <= gap.ToSequence; sequence++ {
			gapped[fmt.Sprintf("%d:%d:%d", gap.Priority, gap.Epoch, sequence)] = true
		}
	}
	for _, event := range all {
		key := fmt.Sprintf("%d:%d:%d", event.position.Priority, event.position.Epoch, event.position.Sequence)
		if !present[key] && !gapped[key] {
			t.Errorf("accepted event %s (%s) silently disappeared", event.id, key)
		}
	}
}

func mustGaps(t *testing.T, s *Spool) []ports.SpoolGap {
	t.Helper()
	gaps, err := s.Gaps(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return gaps
}

func assertGapCovers(t *testing.T, gaps []ports.SpoolGap, reason ports.SpoolGapReason, epoch, sequence uint64) {
	t.Helper()
	for _, gap := range gaps {
		if gap.Reason == reason && gap.KnownSequence && gap.Epoch == epoch && gap.FromSequence <= sequence && gap.ToSequence >= sequence {
			return
		}
	}
	t.Fatalf("missing %s gap covering %d:%d in %#v", reason, epoch, sequence, gaps)
}
