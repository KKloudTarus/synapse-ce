package spool

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestRecoverySkipsCorruptMiddleFrameAndKeepsFollowingFrame(t *testing.T) {
	cfg := testConfig(t)
	cfg.Sync[fleetagent.PriorityP3] = SyncAlways
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first := mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "first", 80))
	second := mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "corrupt", 80))
	third := mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "third", 80))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	path := onlySegment(t, cfg.Dir)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	firstLength := frameHeaderSize + int(binary.LittleEndian.Uint32(data[8:12]))
	secondLength := frameHeaderSize + int(binary.LittleEndian.Uint32(data[firstLength+8:firstLength+12]))
	data[firstLength+secondLength-1] ^= 0x80
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	recovered, err := Open(cfg)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	requireIDs(t, mustPeek(t, recovered), "first", "third")
	gaps, err := recovered.Gaps(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertKnownGap(t, gaps, ports.SpoolGapCorruptFrame, second.Epoch, second.Sequence, second.Sequence)
	stats, _ := recovered.Stats(context.Background())
	if stats.CorruptionEvents != 1 {
		t.Errorf("corruptions = %d", stats.CorruptionEvents)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}

	// Recovery rewrites the segment. A second restart must neither rediscover
	// the same corruption nor duplicate its durable gap record.
	again, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	requireIDs(t, mustPeek(t, again), "first", "third")
	againGaps, _ := again.Gaps(context.Background())
	if len(againGaps) != len(gaps) {
		t.Fatalf("repair was not stable: gaps %d -> %d", len(gaps), len(againGaps))
	}
	if first.Sequence != 1 || third.Sequence != 3 {
		t.Fatal("test coordinates unexpected")
	}
}

func TestRecoveryReportsTornFrameAndContinuesSequence(t *testing.T) {
	cfg := testConfig(t)
	cfg.Sync[fleetagent.PriorityP3] = SyncAlways
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first := mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "complete", 80))
	torn := mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "torn", 256))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	path := onlySegment(t, cfg.Dir)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data[:len(data)-17], 0o600); err != nil {
		t.Fatal(err)
	}

	recovered, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	requireIDs(t, mustPeek(t, recovered), "complete")
	gaps, _ := recovered.Gaps(context.Background())
	assertKnownGap(t, gaps, ports.SpoolGapTornWrite, torn.Epoch, torn.Sequence, torn.Sequence)
	next := mustEnqueue(t, recovered, testItem(fleetagent.PriorityP3, "after", 32))
	if next.Epoch != first.Epoch || next.Sequence != torn.Sequence+1 {
		t.Fatalf("sequence reused after torn accepted frame: %#v", next)
	}
}

func TestBatchTailLossBecomesExactUnsyncedGap(t *testing.T) {
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first := mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "durable-after-close", 64))
	second := mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "simulate-lost", 64))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	path := onlySegment(t, cfg.Dir)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	firstLength := frameHeaderSize + int(binary.LittleEndian.Uint32(data[8:12]))
	if err := os.WriteFile(path, data[:firstLength], 0o600); err != nil {
		t.Fatal(err)
	}

	recovered, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	requireIDs(t, mustPeek(t, recovered), "durable-after-close")
	gaps, _ := recovered.Gaps(context.Background())
	assertKnownGap(t, gaps, ports.SpoolGapUnsyncedTail, second.Epoch, second.Sequence, second.Sequence)
	next := mustEnqueue(t, recovered, testItem(fleetagent.PriorityP3, "next", 32))
	if next.Sequence != second.Sequence+1 || first.Sequence != 1 {
		t.Fatalf("lost accepted coordinate reused: next=%#v", next)
	}
}

func TestStatePrimaryCorruptionFallsBackToBackup(t *testing.T) {
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first := mustEnqueue(t, s, testItem(fleetagent.PriorityP2, "one", 32))
	second := mustEnqueue(t, s, testItem(fleetagent.PriorityP2, "two", 32))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.Dir, "state.json"), []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(cfg)
	if err != nil {
		t.Fatalf("backup recovery: %v", err)
	}
	defer recovered.Close()
	next := mustEnqueue(t, recovered, testItem(fleetagent.PriorityP2, "three", 32))
	if next.Epoch != first.Epoch || next.Sequence != second.Sequence+1 {
		t.Fatalf("backup state reused coordinate: %#v", next)
	}
}

func TestBothStateCopiesLostStartsNewIncarnationAndReportsRecovery(t *testing.T) {
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	old := mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "old", 32))
	// Force a backup generation to exist.
	mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "old-2", 32))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"state.json", "state.backup.json"} {
		if err := os.WriteFile(filepath.Join(cfg.Dir, name), []byte("corrupt"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	recovered, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	fresh := mustEnqueue(t, recovered, testItem(fleetagent.PriorityP3, "fresh", 32))
	if fresh.Epoch <= old.Epoch || fresh.Sequence != 1 {
		t.Fatalf("state loss did not start new incarnation: old=%#v new=%#v", old, fresh)
	}
	gaps, _ := recovered.Gaps(context.Background())
	count := 0
	for _, gap := range gaps {
		if gap.Reason == ports.SpoolGapStateRecovery && !gap.KnownSequence {
			count++
		}
	}
	if count != 4 {
		t.Fatalf("state recovery gaps = %d, want one per priority", count)
	}
}

func TestStateLossUsesGapJournalEpochWhenNoSegmentsRemain(t *testing.T) {
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.appendUnknownGapLocked(fleetagent.PriorityP3, 7, ports.SpoolGapStateRecovery); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.Dir, "state.json"), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(cfg.Dir, "state.backup.json"))
	recovered, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	position := mustEnqueue(t, recovered, testItem(fleetagent.PriorityP3, "fresh", 32))
	if position.Epoch != 8 || position.Sequence != 1 {
		t.Fatalf("position after state loss = %#v, want epoch 8 sequence 1", position)
	}
}

func TestGapJournalTornTailIsSafelyTruncated(t *testing.T) {
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.appendUnknownGapLocked(fleetagent.PriorityP0, 1, ports.SpoolGapStateRecovery); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.Dir, "gaps.log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte{1, 2, 3, 4, 5})
	_ = f.Close()
	recovered, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	gaps, _ := recovered.Gaps(context.Background())
	if len(gaps) != 1 {
		t.Fatalf("gaps = %d", len(gaps))
	}
}

func TestGapJournalChecksumCorruptionFailsClosed(t *testing.T) {
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.appendUnknownGapLocked(fleetagent.PriorityP0, 1, ports.SpoolGapStateRecovery); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.Dir, "gaps.log")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if recovered, err := Open(cfg); err == nil {
		_ = recovered.Close()
		t.Fatal("corrupt loss evidence was silently accepted")
	}
}

func onlySegment(t *testing.T, dir string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*.wal"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("segments = %v, want one", matches)
	}
	return matches[0]
}

func assertKnownGap(t *testing.T, gaps []ports.SpoolGap, reason ports.SpoolGapReason, epoch, from, to uint64) {
	t.Helper()
	for _, gap := range gaps {
		if gap.Reason == reason && gap.KnownSequence && gap.Epoch == epoch && gap.FromSequence == from && gap.ToSequence == to {
			return
		}
	}
	t.Fatalf("missing %s gap %d:%d..%d in %#v", reason, epoch, from, to, gaps)
}
