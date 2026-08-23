package spool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestSpoolPriorityDrainAndLaneOrdering(t *testing.T) {
	s := mustOpen(t, testConfig(t))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "p3-first", 32))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP2, "p2-first", 32))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP0, "p0", 32))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "p3-second", 32))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP1, "p1", 32))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP2, "p2-second", 32))

	records := mustPeek(t, s)
	requireIDs(t, records, "p0", "p1", "p2-first", "p2-second", "p3-first", "p3-second")
	for i := 1; i < len(records); i++ {
		if records[i-1].Position.Priority == records[i].Position.Priority && records[i-1].Position.Sequence >= records[i].Position.Sequence {
			t.Fatalf("lane order is not increasing: %#v then %#v", records[i-1].Position, records[i].Position)
		}
	}
}

func TestPeekCanIsolateDetectionPriority(t *testing.T) {
	s := mustOpen(t, testConfig(t))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP0, "coverage", 32))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP1, "detection-1", 32))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP1, "detection-2", 32))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "telemetry", 32))
	priority := fleetagent.PriorityP1
	records, err := s.Peek(context.Background(), ports.PeekSpoolRequest{MaxRecords: 8, MaxBytes: 1024, OnlyPriority: &priority})
	if err != nil {
		t.Fatal(err)
	}
	requireIDs(t, records, "detection-1", "detection-2")
	invalid := fleetagent.DeliveryPriority(99)
	if _, err := s.Peek(context.Background(), ports.PeekSpoolRequest{OnlyPriority: &invalid}); err == nil {
		t.Fatal("invalid isolated priority accepted")
	}
}

func TestPeekBoundsAndAlwaysMakesProgress(t *testing.T) {
	s := mustOpen(t, testConfig(t))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "large", 4096))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "small", 16))

	records, err := s.Peek(context.Background(), ports.PeekSpoolRequest{MaxRecords: 1, MaxBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].EventID != "large" {
		t.Fatalf("oversize head must make progress, got %v", recordIDs(records))
	}
	if _, err := s.Peek(context.Background(), ports.PeekSpoolRequest{MaxRecords: -1}); !errors.Is(err, context.Canceled) && err == nil {
		t.Fatal("negative limit accepted")
	}
}

func TestACKIsContiguousScopedAndIdempotent(t *testing.T) {
	s := mustOpen(t, testConfig(t))
	p1 := mustEnqueue(t, s, testItem(fleetagent.PriorityP2, "one", 32))
	p2 := mustEnqueue(t, s, testItem(fleetagent.PriorityP2, "two", 32))
	p3 := mustEnqueue(t, s, testItem(fleetagent.PriorityP2, "three", 32))

	result, err := s.Ack(context.Background(), ports.SpoolACK{Priority: fleetagent.PriorityP2, Epoch: p2.Epoch, Through: p2.Sequence})
	if err != nil {
		t.Fatal(err)
	}
	if result.RemovedRecords != 2 || result.HighestACKed != p2.Sequence {
		t.Fatalf("ACK result = %#v", result)
	}
	requireIDs(t, mustPeek(t, s), "three")

	again, err := s.Ack(context.Background(), ports.SpoolACK{Priority: fleetagent.PriorityP2, Epoch: p1.Epoch, Through: p1.Sequence})
	if err != nil || again.RemovedRecords != 0 || again.HighestACKed != p2.Sequence {
		t.Fatalf("idempotent/regressive ACK = %#v, %v", again, err)
	}
	if _, err := s.Ack(context.Background(), ports.SpoolACK{Priority: fleetagent.PriorityP2, Epoch: p3.Epoch, Through: p3.Sequence + 1}); !errors.Is(err, ErrACKAhead) {
		t.Fatalf("ahead ACK error = %v", err)
	}
	if _, err := s.Ack(context.Background(), ports.SpoolACK{Priority: fleetagent.PriorityP3, Epoch: p3.Epoch, Through: 1}); !errors.Is(err, ErrACKAhead) {
		t.Fatalf("cross-lane ACK error = %v", err)
	}
}

func TestResumeAfterRestartPreservesMembershipAndSequence(t *testing.T) {
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first := mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "one", 64))
	second := mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "two", 64))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP1, "detection", 64))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	requireIDs(t, mustPeek(t, reopened), "detection", "one", "two")
	third := mustEnqueue(t, reopened, testItem(fleetagent.PriorityP3, "three", 64))
	if first.Epoch != second.Epoch || third.Epoch != second.Epoch || third.Sequence != second.Sequence+1 {
		t.Fatalf("positions did not resume: first=%#v second=%#v third=%#v", first, second, third)
	}
}

func TestBootChangeAdvancesEpochAndResetsSequence(t *testing.T) {
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	old := mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "before-reboot", 32))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Boot = "boot-2"
	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	fresh := mustEnqueue(t, reopened, testItem(fleetagent.PriorityP3, "after-reboot", 32))
	if fresh.Epoch != old.Epoch+1 || fresh.Sequence != 1 || fresh.Boot != "boot-2" {
		t.Fatalf("reboot position = %#v, old = %#v", fresh, old)
	}
	requireIDs(t, mustPeek(t, reopened), "before-reboot", "after-reboot")
}

func TestSessionChangeAdvancesEpoch(t *testing.T) {
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	old := mustEnqueue(t, s, testItem(fleetagent.PriorityP2, "old-session", 32))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Session = "session-2"
	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	fresh := mustEnqueue(t, reopened, testItem(fleetagent.PriorityP2, "new-session", 32))
	if fresh.Epoch != old.Epoch+1 || fresh.Sequence != 1 || fresh.Session != "session-2" {
		t.Fatalf("new session position = %#v, old = %#v", fresh, old)
	}
}

func TestACKSurvivesRestartAndReclaimsSegment(t *testing.T) {
	cfg := testConfig(t)
	cfg.SegmentBytes = 1024
	cfg.MaxRecordBytes = 256
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first := mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "one", 128))
	second := mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "two", 128))
	before, _ := s.Stats(context.Background())
	if _, err := s.Ack(context.Background(), ports.SpoolACK{Priority: fleetagent.PriorityP3, Epoch: first.Epoch, Through: first.Sequence}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	requireIDs(t, mustPeek(t, reopened), "two")
	stats, _ := reopened.Stats(context.Background())
	if stats.TotalBytes >= before.TotalBytes {
		t.Errorf("ACKed segment was not compacted: before=%d after=%d", before.TotalBytes, stats.TotalBytes)
	}
	if stats.Priorities[fleetagent.PriorityP3].HighestACKed != first.Sequence || second.Sequence != first.Sequence+1 {
		t.Fatalf("ACK/sequence state not restored: %#v", stats.Priorities[fleetagent.PriorityP3])
	}
}

func TestStatsRetainsACKForPastEpochAfterBootChange(t *testing.T) {
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	delivered := mustEnqueue(t, s, testItem(fleetagent.PriorityP1, "delivered", 64))
	if _, err := s.Ack(context.Background(), ports.SpoolACK{
		Priority: fleetagent.PriorityP1, Epoch: delivered.Epoch, Through: delivered.Sequence,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	cfg.Boot = "boot-after-ack"
	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	stats, err := reopened.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Priorities[fleetagent.PriorityP1].CurrentEpoch <= delivered.Epoch {
		t.Fatalf("boot did not advance epoch: stats=%#v delivered=%#v", stats.Priorities[fleetagent.PriorityP1], delivered)
	}
	for _, ack := range stats.EpochACKs {
		if ack.Priority == fleetagent.PriorityP1 && ack.Epoch == delivered.Epoch && ack.HighestACKed == delivered.Sequence {
			return
		}
	}
	t.Fatalf("past-epoch ACK missing after reboot: %#v", stats.EpochACKs)
}

func TestDirectoryHasExclusiveProcessOwnership(t *testing.T) {
	cfg := testConfig(t)
	first, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(cfg)
	if second != nil {
		_ = second.Close()
		t.Fatal("second open unexpectedly succeeded")
	}
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("second open error = %v, want ErrLocked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := Open(cfg)
	if err != nil {
		t.Fatalf("lock not released by Close: %v", err)
	}
	_ = third.Close()
}

func TestConcurrentProducersAssignUniqueMonotonicCoordinates(t *testing.T) {
	cfg := testConfig(t)
	cfg.Sync[fleetagent.PriorityP3] = SyncAlways
	s := mustOpen(t, cfg)
	const producers = 6
	const perProducer = 20
	positions := make(chan fleetagent.StreamPosition, producers*perProducer)
	errs := make(chan error, producers)
	var wg sync.WaitGroup
	for producer := 0; producer < producers; producer++ {
		producer := producer
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < perProducer; n++ {
				id := fmt.Sprintf("producer-%d-%d", producer, n)
				position, err := s.Enqueue(context.Background(), testItem(fleetagent.PriorityP3, id, 16))
				if err != nil {
					errs <- err
					return
				}
				positions <- position
			}
		}()
	}
	wg.Wait()
	close(errs)
	close(positions)
	for err := range errs {
		t.Fatalf("concurrent enqueue: %v", err)
	}
	var sequences []int
	for position := range positions {
		sequences = append(sequences, int(position.Sequence))
	}
	sort.Ints(sequences)
	if len(sequences) != producers*perProducer {
		t.Fatalf("positions = %d", len(sequences))
	}
	for index, sequence := range sequences {
		if sequence != index+1 {
			t.Fatalf("sequence[%d] = %d", index, sequence)
		}
	}
	if len(mustPeek(t, s)) != producers*perProducer {
		t.Fatalf("records missing after concurrent enqueue")
	}
}

func TestClosedAndCancelledOperations(t *testing.T) {
	cfg := testConfig(t)
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, err := s.Enqueue(context.Background(), testItem(fleetagent.PriorityP3, "x", 1)); !errors.Is(err, ErrClosed) {
		t.Errorf("enqueue after close = %v", err)
	}
	if _, err := s.Peek(context.Background(), ports.PeekSpoolRequest{}); !errors.Is(err, ErrClosed) {
		t.Errorf("peek after close = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Flush(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled flush = %v", err)
	}
}

func TestSpoolFilesAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACLs are not represented by os.FileMode permission bits")
	}
	cfg := testConfig(t)
	s := mustOpen(t, cfg)
	mustEnqueue(t, s, testItem(fleetagent.PriorityP2, "secret-signal", 32))
	entries, err := os.ReadDir(cfg.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s permissions = %o, expose group/world bits", filepath.Base(entry.Name()), info.Mode().Perm())
		}
	}
}

func TestSecurePathRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires elevated privileges on some Windows hosts")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "p3-e00000000000000000001-s00000000000000000001.wal")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := securePath(link, 0o600); err == nil {
		t.Fatal("symlink spool path accepted")
	}
}

func TestStatsDescribeAllLanes(t *testing.T) {
	s := mustOpen(t, testConfig(t))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP1, "det", 32))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "raw", 32))
	stats, err := s.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Priorities) != 4 || stats.TotalRecords != 2 || stats.TotalBytes <= 0 || stats.FsyncCount == 0 {
		t.Fatalf("stats = %#v", stats)
	}
	if stats.Priorities[1].Records != 1 || stats.Priorities[3].Records != 1 {
		t.Fatalf("lane stats = %#v", stats.Priorities)
	}
	if !stats.Priorities[1].OldestUnacked.Equal(testNow) {
		t.Errorf("oldest = %s", stats.Priorities[1].OldestUnacked)
	}
}

func TestSegmentNamesRoundTripAndRejectAliases(t *testing.T) {
	for priority := fleetagent.PriorityP0; priority <= fleetagent.PriorityP3; priority++ {
		name := segmentName(priority, 123, 456)
		gotPriority, epoch, start, ok := parseSegmentName(name)
		if !ok || gotPriority != priority || epoch != 123 || start != 456 {
			t.Fatalf("parse %q = %s/%d/%d/%v", name, gotPriority, epoch, start, ok)
		}
	}
	for _, invalid := range []string{"p3-e1-s1.wal", "p4-e00000000000000000001-s00000000000000000001.wal", "p0-e00000000000000000000-s00000000000000000001.wal", "gaps.log", "../p0.wal"} {
		if _, _, _, ok := parseSegmentName(invalid); ok {
			t.Errorf("accepted non-canonical segment name %q", invalid)
		}
	}
}

func TestRollbackAppendRestoresOffsetForNextWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "append.wal")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Write([]byte("goodpartial")); err != nil {
		t.Fatal(err)
	}
	if err := rollbackAppend(file, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("next")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "goodnext" {
		t.Fatalf("repaired contents = %q", data)
	}
}

func TestSyncFailurePoisonsSpoolUntilRecovery(t *testing.T) {
	cfg := testConfig(t)
	cfg.Sync[fleetagent.PriorityP3] = SyncAlways
	s := mustOpen(t, cfg)
	originalSync := s.syncFile
	s.syncFile = func(*os.File) error { return errors.New("injected sync failure") }

	if _, err := s.Enqueue(context.Background(), testItem(fleetagent.PriorityP3, "ambiguous", 32)); !errors.Is(err, ErrFailed) {
		t.Fatalf("enqueue after sync failure = %v, want ErrFailed", err)
	}
	if _, err := s.Peek(context.Background(), ports.PeekSpoolRequest{}); !errors.Is(err, ErrFailed) {
		t.Fatalf("peek after sync failure = %v, want ErrFailed", err)
	}
	if _, err := s.Enqueue(context.Background(), testItem(fleetagent.PriorityP3, "must-not-reuse", 32)); !errors.Is(err, ErrFailed) {
		t.Fatalf("enqueue after sync failure = %v, want ErrFailed", err)
	}

	// Close still owns cleanup after fail-stop. A successful final flush makes
	// the ambiguous frame recoverable without ever reusing its coordinate.
	s.syncFile = originalSync
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := mustOpen(t, cfg)
	defer reopened.Close()
	requireIDs(t, mustPeek(t, reopened), "ambiguous")
	next := mustEnqueue(t, reopened, testItem(fleetagent.PriorityP3, "next", 32))
	if next.Sequence != 2 {
		t.Fatalf("sequence after recovery = %d, want 2", next.Sequence)
	}
}

func TestStateCommitFailurePoisonsSpoolUntilRecovery(t *testing.T) {
	cfg := testConfig(t)
	s := mustOpen(t, cfg)
	originalPersist := s.persistState
	s.persistState = func(string, *diskState) error { return errors.New("injected state failure") }

	if _, err := s.Enqueue(context.Background(), testItem(fleetagent.PriorityP2, "ambiguous", 32)); !errors.Is(err, ErrFailed) {
		t.Fatalf("enqueue after state commit failure = %v, want ErrFailed", err)
	}
	if _, err := s.Stats(context.Background()); !errors.Is(err, ErrFailed) {
		t.Fatalf("stats after state failure = %v, want ErrFailed", err)
	}
	if _, err := s.Enqueue(context.Background(), testItem(fleetagent.PriorityP2, "must-not-reuse", 32)); !errors.Is(err, ErrFailed) {
		t.Fatalf("enqueue after state failure = %v, want ErrFailed", err)
	}

	s.persistState = originalPersist
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := mustOpen(t, cfg)
	defer reopened.Close()
	requireIDs(t, mustPeek(t, reopened), "ambiguous")
	next := mustEnqueue(t, reopened, testItem(fleetagent.PriorityP2, "next", 32))
	if next.Sequence != 2 {
		t.Fatalf("sequence after recovery = %d, want 2", next.Sequence)
	}
}
