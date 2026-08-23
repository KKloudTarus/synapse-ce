package egressbroker

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// countJournalLines returns the number of records currently on disk.
func countJournalLines(t *testing.T, path string) int {
	t.Helper()
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	defer file.Close()
	lines := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan journal: %v", err)
	}
	return lines
}

// TestFileGrantReplayStoreCompactsExpiredRecords proves the append-only journal is rewritten to drop
// expired records once it grows well past the live set, without ever letting a consumed-and-still-valid
// grant be replayed (before or after compaction, and across a restart of the compacted file).
func TestFileGrantReplayStoreCompactsExpiredRecords(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	path := filepath.Join(t.TempDir(), "broker", "replay.jsonl")
	store, err := NewFileGrantReplayStore(path, base)
	if err != nil {
		t.Fatal(err)
	}

	// Consume well past the compaction floor. Each grant lives one second (expiry is stored at
	// whole-second granularity) and the clock advances two seconds per step, so every earlier grant
	// is expired by the next step and the live set stays at one — forcing compaction to drop the
	// backlog.
	const total = replayCompactMinRecords + 64
	var last string
	var lastNow, lastExpiry time.Time
	for i := 0; i < total; i++ {
		now := base.Add(time.Duration(i) * 2 * time.Second)
		expiry := now.Add(time.Second)
		id := fmt.Sprintf("grant-%d", i)
		if err := store.Consume(id, expiry, now); err != nil {
			t.Fatalf("consume %s: %v", id, err)
		}
		last, lastNow, lastExpiry = id, now, expiry
	}

	// Compaction must have bounded the journal far below the number of grants ever consumed.
	if got := countJournalLines(t, path); got >= total {
		t.Fatalf("journal was not compacted: %d records on disk for %d grants", got, total)
	}
	if store.diskRecords >= total {
		t.Fatalf("diskRecords not reset by compaction: %d", store.diskRecords)
	}

	// The most recent grant is still live and must still be rejected as a replay.
	if err := store.Consume(last, lastExpiry, lastNow); !errors.Is(err, ErrGrantReplay) {
		t.Fatalf("live grant replay error = %v, want %v", err, ErrGrantReplay)
	}

	// An early grant that compaction dropped (long expired) is re-consumable: proof it left the
	// journal. Re-consuming an EXPIRED identity is safe — an expired grant can never be presented.
	future := base.Add(2 * time.Hour)
	if err := store.Consume("grant-0", future.Add(time.Minute), future); err != nil {
		t.Fatalf("expired-and-compacted grant should be re-consumable, got %v", err)
	}

	// A fresh store reading the COMPACTED file must still reject the live grant as a replay.
	restarted, err := NewFileGrantReplayStore(path, lastNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Consume(last, lastExpiry, lastNow); !errors.Is(err, ErrGrantReplay) {
		t.Fatalf("post-compaction restart replay error = %v, want %v", err, ErrGrantReplay)
	}
}
