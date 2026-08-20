package spool

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var testNow = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Dir: t.TempDir(), Session: "session-1", Boot: "boot-1",
		MaxBytes: 4 << 20, SegmentBytes: 64 << 10, MaxRecordBytes: 32 << 10,
		PeekRecords: 128, PeekBytes: 1 << 20,
		BatchInterval: time.Hour, BatchBytes: 1 << 20,
		Sync: map[fleetagent.DeliveryPriority]SyncPolicy{
			fleetagent.PriorityP0: SyncAlways,
			fleetagent.PriorityP1: SyncAlways,
			fleetagent.PriorityP2: SyncAlways,
			fleetagent.PriorityP3: SyncBatch,
		},
		Now: func() time.Time { return testNow },
	}
}

func testItem(priority fleetagent.DeliveryPriority, id string, size int) ports.SpoolItem {
	class := detection.ClassProcess
	mustNotShed := false
	if priority == fleetagent.PriorityP2 {
		class = detection.ClassFile
		mustNotShed = true
	}
	if priority < fleetagent.PriorityP2 {
		class = ""
		mustNotShed = true
	}
	kind := ports.SpoolRecordTelemetry
	if priority == fleetagent.PriorityP1 {
		kind = ports.SpoolRecordDetection
	}
	if priority == fleetagent.PriorityP0 {
		kind = ports.SpoolRecordSensorState
	}
	return ports.SpoolItem{
		Kind: kind, Priority: priority, EventID: shared.ID(id), EventClass: class,
		ContentType: "application/json", Payload: bytes.Repeat([]byte(id+"|"), max(1, size/max(1, len(id)+1))),
		ObservedAt: testNow, MustNotShed: mustNotShed, SchemaVersion: 1,
	}
}

func mustOpen(t *testing.T, cfg Config) *Spool {
	t.Helper()
	s, err := Open(cfg)
	if err != nil {
		t.Fatalf("open spool: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close spool: %v", err)
		}
	})
	return s
}

func mustEnqueue(t *testing.T, s *Spool, item ports.SpoolItem) fleetagent.StreamPosition {
	t.Helper()
	position, err := s.Enqueue(context.Background(), item)
	if err != nil {
		t.Fatalf("enqueue %s: %v", item.EventID, err)
	}
	return position
}

func mustPeek(t *testing.T, s *Spool) []ports.SpoolRecord {
	t.Helper()
	records, err := s.Peek(context.Background(), ports.PeekSpoolRequest{MaxRecords: 10_000, MaxBytes: 64 << 20})
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	return records
}

func recordIDs(records []ports.SpoolRecord) []string {
	result := make([]string, len(records))
	for i := range records {
		result[i] = records[i].EventID.String()
	}
	return result
}

func requireIDs(t *testing.T, records []ports.SpoolRecord, want ...string) {
	t.Helper()
	got := recordIDs(records)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("record ids = %v, want %v", got, want)
	}
}
