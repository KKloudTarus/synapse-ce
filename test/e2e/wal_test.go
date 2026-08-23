package e2e

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/spool"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestWAL_RealSpoolRedactedDurableRoundTrip ties the real A2 disk WAL into the exit gate: a source-redacted
// (A6) telemetry envelope is persisted to a real on-disk spool, peeked back byte-durable WITHOUT the
// secret, and acknowledged (highest-contiguous). It uses no sensor goroutines, so it is deterministic.
func TestWAL_RealSpoolRedactedDurableRoundTrip(t *testing.T) {
	h := newHarness(t, 0)
	sp, err := spool.Open(spool.Config{
		Dir: t.TempDir(), Session: e2eSession, Boot: e2eBoot,
		MaxBytes: 16 << 20, SegmentBytes: 4 << 20, MaxRecordBytes: 1 << 20,
		PeekRecords: 64, PeekBytes: 1 << 20, BatchInterval: time.Second, BatchBytes: 1 << 20,
		Now: func() time.Time { return h.now },
	})
	if err != nil {
		t.Fatalf("spool open: %v", err)
	}
	defer sp.Close()

	env := h.telemetryEnvelope(1, []string{"app", "--password=" + plantedSecret, "run"})
	scrubbed, _, err := privacy.Scrub(env, h.policy)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(scrubbed)
	if err != nil {
		t.Fatal(err)
	}
	prio, err := fleetagent.TelemetryPriority(scrubbed.EventClass)
	if err != nil {
		t.Fatal(err)
	}
	item := ports.SpoolItem{
		Kind: ports.SpoolRecordTelemetry, Priority: prio, EventID: scrubbed.EventID,
		EventClass: scrubbed.EventClass, ContentType: "application/vnd.synapse.telemetry-envelope+json",
		Payload: payload, ObservedAt: scrubbed.ObservedAt, SchemaVersion: scrubbed.SchemaVersion,
		MustNotShed: telemetry.MustNotShed(scrubbed.EventClass),
	}
	if _, err := sp.Enqueue(context.Background(), item); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	recs, err := sp.Peek(context.Background(), ports.PeekSpoolRequest{})
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("want 1 durable record, got %d", len(recs))
	}
	if strings.Contains(string(recs[0].Payload), plantedSecret) {
		t.Fatal("secret was persisted to the WAL unredacted (A6 must run before A2)")
	}
	if _, err := sp.Ack(context.Background(), ports.SpoolACK{Priority: prio, Epoch: recs[0].Position.Epoch, Through: recs[0].Position.Sequence}); err != nil {
		t.Fatalf("ack: %v", err)
	}
}
