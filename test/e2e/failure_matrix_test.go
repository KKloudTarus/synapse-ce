package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/spool"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/detectledger"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/telemetryingest"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// This file completes the A7 (#628) failure matrix with the cases the first cut left out — network
// outage/retry, disk full, injected persistence write failure, batch inflation ("decompression bomb"),
// and clock skew — each asserting the coverage-honesty invariant: no silent loss, idempotent, fail-closed.
// (sensor-drop / eBPF-detach and the real syscall→eBPF leg remain Linux-only and are out of this
// in-process harness's reach, as documented in harness.go.)

// buildSignedTelemetry builds + signs a real A3 manifest and its event payloads exactly as the harness
// shipper does, but returns them instead of ingesting — so a test can corrupt one field, re-sign, and
// drive the real ingest with a specific defect.
func (h *harness) buildSignedTelemetry(epoch, seq, prev uint64, envelopes ...telemetry.TelemetryEnvelope) (fleetagent.TelemetryBatchManifest, []telemetryingest.EventPayload) {
	h.t.Helper()
	events := make([]telemetryingest.EventPayload, 0, len(envelopes))
	refs := make([]fleetagent.EventRef, 0, len(envelopes))
	var minAt, maxAt time.Time
	for _, env := range envelopes {
		scrubbed, _, err := privacy.Scrub(env, h.policy)
		if err != nil {
			h.t.Fatalf("scrub: %v", err)
		}
		payload, err := json.Marshal(scrubbed)
		if err != nil {
			h.t.Fatal(err)
		}
		events = append(events, telemetryingest.EventPayload{EventID: scrubbed.EventID, Class: scrubbed.EventClass, Payload: payload, ObservedAt: scrubbed.ObservedAt})
		refs = append(refs, fleetagent.EventRef{ID: scrubbed.EventID, Digest: fleetagent.TelemetryEventDigest(payload, e2eAsset)})
		if minAt.IsZero() || scrubbed.ObservedAt.Before(minAt) {
			minAt = scrubbed.ObservedAt
		}
		if maxAt.IsZero() || scrubbed.ObservedAt.After(maxAt) {
			maxAt = scrubbed.ObservedAt
		}
	}
	m := fleetagent.TelemetryBatchManifest{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion, SchemaVersion: telemetry.SchemaVersion,
		BatchID: shared.ID("batch-fm"), AgentID: e2eAgent, HostID: e2eAgent, AssetID: e2eAsset, StreamID: e2eStream,
		Position:         fleetagent.StreamPosition{Priority: fleetagent.PriorityP1, Epoch: epoch, Sequence: seq, Session: e2eSession, Boot: e2eBoot},
		PreviousSequence: prev, EventTimeMin: minAt, EventTimeMax: maxAt,
		ObservedCount: len(events), KeptCount: len(events), Events: refs,
		PayloadDigest: fleetagent.TelemetryPayloadDigest(refs), KeyID: h.telKey.KeyID,
	}
	m.Signature = fleetagent.SignTelemetryManifest(h.telPriv, m)
	return m, events
}

// flakyTransport wraps a real transport store and fails the next N IngestBatchEvents calls with a
// transient error, standing in for a control-plane outage / network partition during the store step.
type flakyTransport struct {
	ports.TelemetryTransportStore
	failNext int
}

func (f *flakyTransport) IngestBatchEvents(ctx context.Context, batch ports.TelemetryEventBatch) (int, error) {
	if f.failNext > 0 {
		f.failNext--
		return 0, errors.New("transient control-plane outage")
	}
	return f.TelemetryTransportStore.IngestBatchEvents(ctx, batch)
}

// TestFailure_NetworkOutageRetryIsIdempotent: a transient store outage fails the batch fail-closed (no ACK
// advance, nothing stored), and the agent's retry of the SAME batch stores it exactly once and acks it —
// at-least-once delivery with idempotent ingest, no silent loss, no double-store.
func TestFailure_NetworkOutageRetryIsIdempotent(t *testing.T) {
	h := newHarness(t, 0)
	mem := memory.NewTelemetryTransportStore()
	if err := mem.BindTelemetryAsset(h.ctx, ports.TelemetryAssetBinding{
		TenantID: e2eTenant, AgentID: e2eAgent, AssetID: e2eAsset, UpdatedAt: h.now,
	}); err != nil {
		t.Fatalf("bind telemetry asset: %v", err)
	}
	flaky := &flakyTransport{TelemetryTransportStore: mem, failNext: 1}
	svc, err := telemetryingest.NewService(flaky, h.keys, h.audit, h.clock)
	if err != nil {
		t.Fatalf("ingest service: %v", err)
	}
	m, events := h.buildSignedTelemetry(1, 1, 0, h.telemetryEnvelope(1, []string{"a"}))

	// Outage: first attempt fails at the store step, fail-closed — no ACK, no stored events, no gap.
	if _, err := svc.Ingest(h.ctx, e2eAgent, telemetryingest.IngestRequest{Manifest: m, Events: events}); err == nil {
		t.Fatal("a store outage must surface as an error, not a silent success")
	}
	if n, _ := mem.CountBatchEvents(h.ctx, e2eAgent, e2eStream, 1, 1); n != 0 {
		t.Fatalf("nothing may be stored when the batch failed: got %d", n)
	}
	// Retry the same batch after the outage clears: stored exactly once, acked, idempotent.
	res, err := svc.Ingest(h.ctx, e2eAgent, telemetryingest.IngestRequest{Manifest: m, Events: events})
	if err != nil || !res.Accepted || res.ACK != 1 {
		t.Fatalf("retry after outage must be accepted with ACK=1: %+v err=%v", res, err)
	}
	if n, _ := mem.CountBatchEvents(h.ctx, e2eAgent, e2eStream, 1, 1); n != 1 {
		t.Fatalf("retry must store the batch exactly once: got %d", n)
	}
}

// TestFailure_DiskFullIsBoundedNotSilent: a saturated WAL refuses a MUST-NOT-SHED record with an explicit,
// bounded SaturatedError instead of silently dropping it — loss is never silent, and the spool stays within
// its byte budget. (A must-not-shed class — privilege — is used deliberately: unlike a sheddable P3 class,
// it cannot be evicted to make room, so at capacity the spool MUST fail explicitly rather than shed.)
func TestFailure_DiskFullIsBoundedNotSilent(t *testing.T) {
	h := newHarness(t, 0)
	const maxBytes = int64(64 << 10)
	sp, err := spool.Open(spool.Config{
		Dir: t.TempDir(), Session: e2eSession, Boot: e2eBoot,
		MaxBytes: maxBytes, SegmentBytes: 16 << 10, MaxRecordBytes: 8 << 10,
		PeekRecords: 64, PeekBytes: 1 << 20, BatchInterval: time.Second, BatchBytes: 1 << 20,
		Now: func() time.Time { return h.now },
	})
	if err != nil {
		t.Fatalf("spool open: %v", err)
	}
	defer sp.Close()

	// A privilege-class item is MustNotShed → PriorityP2, which the spool cannot evict for capacity.
	prio, err := fleetagent.TelemetryPriority(detection.ClassPrivilege)
	if err != nil {
		t.Fatal(err)
	}
	blob := make([]byte, 1<<10) // 1 KiB payload; ~64 fit the 64 KiB budget, so saturation is fast + bounded.
	for i := range blob {
		blob[i] = 'x'
	}
	mkItem := func(i int) ports.SpoolItem {
		return ports.SpoolItem{
			Kind: ports.SpoolRecordTelemetry, Priority: prio, EventID: shared.ID(fmt.Sprintf("pe-%d", i)),
			EventClass: detection.ClassPrivilege, ContentType: "application/vnd.synapse.telemetry-envelope+json",
			Payload: blob, ObservedAt: h.now, SchemaVersion: telemetry.SchemaVersion,
			MustNotShed: telemetry.MustNotShed(detection.ClassPrivilege),
		}
	}
	// Enqueue must-not-shed records until the bounded spool refuses — the refusal must be explicit
	// (SaturatedError), never a silent drop. The loop is bounded well above the byte budget so a spool
	// that (wrongly) never saturates fails the assertion fast instead of spinning.
	saturated := false
	for i := 1; i <= 4096; i++ {
		if _, err := sp.Enqueue(context.Background(), mkItem(i)); err != nil {
			if errors.Is(err, spool.ErrSaturated) || errors.Is(err, spool.ErrGapJournalFull) {
				saturated = true
				break
			}
			t.Fatalf("unexpected enqueue error at %d: %v", i, err)
		}
	}
	if !saturated {
		t.Fatal("a full spool must return an explicit saturation error for a must-not-shed record, never silently drop it")
	}
}

// TestFailure_EvidenceWriteFailureFailsClosed: when the evidence/audit persistence layer fails on write,
// detection ingest fails closed — no detection record is persisted without its sealed evidence link
// (atomic seal-or-nothing), so a storage failure can never leave an unattested detection behind.
func TestFailure_EvidenceWriteFailureFailsClosed(t *testing.T) {
	h := newHarness(t, 0)
	records := memory.NewDetectionRecordStore()
	failing, err := detectledger.NewEvidenceChainBridge(
		func(context.Context, shared.ID, string, string, []byte, string) (shared.ID, error) {
			return "", errors.New("evidence store write failure (disk/db)")
		},
		func(context.Context, shared.ID) error { return nil },
	)
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	ledger, err := detectledger.NewService(records, failing, h.keys, h.audit, h.clock, &seqIDs{}, 0)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}

	det := h.mkDetection([]string{"app", "dump"})
	scrubbed, _, err := privacy.ScrubDetection(det, h.policy)
	if err != nil {
		t.Fatalf("scrub detection: %v", err)
	}
	payload, err := json.Marshal(scrubbed)
	if err != nil {
		t.Fatal(err)
	}
	batch := fleetagent.AgentBatch{
		AgentID: e2eAgent, EngagementID: e2eEng, Sequence: 1, KeyID: h.detKey.KeyID,
		Detections: []fleetagent.DetectionRef{{ID: "d-writefail", ContentSHA256: fleetagent.DetectionContentHash(payload, e2eAsset)}},
	}
	batch.Signature = fleetagent.SignBatch(h.detPriv, batch)
	item := detectledger.IngestItem{ID: "d-writefail", Detection: scrubbed, AssetID: e2eAsset}

	if _, err := ledger.Ingest(h.ctx, e2eAgent, batch, []detectledger.IngestItem{item}); err == nil {
		t.Fatal("a failed evidence seal must fail the ingest closed, not report success")
	}
	if has, _ := records.HasDetection(h.ctx, e2eEng, "d-writefail"); has {
		t.Fatal("no detection record may persist when its evidence seal failed (atomic seal-or-nothing)")
	}
}

// TestFailure_InflatedBatchRejectedAndAudited: a signed manifest that commits to more events than the
// transport actually ships (event-count/binding mismatch — the "decompression bomb" / batch-inflation
// shape) is refused fail-closed and audited; a transport cannot add, drop, or inflate under a signature.
func TestFailure_InflatedBatchRejectedAndAudited(t *testing.T) {
	h := newHarness(t, 0)
	m, events := h.buildSignedTelemetry(1, 1, 0, h.telemetryEnvelope(1, []string{"a"}))
	// The manifest commits to 1 event, but the transport ships none — an inflated/tampered batch.
	if _, err := h.telemetry.Ingest(h.ctx, e2eAgent, telemetryingest.IngestRequest{Manifest: m, Events: events[:0]}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an event-binding mismatch must be rejected as invalid, got %v", err)
	}
	if !h.audit.has("fleet.telemetry.reject") {
		t.Fatal("a refused (inflated/tampered) batch must be audited")
	}
	if n, _ := h.transport.CountBatchEvents(h.ctx, e2eAgent, e2eStream, 1, 1); n != 0 {
		t.Fatalf("a rejected batch must store nothing, got %d", n)
	}
}

// TestFailure_ClockSkewRejected: a manifest whose event-time window is inverted (max before min — the shape
// a skewed/backwards sensor clock produces) fails the ingest timestamp-integrity check fail-closed, so
// corrupt time never enters the store to poison event-time correlation.
func TestFailure_ClockSkewRejected(t *testing.T) {
	h := newHarness(t, 0)
	m, events := h.buildSignedTelemetry(1, 1, 0, h.telemetryEnvelope(1, []string{"a"}))
	// Invert the window (max an hour before min) and re-sign so the manifest is authentic but time-corrupt.
	m.EventTimeMin = m.EventTimeMax.Add(time.Hour)
	m.Signature = fleetagent.SignTelemetryManifest(h.telPriv, m)
	if _, err := h.telemetry.Ingest(h.ctx, e2eAgent, telemetryingest.IngestRequest{Manifest: m, Events: events}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an inverted event-time window (clock skew) must be rejected as invalid, got %v", err)
	}
	if n, _ := h.transport.CountBatchEvents(h.ctx, e2eAgent, e2eStream, 1, 1); n != 0 {
		t.Fatalf("a time-corrupt batch must store nothing, got %d", n)
	}
}

// compile-time: flakyTransport is a drop-in transport store.
var _ ports.TelemetryTransportStore = (*flakyTransport)(nil)
