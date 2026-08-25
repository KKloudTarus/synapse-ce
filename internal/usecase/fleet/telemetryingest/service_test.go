package telemetryingest

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const tenant = shared.ID("tenant-1")

type fakeClock struct{ now time.Time }

func (c fakeClock) Now() time.Time { return c.now }

type fakeAudit struct {
	mu sync.Mutex
	n  int
}

func (a *fakeAudit) Record(context.Context, ports.AuditEntry) error {
	a.mu.Lock()
	a.n++
	a.mu.Unlock()
	return nil
}
func (a *fakeAudit) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.n
}

type fakeKeys struct{ key fleetagent.AgentSigningKey }

func (k fakeKeys) ResolveSigningKey(_ context.Context, agentID shared.ID, keyID string) (fleetagent.AgentSigningKey, error) {
	if agentID == k.key.AgentID && keyID == k.key.KeyID {
		return k.key, nil
	}
	return fleetagent.AgentSigningKey{}, shared.ErrNotFound
}

type harness struct {
	t         *testing.T
	svc       *Service
	transport *memory.TelemetryTransportStore
	priv      ed25519.PrivateKey
	key       fleetagent.AgentSigningKey
	audit     *fakeAudit
	now       time.Time
	ctx       context.Context
	stream    shared.ID
	session   fleetagent.SessionID
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	now := time.Unix(1_700_000_000, 0).UTC()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := fleetagent.NewSigningKey("agent-1", fleetagent.PurposeTelemetryBatch, pub, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	transport := memory.NewTelemetryTransportStore()
	audit := &fakeAudit{}
	svc, err := NewService(transport, fakeKeys{key: key}, audit, fakeClock{now})
	if err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), tenant)
	if err := transport.BindTelemetryAsset(ctx, ports.TelemetryAssetBinding{TenantID: tenant, AgentID: "agent-1", AssetID: "asset-1", UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	session := fleetagent.CanonicalSessionID("agent-1")
	stream, err := fleetagent.TelemetryDeliveryStreamID("agent-1", session, fleetagent.PriorityP1)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, svc: svc, transport: transport, priv: priv, key: key, audit: audit, now: now, ctx: ctx, stream: stream, session: session}
}

func (h *harness) canonicalEvent(version int, id shared.ID, sequence uint64) (EventPayload, fleetagent.EventRef) {
	h.t.Helper()
	observed := h.now.Add(time.Duration(sequence) * time.Millisecond)
	ev := telemetry.TelemetryEvent{
		Class:   detection.ClassProcess,
		Process: &telemetry.ProcessObservation{Kind: "exec", PID: 100 + int(sequence), EntityID: shared.ID("proc-" + id.String()), Comm: "test-proc"},
	}
	env := telemetry.TelemetryEnvelope{
		SchemaVersion: version,
		EventID:       id, EventType: ev.EventType(), EventClass: detection.ClassProcess,
		AgentID: "agent-1", AgentSessionID: shared.ID(h.session), AssetID: "asset-1",
		BootID: "boot-1", StreamID: "sensor-stream-1", SensorID: "sensor-1", SensorVersion: "1",
		OccurredAt: observed.Add(-time.Millisecond), ObservedAt: observed, Sequence: sequence,
		Event: ev,
	}
	payload, err := json.Marshal(env)
	if err != nil {
		h.t.Fatal(err)
	}
	wrapped := EventPayload{EventID: id, Class: detection.ClassProcess, Payload: payload, ObservedAt: observed}
	ref := fleetagent.EventRef{ID: id, Digest: fleetagent.TelemetryEventDigest(payload, "asset-1")}
	return wrapped, ref
}

func (h *harness) signedBatch(epoch, seq, prev uint64, eventIDs ...shared.ID) IngestRequest {
	return h.signedBatchVersion(telemetry.SchemaVersion, epoch, seq, prev, eventIDs...)
}

func (h *harness) signedBatchVersion(version int, epoch, seq, prev uint64, eventIDs ...shared.ID) IngestRequest {
	h.t.Helper()
	assetID := shared.ID("asset-1")
	events := make([]EventPayload, len(eventIDs))
	refs := make([]fleetagent.EventRef, len(eventIDs))
	var minAt, maxAt time.Time
	for i, id := range eventIDs {
		events[i], refs[i] = h.canonicalEvent(version, id, uint64(i+1))
		at := events[i].ObservedAt.UTC()
		if minAt.IsZero() || at.Before(minAt) {
			minAt = at
		}
		if maxAt.IsZero() || at.After(maxAt) {
			maxAt = at
		}
	}
	m := fleetagent.TelemetryBatchManifest{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion,
		SchemaVersion:   version,
		BatchID:         shared.ID("batch-" + seqStr(epoch) + "-" + seqStr(seq)),
		AgentID:         "agent-1", HostID: "agent-1", AssetID: assetID, StreamID: h.stream,
		Position:             fleetagent.StreamPosition{Priority: fleetagent.PriorityP1, Epoch: epoch, Sequence: seq, Session: h.session, Boot: "boot-1"},
		PreviousSequence:     prev,
		EventTimeMin:         minAt,
		EventTimeMax:         maxAt,
		ObservedCount:        len(eventIDs),
		KeptCount:            len(eventIDs),
		SamplingPolicyDigest: "spd",
		Events:               refs,
		PayloadDigest:        fleetagent.TelemetryPayloadDigest(refs),
		KeyID:                h.key.KeyID,
	}
	m.Signature = fleetagent.SignTelemetryManifest(h.priv, m)
	return IngestRequest{Manifest: m, Events: events}
}

func (h *harness) resignPayload(req *IngestRequest, index int, mutate func(*telemetry.TelemetryEnvelope)) {
	h.t.Helper()
	var env telemetry.TelemetryEnvelope
	if err := json.Unmarshal(req.Events[index].Payload, &env); err != nil {
		h.t.Fatal(err)
	}
	mutate(&env)
	payload, err := json.Marshal(env)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Events[index].Payload = payload
	for i := range req.Manifest.Events {
		if req.Manifest.Events[i].ID == req.Events[index].EventID {
			req.Manifest.Events[i].Digest = fleetagent.TelemetryEventDigest(payload, req.Manifest.AssetID)
		}
	}
	req.Manifest.PayloadDigest = fleetagent.TelemetryPayloadDigest(req.Manifest.Events)
	req.Manifest.Signature = fleetagent.SignTelemetryManifest(h.priv, req.Manifest)
}

func seqStr(u uint64) string { return string(rune('0' + int(u%10))) }

func TestIngestAcceptsAndAcks(t *testing.T) {
	h := newHarness(t)
	res, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 1, 0, "e1", "e2"))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if !res.Accepted || res.Duplicate || res.ACK != 1 || res.Provenance != ProvenanceAcknowledged {
		t.Fatalf("unexpected result: %+v", res)
	}
	if n, _ := h.transport.CountBatchEvents(h.ctx, "agent-1", h.stream, 1, 1); n != 2 {
		t.Fatalf("want 2 stored events, got %d", n)
	}
}

func TestIngestIdempotentReplay(t *testing.T) {
	h := newHarness(t)
	batch := h.signedBatch(1, 1, 0, "e1")
	if _, err := h.svc.Ingest(h.ctx, "agent-1", batch); err != nil {
		t.Fatal(err)
	}
	res, err := h.svc.Ingest(h.ctx, "agent-1", batch)
	if err != nil {
		t.Fatalf("replay must not error: %v", err)
	}
	if res.Accepted || !res.Duplicate || res.ACK != 1 {
		t.Fatalf("replay must be an idempotent duplicate with ACK=1: %+v", res)
	}
	if n, _ := h.transport.CountBatchEvents(h.ctx, "agent-1", h.stream, 1, 1); n != 1 {
		t.Fatalf("replay must not duplicate stored events, got %d", n)
	}
}

func TestIngestRebootResetIsNotReplay(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 1, 0, "e1")); err != nil {
		t.Fatal(err)
	}
	res, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(2, 1, 0, "e2"))
	if err != nil {
		t.Fatalf("reboot reset must ingest: %v", err)
	}
	if !res.Accepted || res.Duplicate {
		t.Fatalf("epoch-bumped reset-to-1 must be a fresh accept, not a replay: %+v", res)
	}
}

func TestIngestStaleIncarnationRejected(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(2, 1, 0, "e1")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 5, 4, "e2")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("stale incarnation must be rejected, got %v", err)
	}
}

func TestIngestForwardGapPersisted(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 1, 0, "e1")); err != nil {
		t.Fatal(err)
	}
	res, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 4, 3, "e4"))
	if err != nil {
		t.Fatalf("forward-gap batch must ingest: %v", err)
	}
	if !res.Accepted || !res.GapOpen || res.ACK != 1 {
		t.Fatalf("forward gap result: %+v", res)
	}
	gaps, _ := h.transport.ListGaps(h.ctx, "agent-1", h.stream)
	if len(gaps) != 1 || gaps[0].FromSequence != 2 || gaps[0].ToSequence != 3 {
		t.Fatalf("want materialized gap [2,3], got %+v", gaps)
	}
	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 2, 1, "e2")); err != nil {
		t.Fatal(err)
	}
	res3, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 3, 2, "e3"))
	if err != nil {
		t.Fatal(err)
	}
	if res3.ACK != 4 {
		t.Fatalf("filling 2,3 must advance ACK to 4, got %d", res3.ACK)
	}
	if gaps, _ := h.transport.ListGaps(h.ctx, "agent-1", h.stream); len(gaps) != 0 {
		t.Fatalf("filled gap must not linger, got %+v", gaps)
	}
}

func TestIngestForwardJumpTooLargeRejected(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, 1, 0, "e1")); err != nil {
		t.Fatal(err)
	}
	far := uint64(1) + maxForwardGap + 1
	if _, err := h.svc.Ingest(h.ctx, "agent-1", h.signedBatch(1, far, far-1, "eFar")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversized jump must be validation error, got %v", err)
	}
}

func TestIngestIdentityMismatchForbidden(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Ingest(h.ctx, "agent-2", h.signedBatch(1, 1, 0, "e1")); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("identity mismatch must be forbidden, got %v", err)
	}
}

func TestIngestRejectsForgedHostSessionStreamAndAsset(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*IngestRequest)
	}{
		{"host", func(r *IngestRequest) { r.Manifest.HostID = "forged-host" }},
		{"session", func(r *IngestRequest) { r.Manifest.Position.Session = "forged-session" }},
		{"stream", func(r *IngestRequest) { r.Manifest.StreamID = "forged-stream" }},
		{"asset", func(r *IngestRequest) { r.Manifest.AssetID = "forged-asset" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			req := h.signedBatch(1, 1, 0, "e1")
			tt.mutate(&req)
			req.Manifest.Signature = fleetagent.SignTelemetryManifest(h.priv, req.Manifest)
			if _, err := h.svc.Ingest(h.ctx, "agent-1", req); !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("forged %s must be forbidden, got %v", tt.name, err)
			}
		})
	}
}

func TestIngestRejectsForgedCanonicalPayloadIdentity(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*telemetry.TelemetryEnvelope)
		want   error
	}{
		{"agent", func(e *telemetry.TelemetryEnvelope) { e.AgentID = "forged-agent" }, shared.ErrForbidden},
		{"asset", func(e *telemetry.TelemetryEnvelope) { e.AssetID = "forged-asset" }, shared.ErrForbidden},
		{"session", func(e *telemetry.TelemetryEnvelope) { e.AgentSessionID = "forged-session" }, shared.ErrForbidden},
		{"boot", func(e *telemetry.TelemetryEnvelope) { e.BootID = "forged-boot" }, shared.ErrForbidden},
		{"received-at", func(e *telemetry.TelemetryEnvelope) { e.ReceivedAt = e.ObservedAt.Add(time.Second) }, shared.ErrForbidden},
		{"schema", func(e *telemetry.TelemetryEnvelope) { e.SchemaVersion = 1 }, shared.ErrValidation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			req := h.signedBatchVersion(2, 1, 1, 0, "e1")
			h.resignPayload(&req, 0, tt.mutate)
			if _, err := h.svc.Ingest(h.ctx, "agent-1", req); !errors.Is(err, tt.want) {
				t.Fatalf("forged canonical payload %s: want %v, got %v", tt.name, tt.want, err)
			}
		})
	}
}

func TestIngestRejectsWrapperMetadataThatDisagreesWithSignedPayload(t *testing.T) {
	h := newHarness(t)
	req := h.signedBatch(1, 1, 0, "e1")
	req.Events[0].Class = detection.ClassNetwork
	if _, err := h.svc.Ingest(h.ctx, "agent-1", req); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("wrapper class mismatch must fail, got %v", err)
	}

	h = newHarness(t)
	req = h.signedBatch(1, 1, 0, "e1")
	req.Events[0].ObservedAt = req.Events[0].ObservedAt.Add(time.Second)
	if _, err := h.svc.Ingest(h.ctx, "agent-1", req); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("wrapper observed-at mismatch must fail, got %v", err)
	}
}

func TestIngestAcceptsSchemaV1AndV2(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(seqStr(uint64(version)), func(t *testing.T) {
			h := newHarness(t)
			req := h.signedBatchVersion(version, 1, 1, 0, "e1")
			if _, err := h.svc.Ingest(h.ctx, "agent-1", req); err != nil {
				t.Fatalf("schema v%d must ingest: %v", version, err)
			}
		})
	}
}

func TestIngestFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*IngestRequest)
		is     error
	}{
		{"bad signature", func(r *IngestRequest) { r.Manifest.Signature = "AAAA" }, fleetagent.ErrBadManifestSignature},
		{"unknown key", func(r *IngestRequest) { r.Manifest.KeyID = "unknown" }, shared.ErrForbidden},
		{"unsupported schema", func(r *IngestRequest) { r.Manifest.SchemaVersion = 999 }, shared.ErrValidation},
		{"tampered event body", func(r *IngestRequest) { r.Events[0].Payload = []byte("tampered") }, shared.ErrValidation},
		{"event not in manifest", func(r *IngestRequest) { r.Events[0].EventID = "ghost" }, shared.ErrValidation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			req := h.signedBatch(1, 1, 0, "e1")
			if tt.name == "unsupported schema" {
				req.Manifest.SchemaVersion = 999
				req.Manifest.Signature = fleetagent.SignTelemetryManifest(h.priv, req.Manifest)
			}
			tt.mutate(&req)
			if _, err := h.svc.Ingest(h.ctx, "agent-1", req); !errors.Is(err, tt.is) {
				t.Fatalf("%s: want %v, got %v", tt.name, tt.is, err)
			}
		})
	}
}
