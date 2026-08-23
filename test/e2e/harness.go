// Package e2e is the Phase-A (#628, A7) data-plane exit-gate harness: it composes the REAL A1–A6
// components — canonical normalizer (A1), durable WAL/spool (A2), signed telemetry ingest + ACK/gap (A3),
// signed detection ingest + evidence seal (A4/A5), and source-side redaction (A6) — and drives the whole
// software loop end to end, under the failure matrix, and under a bounded soak, asserting the
// coverage-honesty invariant (no silent loss; loss becomes a durable queryable gap) across it.
//
// Out of this in-process harness's reach (documented Phase-A tail): the real syscall→eBPF decode leg
// (Linux-only) and the real over-the-network agent shipper (#624/#625 tail). The harness stands in for the
// shipper — it drains the real WAL and builds+signs the real manifest/batch — so every domain/usecase
// component on the path is the production one.
package e2e

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/detectledger"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/telemetryingest"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	e2eTenant  = shared.ID("tenant-e2e")
	e2eAgent   = shared.ID("agent-e2e")
	e2eAsset   = shared.ID("asset-e2e")
	e2eEng     = shared.ID("eng-e2e")
	e2eSession = fleetagent.SessionID("sess-e2e")
	e2eBoot    = fleetagent.BootID("boot-e2e")
	e2eStream  = shared.ID("stream-e2e-p1")
)

// captureAudit records audit actions so fail-closed paths can be asserted (every rejection is audited).
type captureAudit struct {
	mu      sync.Mutex
	actions []string
}

func (a *captureAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.mu.Lock()
	a.actions = append(a.actions, e.Action)
	a.mu.Unlock()
	return nil
}
func (a *captureAudit) has(action string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, x := range a.actions {
		if x == action {
			return true
		}
	}
	return false
}

// e2eClock is a mutable clock shared (by pointer) with every service the harness composes, so a test that
// advances it — e.g. past a retention window — is seen by the ledger/evidence, not just the harness copy.
type e2eClock struct{ t time.Time }

func (c *e2eClock) Now() time.Time { return c.t }

type seqIDs struct {
	mu sync.Mutex
	n  int
}

func (g *seqIDs) NewID() shared.ID {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	return shared.ID(fmt.Sprintf("id-e2e-%d", g.n))
}

// harness holds the composed real data plane and the agent's signing material.
type harness struct {
	t         *testing.T
	ctx       context.Context
	now       time.Time
	clock     *e2eClock
	audit     *captureAudit
	keys      *memory.AgentSigningKeyStore
	transport *memory.TelemetryTransportStore
	records   *memory.DetectionRecordStore
	evidence  *evidenceuc.Service
	telemetry *telemetryingest.Service
	ledger    *detectledger.Service
	policy    privacy.Policy

	telPriv ed25519.PrivateKey
	telKey  fleetagent.AgentSigningKey
	detPriv ed25519.PrivateKey
	detKey  fleetagent.AgentSigningKey
}

// newHarness composes the real components with an in-memory backing and a registered telemetry + detection
// signing key for the agent. retention 0 keeps detection projections forever (a per-test override exists).
func newHarness(t *testing.T, retention time.Duration) *harness {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	clock := &e2eClock{t: now}
	audit := &captureAudit{}
	ids := &seqIDs{}
	ctx := shared.WithTenant(context.Background(), e2eTenant)

	keys := memory.NewAgentSigningKeyStore()
	transport := memory.NewTelemetryTransportStore()
	records := memory.NewDetectionRecordStore()

	evidence, err := evidenceuc.NewService(memory.NewEvidenceStore(), nil, audit, clock, ids)
	if err != nil {
		t.Fatalf("evidence service: %v", err)
	}
	telemetrySvc, err := telemetryingest.NewService(transport, keys, audit, clock)
	if err != nil {
		t.Fatalf("telemetry ingest: %v", err)
	}
	bridge, err := detectledger.NewEvidenceChainBridge(
		func(c context.Context, eng shared.ID, kind, idem string, content []byte, by string) (shared.ID, error) {
			ev, serr := evidence.SealOnce(c, eng, kind, idem, content, by)
			if serr != nil {
				return "", serr
			}
			return ev.ID, nil
		},
		func(c context.Context, eng shared.ID) error { return evidence.VerifyChainError(c, eng) },
	)
	if err != nil {
		t.Fatalf("evidence chain bridge: %v", err)
	}
	ledger, err := detectledger.NewService(records, bridge, keys, audit, clock, ids, retention)
	if err != nil {
		t.Fatalf("detection ledger: %v", err)
	}

	h := &harness{
		t: t, ctx: ctx, now: now, clock: clock, audit: audit, keys: keys, transport: transport,
		records: records, evidence: evidence, telemetry: telemetrySvc, ledger: ledger, policy: privacy.DefaultPolicy(),
	}
	h.telPriv, h.telKey = h.registerKey(fleetagent.PurposeTelemetryBatch)
	h.detPriv, h.detKey = h.registerKey(fleetagent.PurposeDetectionBatch)
	return h
}

// registerKey mints + registers a usable signing key for the agent under the given purpose.
func (h *harness) registerKey(purpose fleetagent.SigningPurpose) (ed25519.PrivateKey, fleetagent.AgentSigningKey) {
	h.t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		h.t.Fatal(err)
	}
	key, err := fleetagent.NewSigningKey(e2eAgent, purpose, pub, h.now.Add(-time.Hour), h.now.Add(time.Hour))
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.keys.Register(h.ctx, key); err != nil {
		h.t.Fatalf("register key: %v", err)
	}
	return priv, key
}

// ---- telemetry leg (A1 normalize is exercised via the sensor tests; here the harness builds the canonical
// envelope, applies A6 redaction, then plays the shipper: sign a manifest and ingest through the real A3) --

// telemetryEnvelope builds a canonical process-telemetry envelope carrying the given argv.
func (h *harness) telemetryEnvelope(seq uint64, args []string) telemetry.TelemetryEnvelope {
	return telemetry.TelemetryEnvelope{
		SchemaVersion: telemetry.SchemaVersion, EventID: shared.ID(fmt.Sprintf("te-%d", seq)),
		EventType: "process.exec", EventClass: detection.ClassProcess,
		AgentID: e2eAgent, AgentSessionID: shared.ID(e2eSession), AssetID: e2eAsset, BootID: shared.ID(e2eBoot),
		StreamID: "sensor-stream", SensorID: "sensor-1", SensorVersion: "1",
		OccurredAt: h.now.Add(time.Duration(seq) * time.Millisecond), ObservedAt: h.now.Add(time.Duration(seq) * time.Millisecond),
		Sequence: seq,
		Event: telemetry.TelemetryEvent{Class: detection.ClassProcess,
			Process: &telemetry.ProcessObservation{Kind: "exec", PID: 100 + int(seq), Comm: "app", Path: "/usr/bin/app", Args: args}},
	}
}

// shipTelemetry redacts (A6) each envelope, then builds + signs the A3 manifest and ingests it. It is the
// harness playing the agent shipper over the real ingest. Returns the ingest result.
func (h *harness) shipTelemetry(epoch, seq, prev uint64, envelopes ...telemetry.TelemetryEnvelope) (telemetryingest.IngestResult, error) {
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
		BatchID: shared.ID(fmt.Sprintf("batch-%d-%d", epoch, seq)), AgentID: e2eAgent, AssetID: e2eAsset, StreamID: e2eStream,
		Position:         fleetagent.StreamPosition{Priority: fleetagent.PriorityP1, Epoch: epoch, Sequence: seq, Session: e2eSession, Boot: e2eBoot},
		PreviousSequence: prev, EventTimeMin: minAt, EventTimeMax: maxAt,
		ObservedCount: len(events), KeptCount: len(events), Events: refs,
		PayloadDigest: fleetagent.TelemetryPayloadDigest(refs), KeyID: h.telKey.KeyID,
	}
	m.Signature = fleetagent.SignTelemetryManifest(h.telPriv, m)
	return h.telemetry.Ingest(h.ctx, e2eAgent, telemetryingest.IngestRequest{Manifest: m, Events: events})
}

// ---- detection leg: build a detection carrying evidence argv, redact it (A6 ScrubDetection), sign the
// batch, and ingest through the real A4/A5 ledger (seals a DetectionEvidenceEnvelope). ------------------

func (h *harness) mkDetection(args []string) detection.Detection {
	h.t.Helper()
	r, ok := detection.Lookup("det.process_enumeration")
	if !ok {
		h.t.Fatal("missing rule det.process_enumeration")
	}
	ev := detection.Event{Class: detection.ClassProcess, At: h.now, Host: e2eAsset,
		Process: &detection.ProcessEvent{PID: 200, PPID: 1, Comm: "app", Path: "/usr/bin/app", Args: args, UID: 0}}
	d, err := detection.NewDetection(r, e2eAgent, e2eAgent, []detection.Event{ev}, h.now)
	if err != nil {
		h.t.Fatal(err)
	}
	return d
}

// shipDetection redacts the detection evidence (A6), signs the batch, and ingests it (A4/A5). detID is the
// detection id; sequence is the batch sequence. Returns the ledger result.
func (h *harness) shipDetection(detID shared.ID, sequence uint64, priv ed25519.PrivateKey, keyID string, det detection.Detection) (detectledger.IngestResult, error) {
	scrubbed, _, err := privacy.ScrubDetection(det, h.policy)
	if err != nil {
		h.t.Fatalf("scrub detection: %v", err)
	}
	payload, err := json.Marshal(scrubbed)
	if err != nil {
		h.t.Fatal(err)
	}
	item := detectledger.IngestItem{ID: detID, Detection: scrubbed, AssetID: e2eAsset}
	batch := fleetagent.AgentBatch{
		AgentID: e2eAgent, EngagementID: e2eEng, Sequence: sequence, KeyID: keyID,
		Detections: []fleetagent.DetectionRef{{ID: detID, ContentSHA256: fleetagent.DetectionContentHash(payload, e2eAsset)}},
	}
	batch.Signature = fleetagent.SignBatch(priv, batch)
	return h.ledger.Ingest(h.ctx, e2eAgent, batch, []detectledger.IngestItem{item})
}
