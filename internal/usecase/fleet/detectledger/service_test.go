package detectledger

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detectionprovenance"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ---- fakes ------------------------------------------------------------------------------------------

type sealCall struct {
	engagement shared.ID
	kind       string
	createdBy  string
	key        string
}

type fakeChain struct {
	mu      sync.Mutex
	seals   []sealCall           // one entry per link ACTUALLY appended; an idempotent replay adds none
	byKey   map[string]shared.ID // (engagement, idempotency key) -> the id of the link sealed for it
	content map[string][]byte    // (engagement, idempotency key) -> the sealed content bytes
	n       int
	broken  bool
	sealErr error
}

// sealKey namespaces the idempotency key by engagement, mirroring the real chain: the key is unique only
// WITHIN an engagement, so the same detection id in two engagements seals two distinct links.
func sealKey(eng shared.ID, key string) string { return string(eng) + "\x00" + key }

// SealOnce models the real chain's idempotency contract: a repeated (engagement, key) returns the existing
// link and appends NOTHING new, so a test can prove a detection is sealed into the chain at most once.
func (c *fakeChain) SealOnce(_ context.Context, eng shared.ID, kind, key string, content []byte, by string) (shared.ID, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sealErr != nil {
		return "", c.sealErr
	}
	if c.byKey == nil {
		c.byKey = map[string]shared.ID{}
	}
	if c.content == nil {
		c.content = map[string][]byte{}
	}
	k := sealKey(eng, key)
	if id, ok := c.byKey[k]; ok {
		return id, nil // idempotent: same (engagement, key) -> same link, nothing appended
	}
	c.n++
	id := shared.ID("ev-" + itoa(c.n))
	c.byKey[k] = id
	c.content[k] = append([]byte(nil), content...)
	c.seals = append(c.seals, sealCall{eng, kind, by, key})
	return id, nil
}

// contentFor returns the sealed content bytes for (engagement, key), under the same lock.
func (c *fakeChain) contentFor(eng shared.ID, key string) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.content[sealKey(eng, key)]
}

// idFor returns the link id sealed for (engagement, key), read under the same lock that guards byKey, so a
// test can inspect it without racing a concurrent SealOnce.
func (c *fakeChain) idFor(eng shared.ID, key string) shared.ID {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.byKey[sealKey(eng, key)]
}
func (c *fakeChain) Verify(_ context.Context, _ shared.ID) error {
	if c.broken {
		return errors.New("evidence chain broken: item 2 tampered")
	}
	return nil
}
func (c *fakeChain) kinds() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.seals))
	for i, s := range c.seals {
		out[i] = s.kind
	}
	return out
}

type fakeKeys struct {
	byAgent map[shared.ID]fleetagent.AgentSigningKey
}

// ResolveSigningKey returns the key bound to (agentID, keyID), fail-closed: an unknown agent or a KeyID
// that does not match the agent's registered key resolves to an error, so the batch is refused.
func (k *fakeKeys) ResolveSigningKey(_ context.Context, agentID shared.ID, keyID string) (fleetagent.AgentSigningKey, error) {
	key, ok := k.byAgent[agentID]
	if !ok || key.KeyID != keyID {
		return fleetagent.AgentSigningKey{}, errors.New("unknown signing key")
	}
	return key, nil
}

type fakeAudit struct {
	mu         sync.Mutex
	actions    []string
	last       map[string]ports.AuditEntry
	failAction string // if set, Record returns an error for this action (and does not record it)
	keys       map[string]int
}

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failAction != "" && e.Action == a.failAction {
		return errors.New("audit store unavailable")
	}
	a.actions = append(a.actions, e.Action)
	if a.last == nil {
		a.last = map[string]ports.AuditEntry{}
	}
	a.last[e.Action] = e
	return nil
}

// RecordOnce collapses exact retries on the deterministic key so a caller that fails
// after a durable mutation can repair the missing audit line without duplicating it.
func (a *fakeAudit) RecordOnce(ctx context.Context, e ports.AuditEntry) error {
	key := e.Metadata["idempotency_key"]
	if key == "" {
		return a.Record(ctx, e)
	}
	a.mu.Lock()
	if a.failAction != "" && e.Action == a.failAction {
		a.mu.Unlock()
		return errors.New("audit store unavailable")
	}
	if a.keys == nil {
		a.keys = map[string]int{}
	}
	if a.keys[key] > 0 {
		a.mu.Unlock()
		return nil
	}
	a.keys[key]++
	a.mu.Unlock()
	return a.Record(ctx, e)
}

// recordedOnce reports how many distinct audit lines carried the given deterministic key.
func (a *fakeAudit) recordedOnce(key string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.keys[key]
}
func (a *fakeAudit) has(action string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, x := range a.actions {
		if x == action {
			return true
		}
	}
	return false
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type mutableClock struct{ now time.Time }

func (c *mutableClock) Now() time.Time { return c.now }

type seqIDs struct {
	mu sync.Mutex
	n  int
}

func (s *seqIDs) NewID() shared.ID {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return shared.ID("id-" + itoa(s.n))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// failingRecords wraps a real record store and fails the next N AppendDetection calls, to simulate a
// projection-write failure AFTER the seal has succeeded — the exact D3 crash window.
type failingRecords struct {
	ports.DetectionRecordStore
	mu         sync.Mutex
	failAppend int
}

type mutableTelemetryResolver struct {
	mu     sync.Mutex
	status ports.TelemetryReferenceStatus
	err    error
}

func (r *mutableTelemetryResolver) ResolveTelemetryReferences(_ context.Context, _ shared.ID, _ shared.ID, _ string, _ []fleetagent.TelemetryReference) (ports.TelemetryReferenceStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status, r.err
}

func (r *mutableTelemetryResolver) set(status ports.TelemetryReferenceStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = status
	r.err = nil
}

type failAfterSealChain struct {
	EvidenceChain
	mu       sync.Mutex
	failNext int
	sealedID shared.ID
}

func (c *failAfterSealChain) SealOnce(ctx context.Context, engagementID shared.ID, kind, idempotencyKey string, content []byte, createdBy string) (shared.ID, error) {
	id, err := c.EvidenceChain.SealOnce(ctx, engagementID, kind, idempotencyKey, content, createdBy)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sealedID = id
	if c.failNext > 0 {
		c.failNext--
		return "", errors.New("injected crash after evidence seal")
	}
	return id, nil
}

type failingProvenance struct {
	ports.DetectionProvenanceStore
	mu       sync.Mutex
	failKind detectionprovenance.TransitionKind
	failNext int
}

func (s *failingProvenance) AppendTransition(ctx context.Context, transition detectionprovenance.Transition) error {
	s.mu.Lock()
	if transition.Kind == s.failKind && s.failNext > 0 {
		s.failNext--
		s.mu.Unlock()
		return errors.New("injected provenance transition failure")
	}
	s.mu.Unlock()
	return s.DetectionProvenanceStore.AppendTransition(ctx, transition)
}

type failingExpiryRecords struct {
	ports.DetectionRecordStore
	mu         sync.Mutex
	failDelete int
}

func (s *failingExpiryRecords) DeleteDetection(ctx context.Context, engagementID, detectionID shared.ID) (bool, error) {
	s.mu.Lock()
	if s.failDelete > 0 {
		s.failDelete--
		s.mu.Unlock()
		return false, errors.New("injected projection deletion failure")
	}
	s.mu.Unlock()
	return s.DetectionRecordStore.DeleteDetection(ctx, engagementID, detectionID)
}

func (f *failingRecords) AppendDetection(ctx context.Context, r detection.Record) error {
	f.mu.Lock()
	if f.failAppend > 0 {
		f.failAppend--
		f.mu.Unlock()
		return errors.New("projection store unavailable")
	}
	f.mu.Unlock()
	return f.DetectionRecordStore.AppendDetection(ctx, r)
}

// ---- harness ----------------------------------------------------------------------------------------

type harness struct {
	svc   *Service
	chain *fakeChain
	audit *fakeAudit
	store *memory.DetectionRecordStore
	priv  ed25519.PrivateKey
	key   fleetagent.AgentSigningKey
}

// mkSigningKey mints a detection-batch signing key bound to agent whose validity window comfortably
// contains the harness clock (Unix 1000), so a well-formed batch verifies under the keyed lifecycle.
func mkSigningKey(t *testing.T, agent shared.ID, pub ed25519.PublicKey) fleetagent.AgentSigningKey {
	t.Helper()
	key, err := fleetagent.NewSigningKey(agent, fleetagent.PurposeDetectionBatch, pub, time.Unix(1, 0), time.Unix(1<<31, 0))
	if err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}
	return key
}

func newHarness(t *testing.T, retention time.Duration) *harness {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	chain := &fakeChain{}
	audit := &fakeAudit{}
	store := memory.NewDetectionRecordStore()
	key := mkSigningKey(t, "agent:1", pub)
	keys := &fakeKeys{byAgent: map[shared.ID]fleetagent.AgentSigningKey{"agent:1": key}}
	svc, err := NewService(store, chain, keys, audit, fixedClock{t: time.Unix(1000, 0)}, &seqIDs{}, retention)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{svc: svc, chain: chain, audit: audit, store: store, priv: priv, key: key}
}

func mkDetection(t *testing.T, comm string) detection.Detection {
	t.Helper()
	r, ok := detection.Lookup("det.process_enumeration")
	if !ok {
		t.Fatal("expected det.process_enumeration")
	}
	ev := detection.Event{Class: detection.ClassProcess, At: time.Unix(1, 0), Host: "h",
		Process: &detection.ProcessEvent{PID: 1, Comm: comm, Path: "/usr/bin/" + comm}}
	d, err := detection.NewDetection(r, "host-1", "agent:1", []detection.Event{ev}, time.Unix(500, 0))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func refsFor(t *testing.T, items []IngestItem) []fleetagent.DetectionRef {
	t.Helper()
	var refs []fleetagent.DetectionRef
	for _, it := range items {
		payload, err := json.Marshal(it.Detection)
		if err != nil {
			t.Fatal(err)
		}
		refs = append(refs, fleetagent.DetectionRef{ID: it.ID, ContentSHA256: fleetagent.DetectionContentHash(payload, it.AssetID)})
	}
	return refs
}

func (h *harness) signedBatch(t *testing.T, seq uint64, items []IngestItem) fleetagent.AgentBatch {
	t.Helper()
	b := fleetagent.AgentBatch{AgentID: "agent:1", EngagementID: "eng-1", Sequence: seq, KeyID: h.key.KeyID, Detections: refsFor(t, items)}
	b.Signature = fleetagent.SignBatch(h.priv, b)
	return b
}

func tctx() context.Context { return shared.WithTenant(context.Background(), "t1") }

// ---- tests ------------------------------------------------------------------------------------------

func TestIngestRejectsIdentityMismatch(t *testing.T) {
	h := newHarness(t, 0)
	items := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	batch := h.signedBatch(t, 1, items) // batch.AgentID == "agent:1"
	// A0.1 server-authoritative identity: a batch signed by a valid agent but ingested under a DIFFERENT
	// authenticated credential is refused BEFORE key resolution or sealing — no chain link, no projection.
	if _, err := h.svc.Ingest(tctx(), "agent:2", batch, items); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("identity mismatch must be forbidden, got %v", err)
	}
	if got := len(h.chain.seals); got != 0 {
		t.Fatalf("an identity-mismatched batch must seal nothing, got %d", got)
	}
	if recs, _ := h.store.ListDetections(tctx(), "eng-1"); len(recs) != 0 {
		t.Fatalf("an identity-mismatched batch must persist nothing, got %d rows", len(recs))
	}
	if !h.audit.has("detection.batch_rejected") {
		t.Error("an identity-mismatched batch must be audited as rejected")
	}
}

func TestIngestRejectionAuditFailureSurfaces(t *testing.T) {
	h := newHarness(t, 0)
	h.audit.failAction = "detection.batch_rejected"
	items := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	batch := h.signedBatch(t, 1, items)

	if _, err := h.svc.Ingest(tctx(), "agent:2", batch, items); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("rejection audit failure = %v, want saturated", err)
	}
	if got := len(h.chain.seals); got != 0 {
		t.Fatalf("rejection audit failure must seal nothing, got %d", got)
	}
}

func TestIngestSealsSelfContainedEvidenceEnvelope(t *testing.T) {
	h := newHarness(t, 0)
	items := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	if _, err := h.svc.Ingest(tctx(), "agent:1", h.signedBatch(t, 1, items), items); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	// A5 (#626): the sealed chain content must be a SELF-CONTAINED DetectionEvidenceEnvelope, decodable and
	// verifiable from the chain link ALONE (no projection read here) — exactly the property needed after the
	// expirable projection row is swept.
	content := h.chain.contentFor("eng-1", "d1")
	if len(content) == 0 {
		t.Fatal("no sealed content captured")
	}
	env, err := fleetagent.DecodeDetectionEvidenceEnvelope(content)
	if err != nil {
		t.Fatalf("sealed content must decode as an evidence envelope: %v", err)
	}
	if env.TenantID != "t1" || env.EngagementID != "eng-1" || env.AgentID != "agent:1" || env.AssetID != "asset-1" ||
		env.DetectionID != "d1" || env.BatchSequence != 1 || env.Provenance != fleetagent.ProvenanceComplete {
		t.Fatalf("envelope attribution wrong: %+v", env)
	}
	if err := env.VerifyContent(); err != nil {
		t.Fatalf("sealed envelope must self-verify against its commitment: %v", err)
	}
}

func TestIngestSealsEachDetectionAsChainedEvidence(t *testing.T) {
	h := newHarness(t, 0)
	items := []IngestItem{
		{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"},
		{ID: "d2", Detection: mkDetection(t, "top"), AssetID: "asset-1"},
	}
	res, err := h.svc.Ingest(tctx(), "agent:1", h.signedBatch(t, 1, items), items)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(res.SealedRecords) != 2 || len(res.EvidenceIDs) != 2 {
		t.Fatalf("both detections must be sealed, got %+v", res)
	}
	// BOUNDARY: every seal is kind="detection" — telemetry is never chained per event.
	for _, k := range h.chain.kinds() {
		if k != "detection" {
			t.Fatalf("only detections may be chained, got kind %q", k)
		}
	}
	if !h.audit.has("detection.batch_sealed") {
		t.Error("a sealed batch must be audited")
	}
	// The projection rows are stored with the evidence + asset binding.
	recs, _ := h.store.ListDetections(tctx(), "eng-1")
	if len(recs) != 2 {
		t.Fatalf("want 2 projection rows, got %d", len(recs))
	}
	for _, r := range recs {
		if r.EvidenceID == "" || r.AssetID != "asset-1" || r.BatchSeq != 1 {
			t.Fatalf("record missing evidence/asset/seq binding: %+v", r)
		}
	}
}

func TestIngestRefusesBadSignature(t *testing.T) {
	h := newHarness(t, 0)
	items := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	b := h.signedBatch(t, 1, items)
	b.Sequence = 99 // tamper a signed field AFTER signing → the signature no longer matches
	if _, err := h.svc.Ingest(tctx(), b.AgentID, b, items); !errors.Is(err, fleetagent.ErrBadBatchSignature) {
		t.Fatalf("a tampered batch must be refused, got %v", err)
	}
	if len(h.chain.kinds()) != 0 {
		t.Error("nothing may be sealed when the batch signature is bad")
	}
	if !h.audit.has("detection.batch_rejected") {
		t.Error("a rejected batch must be audited")
	}
}

// TestIngestRefusesContentTamper: a body swapped for a known, signed id (same id, different detection)
// is refused — the signature binds a digest of the content, not just the id.
func TestIngestRefusesContentTamper(t *testing.T) {
	h := newHarness(t, 0)
	signedItems := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	b := h.signedBatch(t, 1, signedItems) // signs a digest over the "ps" detection
	// Deliver the same id with a DIFFERENT body.
	swapped := []IngestItem{{ID: "d1", Detection: mkDetection(t, "top"), AssetID: "asset-1"}}
	if _, err := h.svc.Ingest(tctx(), b.AgentID, b, swapped); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a content swap must be refused, got %v", err)
	}
	if len(h.chain.kinds()) != 0 {
		t.Error("nothing may be sealed when the content does not match its signed digest")
	}
}

func TestIngestRefusesUnknownAgent(t *testing.T) {
	h := newHarness(t, 0)
	items := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	b := fleetagent.AgentBatch{AgentID: "agent:unknown", EngagementID: "eng-1", Sequence: 1, KeyID: h.key.KeyID, Detections: refsFor(t, items)}
	b.Signature = fleetagent.SignBatch(h.priv, b)
	if _, err := h.svc.Ingest(tctx(), b.AgentID, b, items); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("an agent with no known key must be refused (fail closed), got %v", err)
	}
}

func TestIngestReportsForwardGapButProceeds(t *testing.T) {
	h := newHarness(t, 0)
	// First batch seq 1.
	i1 := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	if _, err := h.svc.Ingest(tctx(), "agent:1", h.signedBatch(t, 1, i1), i1); err != nil {
		t.Fatal(err)
	}
	// Next batch jumps to seq 4 → sequences 2,3 are a gap.
	i2 := []IngestItem{{ID: "d4", Detection: mkDetection(t, "top"), AssetID: "asset-1"}}
	res, err := h.svc.Ingest(tctx(), "agent:1", h.signedBatch(t, 4, i2), i2)
	if err != nil {
		t.Fatalf("a forward gap must still seal the arriving batch: %v", err)
	}
	if res.Gap.Missing != 2 {
		t.Errorf("want 2 missing, got %+v", res.Gap)
	}
	if !h.audit.has("detection.batch_gap") {
		t.Error("a sequence gap must be reported as a potential loss (audited)")
	}
	if len(res.SealedRecords) != 1 {
		t.Error("the arriving batch's detections must still be sealed")
	}
}

// TestIngestIsIdempotentOnReplay: replaying a batch (same sequence + same signed membership) is reported
// as a gap/replay but seals NOTHING new — a detection is never sealed into the chain twice. This is the
// fix for a partial-batch retry: it safely completes rather than being permanently refused.
func TestIngestIsIdempotentOnReplay(t *testing.T) {
	h := newHarness(t, 0)
	i1 := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	b := h.signedBatch(t, 2, i1)
	if _, err := h.svc.Ingest(tctx(), b.AgentID, b, i1); err != nil {
		t.Fatal(err)
	}
	sealedBefore := len(h.chain.kinds())
	// Re-ingest the exact same batch: idempotent — no new seal, d1 skipped, replay reported.
	res, err := h.svc.Ingest(tctx(), b.AgentID, b, i1)
	if err != nil {
		t.Fatalf("an idempotent replay must not error, got %v", err)
	}
	if len(h.chain.kinds()) != sealedBefore {
		t.Error("a replayed detection must not be sealed into the chain twice")
	}
	if len(res.SealedRecords) != 0 || len(res.Skipped) != 1 {
		t.Errorf("a duplicate must seal nothing new and skip the already-sealed detection, got %+v", res)
	}
	if !res.Gap.Replay || !h.audit.has("detection.batch_gap") {
		t.Error("a replay must be reported as a gap, never silently accepted")
	}
}

func TestIngestSuccessAuditFailureExactRetryRepairsOneLine(t *testing.T) {
	h := newHarness(t, 0)
	h.audit.failAction = "detection.batch_sealed"
	items := []IngestItem{{ID: "d-audit-repair", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	batch := h.signedBatch(t, 1, items)

	if _, err := h.svc.Ingest(tctx(), batch.AgentID, batch, items); err == nil {
		t.Fatal("successful persistence with failed audit must return an error")
	}
	if recs, err := h.store.ListDetections(tctx(), batch.EngagementID); err != nil || len(recs) != 1 {
		t.Fatalf("durable detection after audit failure=%d err=%v, want one", len(recs), err)
	}

	h.audit.failAction = ""
	result, err := h.svc.Ingest(tctx(), batch.AgentID, batch, items)
	if err != nil {
		t.Fatalf("exact retry must repair the success audit: %v", err)
	}
	if len(result.SealedRecords) != 0 || len(result.Skipped) != 1 {
		t.Fatalf("audit repair retry result=%+v, want one skipped record", result)
	}
	key := detectionBatchAuditKey("detection.batch_sealed", batch.AgentID, batch.EngagementID, batch.Sequence)
	if got := h.audit.recordedOnce(key); got != 1 {
		t.Fatalf("repaired success audit lines=%d, want one", got)
	}
}

func TestIngestRequiresMembershipMatchAndTenant(t *testing.T) {
	h := newHarness(t, 0)
	items := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	// Membership mismatch: batch names d1+d2 but only d1 supplied.
	extra := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}, {ID: "d2", Detection: mkDetection(t, "top"), AssetID: "asset-1"}}
	b := fleetagent.AgentBatch{AgentID: "agent:1", EngagementID: "eng-1", Sequence: 1, KeyID: h.key.KeyID, Detections: refsFor(t, extra)}
	b.Signature = fleetagent.SignBatch(h.priv, b)
	if _, err := h.svc.Ingest(tctx(), b.AgentID, b, items); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("membership mismatch must be a validation error, got %v", err)
	}
	// Missing tenant in context.
	good := h.signedBatch(t, 1, items)
	if _, err := h.svc.Ingest(context.Background(), good.AgentID, good, items); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a missing tenant must be refused, got %v", err)
	}
}

// TestIngestFailsWhenGapAuditFails: a sequence gap must never be silently accepted — if its coverage
// event cannot be recorded, the whole ingest fails rather than admitting an unrecorded gap.
func TestIngestFailsWhenGapAuditFails(t *testing.T) {
	h := newHarness(t, 0)
	// Seed seq 1 so a jump to seq 5 is a forward gap.
	i1 := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	if _, err := h.svc.Ingest(tctx(), "agent:1", h.signedBatch(t, 1, i1), i1); err != nil {
		t.Fatal(err)
	}
	h.audit.failAction = "detection.batch_gap" // the gap coverage event cannot be written
	i2 := []IngestItem{{ID: "d5", Detection: mkDetection(t, "top"), AssetID: "asset-1"}}
	sealedBefore := len(h.chain.kinds())
	if _, err := h.svc.Ingest(tctx(), "agent:1", h.signedBatch(t, 5, i2), i2); err == nil {
		t.Fatal("an unrecordable gap must fail the ingest, not silently proceed")
	}
	if len(h.chain.kinds()) != sealedBefore {
		t.Error("nothing may be sealed when the gap could not be recorded")
	}
}

func TestVerifyChainBlocksOnBreak(t *testing.T) {
	h := newHarness(t, 0)
	if err := h.svc.VerifyChain(tctx(), "eng-1"); err != nil {
		t.Fatalf("an intact chain must verify: %v", err)
	}
	h.chain.broken = true
	if err := h.svc.VerifyChain(tctx(), "eng-1"); err == nil {
		t.Fatal("a broken chain must return an error so the dependent report is blocked")
	}
}

func TestIncidentsRollupFromLedger(t *testing.T) {
	h := newHarness(t, 0)
	items := []IngestItem{
		{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"},
		{ID: "d2", Detection: mkDetection(t, "ps"), AssetID: "asset-1"},
	}
	if _, err := h.svc.Ingest(tctx(), "agent:1", h.signedBatch(t, 1, items), items); err != nil {
		t.Fatal(err)
	}
	inc, err := h.svc.Incidents(tctx(), "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(inc) != 1 || inc[0].Count != 2 || len(inc[0].DetectionIDs) != 2 {
		t.Fatalf("rollup must fold repeats yet keep the underlying records, got %+v", inc)
	}
}

func TestExpireIsAuditedAndRequiresActorReason(t *testing.T) {
	h := newHarness(t, time.Hour) // records expire 1h after RecordedAt (clock = t=1000s)
	items := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	if _, err := h.svc.Ingest(tctx(), "agent:1", h.signedBatch(t, 1, items), items); err != nil {
		t.Fatal(err)
	}
	// Actor/reason required.
	if _, err := h.svc.Expire(tctx(), "eng-1", "  ", "policy"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expiry must require an actor, got %v", err)
	}
	if _, err := h.svc.Expire(tctx(), "eng-1", "operator", " "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expiry must require a reason, got %v", err)
	}
	// At t=1000s the record (ExpiresAt = 1000+3600) is not yet expired.
	if n, _ := h.svc.Expire(tctx(), "eng-1", "operator", "retention"); n != 0 {
		t.Fatalf("record not yet past retention should not expire, got %d", n)
	}
	// Advance the clock past the retention window and expire.
	h.svc.clock = fixedClock{t: time.Unix(1000+3601, 0)}
	n, err := h.svc.Expire(tctx(), "eng-1", "operator", "retention")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("the expired record must be removed, got %d", n)
	}
	if !h.audit.has("detection.expired") {
		t.Error("expiry must be audited (actor + reason), never silent")
	}
	if e := h.audit.last["detection.expired"]; e.Actor != "operator" || e.Metadata["reason"] != "retention" {
		t.Errorf("expiry audit must carry actor + reason, got %+v", e)
	}
}

// TestIngestNeverDoubleSealsAfterProjectionFailure proves the D3 fix (#610): sealing a detection into
// the permanent chain and writing its projection row are two stores with no shared transaction. If the
// projection write fails AFTER a successful seal, a retry finds no row (HasDetection is false) and, with
// a naive Seal, would append a SECOND chain link for the same detection. Because SealOnce is keyed on the
// detection id, the retry returns the first link instead — the detection is sealed exactly once.
// TestIngestSealsOnceThroughRealEvidenceServiceAcrossProjectionCrash supersedes the fake-backed D3 test
// (A5, #626): it runs the seal-then-projection-crash retry through the REAL evidence.Service.SealOnce
// (memory-backed vault, bridged as the ledger's chain), proving the production seal path itself leaves
// exactly ONE permanent chain link — and that the link is the self-contained envelope.
func TestIngestSealsOnceThroughRealEvidenceServiceAcrossProjectionCrash(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	audit := &fakeAudit{}
	clock := fixedClock{t: time.Unix(1000, 0)}
	ids := &seqIDs{}
	evSvc, err := evidenceuc.NewService(memory.NewEvidenceStore(), nil, audit, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := NewEvidenceChainBridge(
		func(ctx context.Context, eng shared.ID, kind, idem string, content []byte, by string) (shared.ID, error) {
			ev, serr := evSvc.SealOnce(ctx, eng, kind, idem, content, by)
			if serr != nil {
				return "", serr
			}
			return ev.ID, nil
		},
		func(ctx context.Context, eng shared.ID) error { return evSvc.VerifyChainError(ctx, eng) },
	)
	if err != nil {
		t.Fatal(err)
	}
	records := &failingRecords{DetectionRecordStore: memory.NewDetectionRecordStore(), failAppend: 1}
	key := mkSigningKey(t, "agent:1", pub)
	keys := &fakeKeys{byAgent: map[shared.ID]fleetagent.AgentSigningKey{"agent:1": key}}
	svc, err := NewService(records, bridge, keys, audit, clock, ids, 0)
	if err != nil {
		t.Fatal(err)
	}

	items := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	b := fleetagent.AgentBatch{AgentID: "agent:1", EngagementID: "eng-1", Sequence: 1, KeyID: key.KeyID, Detections: refsFor(t, items)}
	b.Signature = fleetagent.SignBatch(priv, b)

	// First ingest: the real seal succeeds, then the injected projection write fails.
	if _, err := svc.Ingest(tctx(), b.AgentID, b, items); err == nil {
		t.Fatal("expected the injected projection-write failure to surface")
	}
	// Retry the SAME batch through the real service (projection row still missing → HasDetection false).
	if _, err := svc.Ingest(tctx(), b.AgentID, b, items); err != nil {
		t.Fatalf("retry must complete: %v", err)
	}
	// D3: the real vault holds exactly ONE permanent detection link.
	links, err := evSvc.List(tctx(), "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 {
		t.Fatalf("D3: exactly one permanent chain link expected, got %d", len(links))
	}
	if links[0].Kind != evidenceKindDetection {
		t.Fatalf("the link must be kind=detection, got %q", links[0].Kind)
	}
	// The permanent link is the self-contained envelope and verifies on its own.
	env, err := fleetagent.DecodeDetectionEvidenceEnvelope(links[0].Content)
	if err != nil {
		t.Fatalf("permanent link must decode as an evidence envelope: %v", err)
	}
	if err := env.VerifyContent(); err != nil {
		t.Fatalf("permanent envelope must self-verify: %v", err)
	}
}

func TestIngestNeverDoubleSealsAfterProjectionFailure(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	chain := &fakeChain{}
	audit := &fakeAudit{}
	records := &failingRecords{DetectionRecordStore: memory.NewDetectionRecordStore(), failAppend: 1}
	key := mkSigningKey(t, "agent:1", pub)
	keys := &fakeKeys{byAgent: map[shared.ID]fleetagent.AgentSigningKey{"agent:1": key}}
	svc, err := NewService(records, chain, keys, audit, fixedClock{t: time.Unix(1000, 0)}, &seqIDs{}, 0)
	if err != nil {
		t.Fatal(err)
	}

	items := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	b := fleetagent.AgentBatch{AgentID: "agent:1", EngagementID: "eng-1", Sequence: 1, KeyID: key.KeyID, Detections: refsFor(t, items)}
	b.Signature = fleetagent.SignBatch(priv, b)

	// First ingest: the seal succeeds, then the injected projection-write failure surfaces.
	if _, err := svc.Ingest(tctx(), b.AgentID, b, items); err == nil {
		t.Fatal("expected the injected projection-write failure to surface")
	}
	if got := len(chain.kinds()); got != 1 {
		t.Fatalf("the detection must have been sealed exactly once before the crash, got %d", got)
	}
	if recs, _ := records.ListDetections(tctx(), "eng-1"); len(recs) != 0 {
		t.Fatalf("the projection write failed, so no row should exist yet, got %d", len(recs))
	}

	// Retry the SAME batch. The row is still missing (HasDetection is false), so a naive Seal would run
	// again — SealOnce must return the first link instead.
	res, err := svc.Ingest(tctx(), b.AgentID, b, items)
	if err != nil {
		t.Fatalf("the retry must complete the projection, got %v", err)
	}
	if got := len(chain.kinds()); got != 1 {
		t.Fatalf("D3: a detection must never be sealed into the chain twice, got %d links", got)
	}
	if len(res.SealedRecords) != 1 {
		t.Fatalf("the retry must complete the previously-unwritten projection row, got %+v", res)
	}
	recs, _ := records.ListDetections(tctx(), "eng-1")
	sealed := chain.idFor("eng-1", "d1")
	if len(recs) != 1 || recs[0].EvidenceID != sealed {
		t.Fatalf("the row must bind to the single sealed link %q, got %+v", sealed, recs)
	}
}

// TestIngestSealsSameDetectionIDInDistinctEngagements proves the seal namespace is per-engagement: the
// same detection id delivered under two different engagements is two distinct detections and must each be
// sealed — the engagement-scoped HasDetection skip must NOT suppress the second (the D3 cross-engagement
// loss/suppression vector). Both links are sealed and both projection rows are written.
func TestIngestSealsSameDetectionIDInDistinctEngagements(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	chain := &fakeChain{}
	audit := &fakeAudit{}
	records := memory.NewDetectionRecordStore()
	key := mkSigningKey(t, "agent:1", pub)
	keys := &fakeKeys{byAgent: map[shared.ID]fleetagent.AgentSigningKey{"agent:1": key}}
	svc, err := NewService(records, chain, keys, audit, fixedClock{t: time.Unix(1000, 0)}, &seqIDs{}, 0)
	if err != nil {
		t.Fatal(err)
	}

	items := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	for _, eng := range []shared.ID{"eng-1", "eng-2"} {
		b := fleetagent.AgentBatch{AgentID: "agent:1", EngagementID: eng, Sequence: 1, KeyID: key.KeyID, Detections: refsFor(t, items)}
		b.Signature = fleetagent.SignBatch(priv, b)
		res, err := svc.Ingest(tctx(), b.AgentID, b, items)
		if err != nil {
			t.Fatalf("ingest into %s: %v", eng, err)
		}
		if len(res.SealedRecords) != 1 || len(res.Skipped) != 0 {
			t.Fatalf("%s: the detection must be sealed, not skipped, got %+v", eng, res)
		}
	}
	if got := len(chain.kinds()); got != 2 {
		t.Fatalf("the same id in two engagements must seal two distinct links, got %d", got)
	}
	l1, l2 := chain.idFor("eng-1", "d1"), chain.idFor("eng-2", "d1")
	if l1 == "" || l2 == "" || l1 == l2 {
		t.Fatalf("each engagement must get its own link, got %q and %q", l1, l2)
	}
	// The projection must hold BOTH rows — one per engagement — each bound to its own sealed link. A
	// projection keyed on (tenant, id) alone would drop one of these silently; the (tenant, engagement,
	// id) key keeps them distinct. Assert per engagement so this test actually verifies the claim.
	r1, _ := records.ListDetections(tctx(), "eng-1")
	if len(r1) != 1 || r1[0].ID != "d1" || r1[0].EvidenceID != l1 {
		t.Fatalf("eng-1 must retain its own row bound to link %q, got %+v", l1, r1)
	}
	r2, _ := records.ListDetections(tctx(), "eng-2")
	if len(r2) != 1 || r2[0].ID != "d1" || r2[0].EvidenceID != l2 {
		t.Fatalf("eng-2 must retain its own row bound to link %q, got %+v", l2, r2)
	}
}

// TestIngestRefusesUnknownKeyID: the agent is known but the batch names a KeyID the resolver cannot
// resolve — fail closed (ErrForbidden), nothing sealed, and the rejection is audited.
func TestIngestRefusesUnknownKeyID(t *testing.T) {
	h := newHarness(t, 0)
	items := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	b := fleetagent.AgentBatch{AgentID: "agent:1", EngagementID: "eng-1", Sequence: 1, KeyID: "kid-does-not-exist", Detections: refsFor(t, items)}
	b.Signature = fleetagent.SignBatch(h.priv, b)
	if _, err := h.svc.Ingest(tctx(), b.AgentID, b, items); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("an unresolvable KeyID must be refused (fail closed), got %v", err)
	}
	if len(h.chain.kinds()) != 0 {
		t.Fatal("nothing may be sealed when the key does not resolve")
	}
	if !h.audit.has("detection.batch_rejected") {
		t.Error("an unknown-key rejection must be audited")
	}
}

// TestIngestRefusesRevokedKey: the batch is validly signed by a key that resolves, but the key is revoked
// at ingest time — VerifyBatchWithKey fails closed, so the batch is refused and nothing is sealed.
func TestIngestRefusesRevokedKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	chain := &fakeChain{}
	audit := &fakeAudit{}
	store := memory.NewDetectionRecordStore()
	key := mkSigningKey(t, "agent:1", pub)
	key.RevokedAt = time.Unix(500, 0) // revoked before the harness clock (Unix 1000)
	keys := &fakeKeys{byAgent: map[shared.ID]fleetagent.AgentSigningKey{"agent:1": key}}
	svc, err := NewService(store, chain, keys, audit, fixedClock{t: time.Unix(1000, 0)}, &seqIDs{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	items := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	b := fleetagent.AgentBatch{AgentID: "agent:1", EngagementID: "eng-1", Sequence: 1, KeyID: key.KeyID, Detections: refsFor(t, items)}
	b.Signature = fleetagent.SignBatch(priv, b)
	if _, err := svc.Ingest(tctx(), b.AgentID, b, items); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("a revoked key must fail closed, got %v", err)
	}
	if len(chain.kinds()) != 0 {
		t.Fatal("nothing may be sealed under a revoked key")
	}
	if !audit.has("detection.batch_rejected") {
		t.Error("a revoked-key rejection must be audited")
	}
}

func newV2Harness(t *testing.T, records ports.DetectionRecordStore, provenance ports.DetectionProvenanceStore, telemetry ports.TelemetryReferenceResolver, chain EvidenceChain, clock ports.Clock, ids ports.IDGenerator, retention time.Duration) (*Service, fleetagent.AgentSigningKey, ed25519.PrivateKey) {
	t.Helper()
	svc, key, priv, _ := newV2HarnessWithAudit(t, records, provenance, telemetry, chain, clock, ids, retention)
	return svc, key, priv
}

func newV2HarnessWithAudit(t *testing.T, records ports.DetectionRecordStore, provenance ports.DetectionProvenanceStore, telemetry ports.TelemetryReferenceResolver, chain EvidenceChain, clock ports.Clock, ids ports.IDGenerator, retention time.Duration) (*Service, fleetagent.AgentSigningKey, ed25519.PrivateKey, *fakeAudit) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key := mkSigningKey(t, "agent:1", pub)
	keys := &fakeKeys{byAgent: map[shared.ID]fleetagent.AgentSigningKey{"agent:1": key}}
	audit := &fakeAudit{}
	svc, err := NewServiceWithProvenance(records, provenance, telemetry, chain, keys, audit, clock, ids, retention)
	if err != nil {
		t.Fatal(err)
	}
	return svc, key, priv, audit
}

func TestIngestV2RejectionAuditFailureSurfaces(t *testing.T) {
	records := memory.NewDetectionRecordStore()
	svc, key, priv, audit := newV2HarnessWithAudit(t, records, memory.NewDetectionProvenanceStore(), &mutableTelemetryResolver{}, &fakeChain{}, fixedClock{t: time.Unix(1000, 0)}, &seqIDs{}, 0)
	audit.failAction = "detection.v2_batch_rejected"
	batch, items := signedV2Batch(t, priv, key)

	if _, err := svc.IngestV2(tctx(), "agent:2", batch, items); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("attributed rejection audit failure = %v, want saturated", err)
	}
	if recs, err := records.ListDetections(tctx(), batch.EngagementID); err != nil || len(recs) != 0 {
		t.Fatalf("attributed rejection audit failure persisted records=%d err=%v", len(recs), err)
	}
}

func signedV2Batch(t *testing.T, priv ed25519.PrivateKey, key fleetagent.AgentSigningKey) (fleetagent.AgentBatchV2, []fleetagent.DetectionBatchItemV2) {
	t.Helper()
	item := fleetagent.DetectionBatchItemV2{
		ID: "d-v2", Detection: mkDetection(t, "ps"), AssetID: "asset-1",
		TelemetryRefs:         []fleetagent.TelemetryReference{{StreamID: "stream-1", Epoch: 1, Sequence: 7, EventID: "event-7", Digest: strings.Repeat("a", 64)}},
		Rulepack:              fleetagent.RulepackReference{ID: "builtin", Version: 1, Digest: strings.Repeat("b", 64)},
		RedactionPolicyDigest: strings.Repeat("c", 64),
	}
	ref, err := item.Reference()
	if err != nil {
		t.Fatal(err)
	}
	batch := fleetagent.AgentBatchV2{Context: "synapse-agent-detection-batch:v2", Version: 2, AgentID: "agent:1", EngagementID: "eng-1", Sequence: 1, KeyID: key.KeyID, Detections: []fleetagent.DetectionRefV2{ref}}
	batch.Signature = fleetagent.SignBatchV2(priv, batch)
	return batch, []fleetagent.DetectionBatchItemV2{item}
}

func TestIngestV2SuccessAuditFailureExactRetryRepairsOneLine(t *testing.T) {
	records := memory.NewDetectionRecordStore()
	provenance := memory.NewDetectionProvenanceStore()
	telemetryResolver := &mutableTelemetryResolver{}
	chain := &fakeChain{}
	svc, key, priv, audit := newV2HarnessWithAudit(t, records, provenance, telemetryResolver, chain, fixedClock{t: time.Unix(1000, 0)}, &seqIDs{}, 0)
	batch, items := signedV2Batch(t, priv, key)
	telemetryResolver.set(ports.TelemetryReferencesDurable)
	audit.failAction = "detection.v2_batch_reconciled"

	if _, err := svc.IngestV2(tctx(), batch.AgentID, batch, items); err == nil {
		t.Fatal("successful attributed persistence with failed audit must return an error")
	}
	state, found, err := provenance.Current(tctx(), batch.EngagementID, items[0].ID)
	if err != nil || !found || state.Status != detectionprovenance.StatusComplete {
		t.Fatalf("durable attributed detection after audit failure=%#v found=%t err=%v", state, found, err)
	}

	audit.failAction = ""
	result, err := svc.IngestV2(tctx(), batch.AgentID, batch, items)
	if err != nil {
		t.Fatalf("exact attributed retry must repair the success audit: %v", err)
	}
	if len(result.SealedRecords) != 0 || len(result.Skipped) != 1 {
		t.Fatalf("attributed audit repair retry result=%+v, want one skipped record", result)
	}
	keyID := detectionBatchAuditKey("detection.v2_batch_reconciled", batch.AgentID, batch.EngagementID, batch.Sequence)
	if got := audit.recordedOnce(keyID); got != 1 {
		t.Fatalf("repaired attributed success audit lines=%d, want one", got)
	}
}

func provenanceKinds(t *testing.T, store ports.DetectionProvenanceStore) []detectionprovenance.TransitionKind {
	t.Helper()
	history, err := store.ListTransitions(tctx(), "eng-1", "d-v2")
	if err != nil {
		t.Fatal(err)
	}
	kinds := make([]detectionprovenance.TransitionKind, len(history))
	for i := range history {
		kinds[i] = history[i].Kind
	}
	return kinds
}

func requireProvenanceKinds(t *testing.T, store ports.DetectionProvenanceStore, want ...detectionprovenance.TransitionKind) {
	t.Helper()
	if got := provenanceKinds(t, store); !reflect.DeepEqual(got, want) {
		t.Fatalf("provenance kinds = %v, want %v", got, want)
	}
}

func realEvidenceChain(t *testing.T, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*evidenceuc.Service, EvidenceChain) {
	t.Helper()
	svc, err := evidenceuc.NewService(memory.NewEvidenceStore(), nil, audit, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := NewEvidenceChainBridge(
		func(ctx context.Context, engagementID shared.ID, kind, idempotencyKey string, content []byte, createdBy string) (shared.ID, error) {
			ev, sealErr := svc.SealOnce(ctx, engagementID, kind, idempotencyKey, content, createdBy)
			if sealErr != nil {
				return "", sealErr
			}
			return ev.ID, nil
		},
		func(ctx context.Context, engagementID shared.ID) error {
			return svc.VerifyChainError(ctx, engagementID)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return svc, bridge
}

func TestIngestV2MissingThenDelayedTelemetry(t *testing.T) {
	records := memory.NewDetectionRecordStore()
	provenance := memory.NewDetectionProvenanceStore()
	telemetry := &mutableTelemetryResolver{status: ports.TelemetryReferencesMissing}
	chain := &fakeChain{}
	svc, key, priv := newV2Harness(t, records, provenance, telemetry, chain, fixedClock{t: time.Unix(1000, 0)}, &seqIDs{}, 0)
	batch, items := signedV2Batch(t, priv, key)

	result, err := svc.IngestV2(tctx(), batch.AgentID, batch, items)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SealedRecords) != 0 || len(chain.kinds()) != 0 {
		t.Fatalf("missing telemetry must remain unsealed: %+v", result)
	}
	if exists, _ := records.HasDetection(tctx(), "eng-1", "d-v2"); exists {
		t.Fatal("missing telemetry must not create a detection projection")
	}
	requireProvenanceKinds(t, provenance, detectionprovenance.Received)

	telemetry.set(ports.TelemetryReferencesDurable)
	completed, err := svc.ReconcilePending(tctx(), "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	if completed != 1 || len(chain.kinds()) != 1 {
		t.Fatalf("delayed telemetry must complete exactly one detection: completed=%d links=%d", completed, len(chain.kinds()))
	}
	if exists, _ := records.HasDetection(tctx(), "eng-1", "d-v2"); !exists {
		t.Fatal("reconciliation must create the projection")
	}
	state, found, err := provenance.Current(tctx(), "eng-1", "d-v2")
	if err != nil || !found || state.Status != detectionprovenance.StatusComplete {
		t.Fatalf("provenance must be complete: %+v found=%t err=%v", state, found, err)
	}
	requireProvenanceKinds(t, provenance, detectionprovenance.Received, detectionprovenance.TelemetryDurable, detectionprovenance.CommitmentPending, detectionprovenance.CommitmentSealed, detectionprovenance.Acknowledged)
}

func TestIngestV2ContradictoryTelemetryBreaksProvenance(t *testing.T) {
	records := memory.NewDetectionRecordStore()
	provenance := memory.NewDetectionProvenanceStore()
	telemetry := &mutableTelemetryResolver{status: ports.TelemetryReferencesContradictory}
	chain := &fakeChain{}
	svc, key, priv := newV2Harness(t, records, provenance, telemetry, chain, fixedClock{t: time.Unix(1000, 0)}, &seqIDs{}, 0)
	batch, items := signedV2Batch(t, priv, key)

	if _, err := svc.IngestV2(tctx(), batch.AgentID, batch, items); err != nil {
		t.Fatal(err)
	}
	state, found, err := provenance.Current(tctx(), "eng-1", "d-v2")
	if err != nil || !found || state.Status != detectionprovenance.StatusBroken {
		t.Fatalf("contradictory telemetry must be broken: %+v found=%t err=%v", state, found, err)
	}
	if len(chain.kinds()) != 0 {
		t.Fatal("contradictory telemetry must not seal evidence")
	}
	if exists, _ := records.HasDetection(tctx(), "eng-1", "d-v2"); exists {
		t.Fatal("contradictory telemetry must not create a projection")
	}
	requireProvenanceKinds(t, provenance, detectionprovenance.Received, detectionprovenance.Broken)
}

func TestReconcileV2ReverifiesDurableSignature(t *testing.T) {
	records := memory.NewDetectionRecordStore()
	provenance := memory.NewDetectionProvenanceStore()
	telemetry := &mutableTelemetryResolver{status: ports.TelemetryReferencesMissing}
	chain := &fakeChain{}
	svc, key, priv := newV2Harness(t, records, provenance, telemetry, chain, fixedClock{t: time.Unix(1000, 0)}, &seqIDs{}, 0)
	batch, items := signedV2Batch(t, priv, key)

	if _, err := svc.IngestV2(tctx(), batch.AgentID, batch, items); err != nil {
		t.Fatal(err)
	}
	key.PublicKey = append(ed25519.PublicKey(nil), key.PublicKey...)
	key.PublicKey[0] ^= 0xff
	svc.keys = &fakeKeys{byAgent: map[shared.ID]fleetagent.AgentSigningKey{batch.AgentID: key}}
	telemetry.set(ports.TelemetryReferencesDurable)

	completed, err := svc.ReconcilePending(tctx(), batch.EngagementID)
	if err != nil {
		t.Fatal(err)
	}
	if completed != 0 || len(chain.kinds()) != 0 {
		t.Fatalf("invalid durable signature must not complete or seal: completed=%d links=%d", completed, len(chain.kinds()))
	}
	state, found, err := provenance.Current(tctx(), batch.EngagementID, items[0].ID)
	if err != nil || !found || state.Status != detectionprovenance.StatusBroken {
		t.Fatalf("invalid durable signature must break provenance: %+v found=%t err=%v", state, found, err)
	}
	if exists, _ := records.HasDetection(tctx(), batch.EngagementID, items[0].ID); exists {
		t.Fatal("invalid durable signature must not create a projection")
	}
	requireProvenanceKinds(t, provenance, detectionprovenance.Received, detectionprovenance.Broken)
}

func TestIngestV2CrashAfterActualSealRetriesSameEvidence(t *testing.T) {
	clock := fixedClock{t: time.Unix(1000, 0)}
	ids := &seqIDs{}
	audit := &fakeAudit{}
	evidenceService, bridge := realEvidenceChain(t, audit, clock, ids)
	crashing := &failAfterSealChain{EvidenceChain: bridge, failNext: 1}
	records := memory.NewDetectionRecordStore()
	provenance := memory.NewDetectionProvenanceStore()
	telemetry := &mutableTelemetryResolver{status: ports.TelemetryReferencesDurable}
	svc, key, priv := newV2Harness(t, records, provenance, telemetry, crashing, clock, ids, 0)
	batch, items := signedV2Batch(t, priv, key)

	if _, err := svc.IngestV2(tctx(), batch.AgentID, batch, items); err == nil {
		t.Fatal("expected injected post-seal crash")
	}
	firstID := crashing.sealedID
	if firstID.IsZero() {
		t.Fatal("underlying evidence seal must succeed before the injected crash")
	}
	requireProvenanceKinds(t, provenance, detectionprovenance.Received, detectionprovenance.TelemetryDurable, detectionprovenance.CommitmentPending)

	completed, err := svc.ReconcilePending(tctx(), "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	if completed != 1 {
		t.Fatalf("retry completed %d detections, want 1", completed)
	}
	links, err := evidenceService.List(tctx(), "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].ID != firstID {
		t.Fatalf("post-seal retry must reuse evidence %q exactly once, got %+v", firstID, links)
	}
	state, found, err := provenance.Current(tctx(), "eng-1", "d-v2")
	if err != nil || !found || state.EvidenceID != firstID || state.Status != detectionprovenance.StatusComplete {
		t.Fatalf("retry must converge on first evidence identity: %+v found=%t err=%v", state, found, err)
	}
	requireProvenanceKinds(t, provenance, detectionprovenance.Received, detectionprovenance.TelemetryDurable, detectionprovenance.CommitmentPending, detectionprovenance.CommitmentSealed, detectionprovenance.Acknowledged)
}

func TestIngestV2ProjectionFailureAfterSealRecovers(t *testing.T) {
	baseRecords := memory.NewDetectionRecordStore()
	records := &failingRecords{DetectionRecordStore: baseRecords, failAppend: 1}
	provenance := memory.NewDetectionProvenanceStore()
	telemetry := &mutableTelemetryResolver{status: ports.TelemetryReferencesDurable}
	chain := &fakeChain{}
	svc, key, priv := newV2Harness(t, records, provenance, telemetry, chain, fixedClock{t: time.Unix(1000, 0)}, &seqIDs{}, 0)
	batch, items := signedV2Batch(t, priv, key)

	if _, err := svc.IngestV2(tctx(), batch.AgentID, batch, items); err == nil {
		t.Fatal("expected injected projection failure")
	}
	if exists, _ := baseRecords.HasDetection(tctx(), "eng-1", "d-v2"); exists {
		t.Fatal("failed projection write must leave no row")
	}
	if len(chain.kinds()) != 1 {
		t.Fatal("evidence must already be sealed exactly once")
	}
	requireProvenanceKinds(t, provenance, detectionprovenance.Received, detectionprovenance.TelemetryDurable, detectionprovenance.CommitmentPending, detectionprovenance.CommitmentSealed)

	if completed, err := svc.ReconcilePending(tctx(), "eng-1"); err != nil || completed != 1 {
		t.Fatalf("projection retry must complete: completed=%d err=%v", completed, err)
	}
	if len(chain.kinds()) != 1 {
		t.Fatal("projection retry must not reseal evidence")
	}
	if exists, _ := baseRecords.HasDetection(tctx(), "eng-1", "d-v2"); !exists {
		t.Fatal("projection retry must create the row")
	}
	requireProvenanceKinds(t, provenance, detectionprovenance.Received, detectionprovenance.TelemetryDurable, detectionprovenance.CommitmentPending, detectionprovenance.CommitmentSealed, detectionprovenance.Acknowledged)
}

func TestIngestV2AcknowledgementFailureAppendsOnlyMissingTransition(t *testing.T) {
	records := memory.NewDetectionRecordStore()
	baseProvenance := memory.NewDetectionProvenanceStore()
	provenance := &failingProvenance{DetectionProvenanceStore: baseProvenance, failKind: detectionprovenance.Acknowledged, failNext: 1}
	telemetry := &mutableTelemetryResolver{status: ports.TelemetryReferencesDurable}
	chain := &fakeChain{}
	svc, key, priv := newV2Harness(t, records, provenance, telemetry, chain, fixedClock{t: time.Unix(1000, 0)}, &seqIDs{}, 0)
	batch, items := signedV2Batch(t, priv, key)

	if _, err := svc.IngestV2(tctx(), batch.AgentID, batch, items); err == nil {
		t.Fatal("expected injected acknowledgement persistence failure")
	}
	if exists, _ := records.HasDetection(tctx(), "eng-1", "d-v2"); !exists {
		t.Fatal("projection must exist before acknowledgement")
	}
	if len(chain.kinds()) != 1 {
		t.Fatal("evidence must be sealed once before acknowledgement")
	}
	requireProvenanceKinds(t, baseProvenance, detectionprovenance.Received, detectionprovenance.TelemetryDurable, detectionprovenance.CommitmentPending, detectionprovenance.CommitmentSealed)

	if completed, err := svc.ReconcilePending(tctx(), "eng-1"); err != nil || completed != 1 {
		t.Fatalf("acknowledgement retry must complete: completed=%d err=%v", completed, err)
	}
	if len(chain.kinds()) != 1 {
		t.Fatal("acknowledgement retry must not reseal evidence")
	}
	requireProvenanceKinds(t, baseProvenance, detectionprovenance.Received, detectionprovenance.TelemetryDurable, detectionprovenance.CommitmentPending, detectionprovenance.CommitmentSealed, detectionprovenance.Acknowledged)
}

func TestExpireV2TombstoneFailureDeletesNoProjection(t *testing.T) {
	clock := &mutableClock{now: time.Unix(1000, 0)}
	records := memory.NewDetectionRecordStore()
	baseProvenance := memory.NewDetectionProvenanceStore()
	provenance := &failingProvenance{DetectionProvenanceStore: baseProvenance, failKind: detectionprovenance.Expired, failNext: 1}
	telemetry := &mutableTelemetryResolver{status: ports.TelemetryReferencesDurable}
	chain := &fakeChain{}
	svc, key, priv := newV2Harness(t, records, provenance, telemetry, chain, clock, &seqIDs{}, time.Nanosecond)
	batch, items := signedV2Batch(t, priv, key)
	if _, err := svc.IngestV2(tctx(), batch.AgentID, batch, items); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(time.Second)

	if _, err := svc.Expire(tctx(), "eng-1", "operator", "retention"); err == nil {
		t.Fatal("expected injected tombstone failure")
	}
	if exists, _ := records.HasDetection(tctx(), "eng-1", "d-v2"); !exists {
		t.Fatal("tombstone failure must not delete the projection")
	}
	requireProvenanceKinds(t, baseProvenance, detectionprovenance.Received, detectionprovenance.TelemetryDurable, detectionprovenance.CommitmentPending, detectionprovenance.CommitmentSealed, detectionprovenance.Acknowledged)
}

func TestExpireV2DeletionFailureAfterTombstoneIsResumable(t *testing.T) {
	clock := &mutableClock{now: time.Unix(1000, 0)}
	baseRecords := memory.NewDetectionRecordStore()
	records := &failingExpiryRecords{DetectionRecordStore: baseRecords, failDelete: 1}
	provenance := memory.NewDetectionProvenanceStore()
	telemetry := &mutableTelemetryResolver{status: ports.TelemetryReferencesDurable}
	chain := &fakeChain{}
	svc, key, priv := newV2Harness(t, records, provenance, telemetry, chain, clock, &seqIDs{}, time.Nanosecond)
	batch, items := signedV2Batch(t, priv, key)
	if _, err := svc.IngestV2(tctx(), batch.AgentID, batch, items); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(time.Second)

	if _, err := svc.Expire(tctx(), "eng-1", "operator", "retention"); err == nil {
		t.Fatal("expected injected deletion failure")
	}
	if exists, _ := baseRecords.HasDetection(tctx(), "eng-1", "d-v2"); !exists {
		t.Fatal("failed deletion must leave the projection resumable")
	}
	requireProvenanceKinds(t, provenance, detectionprovenance.Received, detectionprovenance.TelemetryDurable, detectionprovenance.CommitmentPending, detectionprovenance.CommitmentSealed, detectionprovenance.Acknowledged, detectionprovenance.Expired)

	deleted, err := svc.Expire(tctx(), "eng-1", "operator", "retention retry")
	if err != nil || deleted != 1 {
		t.Fatalf("expiry retry must delete the projection: deleted=%d err=%v", deleted, err)
	}
	if exists, _ := baseRecords.HasDetection(tctx(), "eng-1", "d-v2"); exists {
		t.Fatal("expiry retry must delete the projection")
	}
	state, found, err := provenance.Current(tctx(), "eng-1", "d-v2")
	if err != nil || !found || state.Status != detectionprovenance.StatusExpired || state.EvidenceID.IsZero() {
		t.Fatalf("expired provenance and evidence identity must remain queryable: %+v found=%t err=%v", state, found, err)
	}
	requireProvenanceKinds(t, provenance, detectionprovenance.Received, detectionprovenance.TelemetryDurable, detectionprovenance.CommitmentPending, detectionprovenance.CommitmentSealed, detectionprovenance.Acknowledged, detectionprovenance.Expired)
}

// TestExpireAuditFailureDeletesNoProjection proves the actor/reason attribution for expiry is
// mandatory: the audit line is the ONLY record of WHO expired the projections and WHY, so an audit
// outage must stop the deletion rather than leave unattributable data loss. The retry then repairs
// the audit and completes the expiry, writing exactly one line for that expiry set.
func TestExpiryAuditKeyBindsActorReasonAndSet(t *testing.T) {
	ids := []shared.ID{"d2", "d1"}
	base := expiryAuditKey("eng-1", ids, "operator", "retention")
	if got := expiryAuditKey("eng-1", []shared.ID{"d1", "d2"}, "operator", "retention"); got != base {
		t.Fatalf("same expiry operation in another set order changed identity: %q != %q", got, base)
	}
	if got := expiryAuditKey("eng-1", ids, "other-operator", "retention"); got == base {
		t.Fatal("expiry operation identity did not bind actor")
	}
	if got := expiryAuditKey("eng-1", ids, "operator", "manual cleanup"); got == base {
		t.Fatal("expiry operation identity did not bind reason")
	}
}

func TestExpireAuditFailureDeletesNoProjection(t *testing.T) {
	h := newHarness(t, time.Nanosecond)
	items := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	if _, err := h.svc.Ingest(tctx(), "agent:1", h.signedBatch(t, 1, items), items); err != nil {
		t.Fatal(err)
	}
	h.svc.clock = fixedClock{t: time.Unix(2000, 0)}

	h.audit.failAction = "detection.expired"
	if _, err := h.svc.Expire(tctx(), "eng-1", "operator", "retention"); err == nil {
		t.Fatal("an unrecordable expiry audit must fail the expiry, not silently delete the projection")
	}
	if exists, _ := h.store.HasDetection(tctx(), "eng-1", "d1"); !exists {
		t.Fatal("no projection may be deleted while the actor/reason audit is not durable")
	}

	h.audit.failAction = ""
	deleted, err := h.svc.Expire(tctx(), "eng-1", "operator", "retention")
	if err != nil || deleted != 1 {
		t.Fatalf("expiry retry must repair the audit and delete: deleted=%d err=%v", deleted, err)
	}
	key := expiryAuditKey("eng-1", []shared.ID{"d1"}, "operator", "retention")
	if got := h.audit.recordedOnce(key); got != 1 {
		t.Fatalf("repaired expiry audit lines = %d, want exactly 1", got)
	}
	if e := h.audit.last["detection.expired"]; e.Actor != "operator" || e.Metadata["reason"] != "retention" {
		t.Fatalf("expiry audit must carry actor + reason, got %+v", e)
	}
}
