package detectledger

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
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ---- fakes ------------------------------------------------------------------------------------------

type sealCall struct {
	engagement shared.ID
	kind       string
	createdBy  string
}

type fakeChain struct {
	mu      sync.Mutex
	seals   []sealCall
	n       int
	broken  bool
	sealErr error
}

func (c *fakeChain) Seal(_ context.Context, eng shared.ID, kind string, _ []byte, by string) (shared.ID, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sealErr != nil {
		return "", c.sealErr
	}
	c.seals = append(c.seals, sealCall{eng, kind, by})
	c.n++
	return shared.ID("ev-" + itoa(c.n)), nil
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
	pub   ed25519.PublicKey
	known map[shared.ID]bool
}

func (k *fakeKeys) AgentPublicKey(_ context.Context, id shared.ID) (ed25519.PublicKey, error) {
	if k.known[id] {
		return k.pub, nil
	}
	return nil, errors.New("unknown agent")
}

type fakeAudit struct {
	mu         sync.Mutex
	actions    []string
	last       map[string]ports.AuditEntry
	failAction string // if set, Record returns an error for this action (and does not record it)
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

// ---- harness ----------------------------------------------------------------------------------------

type harness struct {
	svc   *Service
	chain *fakeChain
	audit *fakeAudit
	store *memory.DetectionRecordStore
	priv  ed25519.PrivateKey
}

func newHarness(t *testing.T, retention time.Duration) *harness {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	chain := &fakeChain{}
	audit := &fakeAudit{}
	store := memory.NewDetectionRecordStore()
	keys := &fakeKeys{pub: pub, known: map[shared.ID]bool{"agent:1": true}}
	svc, err := NewService(store, chain, keys, audit, fixedClock{t: time.Unix(1000, 0)}, &seqIDs{}, retention)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{svc: svc, chain: chain, audit: audit, store: store, priv: priv}
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
	b := fleetagent.AgentBatch{AgentID: "agent:1", EngagementID: "eng-1", Sequence: seq, Detections: refsFor(t, items)}
	b.Signature = fleetagent.SignBatch(h.priv, b)
	return b
}

func tctx() context.Context { return shared.WithTenant(context.Background(), "t1") }

// ---- tests ------------------------------------------------------------------------------------------

func TestIngestSealsEachDetectionAsChainedEvidence(t *testing.T) {
	h := newHarness(t, 0)
	items := []IngestItem{
		{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"},
		{ID: "d2", Detection: mkDetection(t, "top"), AssetID: "asset-1"},
	}
	res, err := h.svc.Ingest(tctx(), h.signedBatch(t, 1, items), items)
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
	if _, err := h.svc.Ingest(tctx(), b, items); !errors.Is(err, fleetagent.ErrBadBatchSignature) {
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
	if _, err := h.svc.Ingest(tctx(), b, swapped); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a content swap must be refused, got %v", err)
	}
	if len(h.chain.kinds()) != 0 {
		t.Error("nothing may be sealed when the content does not match its signed digest")
	}
}

func TestIngestRefusesUnknownAgent(t *testing.T) {
	h := newHarness(t, 0)
	items := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	b := fleetagent.AgentBatch{AgentID: "agent:unknown", EngagementID: "eng-1", Sequence: 1, Detections: refsFor(t, items)}
	b.Signature = fleetagent.SignBatch(h.priv, b)
	if _, err := h.svc.Ingest(tctx(), b, items); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("an agent with no known key must be refused (fail closed), got %v", err)
	}
}

func TestIngestReportsForwardGapButProceeds(t *testing.T) {
	h := newHarness(t, 0)
	// First batch seq 1.
	i1 := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	if _, err := h.svc.Ingest(tctx(), h.signedBatch(t, 1, i1), i1); err != nil {
		t.Fatal(err)
	}
	// Next batch jumps to seq 4 → sequences 2,3 are a gap.
	i2 := []IngestItem{{ID: "d4", Detection: mkDetection(t, "top"), AssetID: "asset-1"}}
	res, err := h.svc.Ingest(tctx(), h.signedBatch(t, 4, i2), i2)
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
	if _, err := h.svc.Ingest(tctx(), b, i1); err != nil {
		t.Fatal(err)
	}
	sealedBefore := len(h.chain.kinds())
	// Re-ingest the exact same batch: idempotent — no new seal, d1 skipped, replay reported.
	res, err := h.svc.Ingest(tctx(), b, i1)
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

func TestIngestRequiresMembershipMatchAndTenant(t *testing.T) {
	h := newHarness(t, 0)
	items := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	// Membership mismatch: batch names d1+d2 but only d1 supplied.
	extra := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}, {ID: "d2", Detection: mkDetection(t, "top"), AssetID: "asset-1"}}
	b := fleetagent.AgentBatch{AgentID: "agent:1", EngagementID: "eng-1", Sequence: 1, Detections: refsFor(t, extra)}
	b.Signature = fleetagent.SignBatch(h.priv, b)
	if _, err := h.svc.Ingest(tctx(), b, items); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("membership mismatch must be a validation error, got %v", err)
	}
	// Missing tenant in context.
	good := h.signedBatch(t, 1, items)
	if _, err := h.svc.Ingest(context.Background(), good, items); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a missing tenant must be refused, got %v", err)
	}
}

// TestIngestFailsWhenGapAuditFails: a sequence gap must never be silently accepted — if its coverage
// event cannot be recorded, the whole ingest fails rather than admitting an unrecorded gap.
func TestIngestFailsWhenGapAuditFails(t *testing.T) {
	h := newHarness(t, 0)
	// Seed seq 1 so a jump to seq 5 is a forward gap.
	i1 := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	if _, err := h.svc.Ingest(tctx(), h.signedBatch(t, 1, i1), i1); err != nil {
		t.Fatal(err)
	}
	h.audit.failAction = "detection.batch_gap" // the gap coverage event cannot be written
	i2 := []IngestItem{{ID: "d5", Detection: mkDetection(t, "top"), AssetID: "asset-1"}}
	sealedBefore := len(h.chain.kinds())
	if _, err := h.svc.Ingest(tctx(), h.signedBatch(t, 5, i2), i2); err == nil {
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
	if _, err := h.svc.Ingest(tctx(), h.signedBatch(t, 1, items), items); err != nil {
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
	if _, err := h.svc.Ingest(tctx(), h.signedBatch(t, 1, items), items); err != nil {
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
