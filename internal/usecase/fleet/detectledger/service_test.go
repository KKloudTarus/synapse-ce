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
	key        string
}

type fakeChain struct {
	mu      sync.Mutex
	seals   []sealCall           // one entry per link ACTUALLY appended; an idempotent replay adds none
	byKey   map[string]shared.ID // (engagement, idempotency key) -> the id of the link sealed for it
	n       int
	broken  bool
	sealErr error
}

// sealKey namespaces the idempotency key by engagement, mirroring the real chain: the key is unique only
// WITHIN an engagement, so the same detection id in two engagements seals two distinct links.
func sealKey(eng shared.ID, key string) string { return string(eng) + "\x00" + key }

// SealOnce models the real chain's idempotency contract: a repeated (engagement, key) returns the existing
// link and appends NOTHING new, so a test can prove a detection is sealed into the chain at most once.
func (c *fakeChain) SealOnce(_ context.Context, eng shared.ID, kind, key string, _ []byte, by string) (shared.ID, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sealErr != nil {
		return "", c.sealErr
	}
	if c.byKey == nil {
		c.byKey = map[string]shared.ID{}
	}
	k := sealKey(eng, key)
	if id, ok := c.byKey[k]; ok {
		return id, nil // idempotent: same (engagement, key) -> same link, nothing appended
	}
	c.n++
	id := shared.ID("ev-" + itoa(c.n))
	c.byKey[k] = id
	c.seals = append(c.seals, sealCall{eng, kind, by, key})
	return id, nil
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

// failingRecords wraps a real record store and fails the next N AppendDetection calls, to simulate a
// projection-write failure AFTER the seal has succeeded — the exact D3 crash window.
type failingRecords struct {
	ports.DetectionRecordStore
	mu         sync.Mutex
	failAppend int
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

// TestIngestNeverDoubleSealsAfterProjectionFailure proves the D3 fix (#610): sealing a detection into
// the permanent chain and writing its projection row are two stores with no shared transaction. If the
// projection write fails AFTER a successful seal, a retry finds no row (HasDetection is false) and, with
// a naive Seal, would append a SECOND chain link for the same detection. Because SealOnce is keyed on the
// detection id, the retry returns the first link instead — the detection is sealed exactly once.
func TestIngestNeverDoubleSealsAfterProjectionFailure(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	chain := &fakeChain{}
	audit := &fakeAudit{}
	records := &failingRecords{DetectionRecordStore: memory.NewDetectionRecordStore(), failAppend: 1}
	keys := &fakeKeys{pub: pub, known: map[shared.ID]bool{"agent:1": true}}
	svc, err := NewService(records, chain, keys, audit, fixedClock{t: time.Unix(1000, 0)}, &seqIDs{}, 0)
	if err != nil {
		t.Fatal(err)
	}

	items := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	b := fleetagent.AgentBatch{AgentID: "agent:1", EngagementID: "eng-1", Sequence: 1, Detections: refsFor(t, items)}
	b.Signature = fleetagent.SignBatch(priv, b)

	// First ingest: the seal succeeds, then the injected projection-write failure surfaces.
	if _, err := svc.Ingest(tctx(), b, items); err == nil {
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
	res, err := svc.Ingest(tctx(), b, items)
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
	keys := &fakeKeys{pub: pub, known: map[shared.ID]bool{"agent:1": true}}
	svc, err := NewService(records, chain, keys, audit, fixedClock{t: time.Unix(1000, 0)}, &seqIDs{}, 0)
	if err != nil {
		t.Fatal(err)
	}

	items := []IngestItem{{ID: "d1", Detection: mkDetection(t, "ps"), AssetID: "asset-1"}}
	for _, eng := range []shared.ID{"eng-1", "eng-2"} {
		b := fleetagent.AgentBatch{AgentID: "agent:1", EngagementID: eng, Sequence: 1, Detections: refsFor(t, items)}
		b.Signature = fleetagent.SignBatch(priv, b)
		res, err := svc.Ingest(tctx(), b, items)
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
