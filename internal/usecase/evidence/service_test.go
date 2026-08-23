package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// --- fakes ---

type memStore struct {
	items map[shared.ID][]evdom.Evidence
}

func newMemStore() *memStore { return &memStore{items: map[shared.ID][]evdom.Evidence{}} }
func (s *memStore) Append(_ context.Context, items []evdom.Evidence) error {
	for _, e := range items {
		s.items[e.EngagementID] = append(s.items[e.EngagementID], e)
	}
	return nil
}
func (s *memStore) ListByEngagement(_ context.Context, id shared.ID) ([]evdom.Evidence, error) {
	out := make([]evdom.Evidence, len(s.items[id]))
	copy(out, s.items[id])
	return out, nil
}
func (s *memStore) Head(_ context.Context, id shared.ID) (string, error) {
	c := s.items[id]
	if len(c) == 0 {
		return "", nil
	}
	return c[len(c)-1].Hash, nil
}

func (s *memStore) LookupSealedForFinding(_ context.Context, engagementID, findingID shared.ID, kind string) (evdom.Evidence, bool, error) {
	chain := s.items[engagementID]
	for i := len(chain) - 1; i >= 0; i-- {
		e := chain[i]
		if e.FindingID == findingID && e.Kind == kind {
			return e, true, nil
		}
	}
	return evdom.Evidence{}, false, nil
}

type concurrentEvidenceStore struct {
	mu      sync.Mutex
	items   map[shared.ID][]evdom.Evidence
	tenants map[shared.ID]shared.ID
}

func newConcurrentEvidenceStore() *concurrentEvidenceStore {
	return &concurrentEvidenceStore{items: map[shared.ID][]evdom.Evidence{}, tenants: map[shared.ID]shared.ID{}}
}
func (s *concurrentEvidenceStore) Append(ctx context.Context, items []evdom.Evidence) error {
	tenant, _ := shared.TenantFrom(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range items {
		if existing, ok := s.tenants[e.EngagementID]; ok && existing != tenant {
			return shared.ErrNotFound
		}
		if list := s.items[e.EngagementID]; len(list) > 0 && e.PreviousHash != list[len(list)-1].Hash {
			return shared.ErrConflict
		}
		s.tenants[e.EngagementID] = tenant
		s.items[e.EngagementID] = append(s.items[e.EngagementID], e)
	}
	return nil
}
func (s *concurrentEvidenceStore) ListByEngagement(ctx context.Context, id shared.ID) ([]evdom.Evidence, error) {
	tenant, _ := shared.TenantFrom(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.tenants[id]; ok && existing != tenant {
		return nil, shared.ErrNotFound
	}
	return append([]evdom.Evidence(nil), s.items[id]...), nil
}
func (s *concurrentEvidenceStore) Head(ctx context.Context, id shared.ID) (string, error) {
	items, err := s.ListByEngagement(ctx, id)
	if err != nil {
		return "", err
	}
	if len(items) == 0 {
		return "", nil
	}
	return items[len(items)-1].Hash, nil
}

type randomTestIDs struct {
	mu sync.Mutex
	n  int64
}

func (g *randomTestIDs) NewID() shared.ID {
	// Guarded: TestSealConcurrentStaysLinear calls Seal (and thus NewID) from multiple goroutines, so an
	// unsynchronized counter is a data race under -race (pre-existing; a real ports.IDGenerator is safe).
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	return shared.ID("test-" + strconv.FormatInt(g.n, 10))
}

type memBlobs struct{ m map[string][]byte }

func newMemBlobs() *memBlobs { return &memBlobs{m: map[string][]byte{}} }
func (b *memBlobs) Put(_ context.Context, key string, data []byte) error {
	cp := make([]byte, len(data))
	copy(cp, data)
	b.m[key] = cp
	return nil
}
func (b *memBlobs) Get(_ context.Context, key string) ([]byte, error) {
	d, ok := b.m[key]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return d, nil
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type seqIDs struct{ n int }

func (g *seqIDs) NewID() shared.ID { g.n++; return shared.ID("ev-" + strconv.Itoa(g.n)) }

type capAudit struct{ entries []ports.AuditEntry }

func (a *capAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}
func (a *capAudit) has(action string) bool {
	for _, e := range a.entries {
		if e.Action == action {
			return true
		}
	}
	return false
}

func newVault(t *testing.T, blobs ports.BlobStore) (*Service, *memStore, *capAudit) {
	t.Helper()
	store := newMemStore()
	audit := &capAudit{}
	svc, err := NewService(store, blobs, audit, fixedClock{t: time.Unix(1000, 0).UTC()}, &seqIDs{})
	if err != nil {
		t.Fatal(err)
	}
	return svc, store, audit
}

func TestNewServiceValidates(t *testing.T) {
	if _, err := NewService(nil, nil, &capAudit{}, fixedClock{}, &seqIDs{}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("nil store: want ErrValidation, got %v", err)
	}
	if _, err := NewService(newMemStore(), nil, nil, fixedClock{}, &seqIDs{}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("nil audit: want ErrValidation, got %v", err)
	}
}

// stubSigner records calls and returns a sentinel attestation over the head, so the
// service test asserts the WIRING (attest on intact, skip on broken/empty) without
// real crypto – signature correctness is covered in the signing + domain packages.
type stubSigner struct{ calls int }

func (s *stubSigner) Sign(_ context.Context, head string) (evdom.Attestation, error) {
	s.calls++
	return evdom.Attestation{Algorithm: "ed25519", KeyID: "test", PublicKey: "pk", Head: head, Signature: "sig"}, nil
}
func (s *stubSigner) PublicKey() string { return "pk" }
func (s *stubSigner) KeyID() string     { return "test" }

func TestVerifyAttestsIntactHead(t *testing.T) {
	svc, _, _ := newVault(t, nil)
	signer := &stubSigner{}
	svc.SetSigner(signer)
	ctx := context.Background()

	// Empty chain: nothing to attest.
	if rep, err := svc.Verify(ctx, "e1"); err != nil || rep.Attestation != nil || signer.calls != 0 {
		t.Fatalf("empty chain must not be attested: att=%v calls=%d err=%v", rep.Attestation, signer.calls, err)
	}

	for i := 0; i < 2; i++ {
		if _, err := svc.Seal(ctx, "e1", "scan", []byte("p"+strconv.Itoa(i)), "op"); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := svc.Verify(ctx, "e1")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Attestation == nil || rep.Attestation.Head != rep.Head || signer.calls != 1 {
		t.Fatalf("intact chain must be attested over its head: att=%+v head=%s calls=%d", rep.Attestation, rep.Head, signer.calls)
	}
}

func TestVerifyDoesNotAttestBrokenChain(t *testing.T) {
	svc, store, _ := newVault(t, nil)
	signer := &stubSigner{}
	svc.SetSigner(signer)
	ctx := context.Background()
	if _, err := svc.Seal(ctx, "e1", "scan", []byte("a"), "op"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Seal(ctx, "e1", "scan", []byte("b"), "op"); err != nil {
		t.Fatal(err)
	}
	// Tamper the stored chain so verification fails.
	store.items["e1"][0].Content = []byte("HACKED")
	rep, err := svc.Verify(ctx, "e1")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Intact {
		t.Fatal("setup: chain should be broken")
	}
	if rep.Attestation != nil || signer.calls != 0 {
		t.Fatalf("a broken chain must NOT be attested: att=%v calls=%d", rep.Attestation, signer.calls)
	}
}

func TestSealBuildsVerifiableChain(t *testing.T) {
	svc, _, _ := newVault(t, nil)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := svc.Seal(ctx, "e1", "scan", []byte("payload-"+strconv.Itoa(i)), "op"); err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
	}
	rep, err := svc.Verify(ctx, "e1")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Intact || rep.Verified != 3 {
		t.Fatalf("want intact chain of 3, got intact=%v verified=%d", rep.Intact, rep.Verified)
	}
	for i := 1; i < len(rep.Items); i++ {
		if rep.Items[i].PreviousHash != rep.Items[i-1].Hash {
			t.Errorf("link %d does not chain to %d", i, i-1)
		}
	}
}

func TestVerifyDetectsTamperAndAlerts(t *testing.T) {
	svc, store, audit := newVault(t, nil)
	ctx := context.Background()
	_, _ = svc.Seal(ctx, "e1", "scan", []byte("a"), "op")
	_, _ = svc.Seal(ctx, "e1", "scan", []byte("b"), "op")

	// Tamper a stored link's content; the chain must fail and an alert must fire.
	store.items["e1"][0].Content = []byte("tampered")
	rep, err := svc.Verify(ctx, "e1")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Intact {
		t.Error("tampered chain must verify as broken")
	}
	if !audit.has("evidence.tampered") {
		t.Error("tamper must emit an evidence.tampered alert on the audit log")
	}
}

func TestCaptureArtifact(t *testing.T) {
	blobs := newMemBlobs()
	svc, _, audit := newVault(t, blobs)
	ctx := context.Background()

	data := []byte("screenshot-bytes")
	link, err := svc.CaptureArtifact(ctx, "e1", "op", "screenshot", "shot.png", data, "login page")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	// The blob is stored content-addressed and the link references it.
	if link.StorageRef == "" || blobs.m[link.StorageRef] == nil {
		t.Fatalf("blob not stored under StorageRef %q", link.StorageRef)
	}
	// The blob sha256 is sealed INSIDE the content (chain-protected).
	var payload map[string]any
	if err := json.Unmarshal(link.Content, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["blob_sha256"] != link.StorageRef {
		t.Errorf("content blob_sha256 %v != StorageRef %q", payload["blob_sha256"], link.StorageRef)
	}
	if !audit.has("evidence.captured") {
		t.Error("capture must be audited")
	}

	// Retrieval re-verifies the bytes against the hash.
	got, err := svc.ArtifactForEngagement(ctx, "e1", link.StorageRef)
	if err != nil || string(got) != string(data) {
		t.Fatalf("artifact retrieval: got=%q err=%v", got, err)
	}
	// Scoped to the engagement: another engagement cannot read the same blob.
	if _, err := svc.ArtifactForEngagement(ctx, "e2", link.StorageRef); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-engagement read: want ErrNotFound, got %v", err)
	}
	// A malformed sha is rejected before the blob store is touched.
	if _, err := svc.ArtifactForEngagement(ctx, "e1", "not-a-sha"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("bad sha: want ErrValidation, got %v", err)
	}
	// Tamper the stored blob -> retrieval detects the hash mismatch.
	blobs.m[link.StorageRef] = []byte("tampered")
	if _, err := svc.ArtifactForEngagement(ctx, "e1", link.StorageRef); !errors.Is(err, evdom.ErrChainBroken) {
		t.Errorf("tampered blob: want ErrChainBroken, got %v", err)
	}
}

func TestCaptureArtifactRequiresBlobStore(t *testing.T) {
	svc, _, _ := newVault(t, nil) // no blob store
	if _, err := svc.CaptureArtifact(context.Background(), "e1", "op", "screenshot", "x", []byte("d"), ""); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("want ErrValidation without a blob store, got %v", err)
	}
}

// ---- external RFC-3161 anchoring (wiring; crypto is tested in infra) ----

type stubTSA struct {
	calls int
	fail  bool
}

func (t *stubTSA) Timestamp(_ context.Context, digest []byte) (ports.TimestampToken, error) {
	t.calls++
	if t.fail {
		return ports.TimestampToken{}, errors.New("tsa unreachable")
	}
	return ports.TimestampToken{Authority: "test-tsa", Token: "tok:" + string(digest)}, nil
}

type fakeTSStore struct {
	m    map[string]ports.TimestampToken
	last string
}

func newTSStore() *fakeTSStore { return &fakeTSStore{m: map[string]ports.TimestampToken{}} }
func (f *fakeTSStore) Get(_ context.Context, chain string, eng shared.ID, head string) (*ports.TimestampToken, error) {
	if t, ok := f.m[chain+eng.String()+head]; ok {
		c := t
		return &c, nil
	}
	return nil, nil
}
func (f *fakeTSStore) Put(_ context.Context, chain string, eng shared.ID, head string, tok ports.TimestampToken) error {
	f.m[chain+eng.String()+head] = tok
	f.last = head
	return nil
}
func (f *fakeTSStore) LatestHead(_ context.Context, _ string, _ shared.ID) (string, bool, error) {
	return f.last, f.last != "", nil
}

func TestVerifyAnchorsHeadThenReusesStoredToken(t *testing.T) {
	svc, _, _ := newVault(t, nil)
	tsa := &stubTSA{}
	svc.SetTimestamper(tsa, newTSStore())
	ctx := context.Background()
	if _, err := svc.Seal(ctx, "e1", "scan", []byte("x"), "op"); err != nil {
		t.Fatal(err)
	}
	rep, err := svc.Verify(ctx, "e1")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Anchored || rep.Timestamp == nil || tsa.calls != 1 {
		t.Fatalf("head must be externally anchored: anchored=%v ts=%v calls=%d", rep.Anchored, rep.Timestamp, tsa.calls)
	}
	// A second verify must reuse the stored token, not call the TSA again.
	rep2, _ := svc.Verify(ctx, "e1")
	if !rep2.Anchored || tsa.calls != 1 {
		t.Errorf("second verify should reuse the stored token, calls=%d", tsa.calls)
	}
}

func TestVerifyDetectsTailTruncation(t *testing.T) {
	svc, _, _ := newVault(t, nil)
	ts := newTSStore()
	svc.SetTimestamper(&stubTSA{}, ts)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := svc.Seal(ctx, "e1", "scan", []byte{byte(i)}, "op"); err != nil {
			t.Fatal(err)
		}
	}
	// A complete chain verifies intact and anchors its head (retained out-of-band).
	if rep, err := svc.Verify(ctx, "e1"); err != nil || !rep.Intact {
		t.Fatalf("a complete chain must verify intact: intact=%v err=%v", rep.Intact, err)
	}
	// Simulate an out-of-band tail truncation: a head was anchored (retained) that is no longer
	// present in the chain – i.e. a superuser disabled the append-only trigger and deleted the
	// tail. The latest retained head now mismatches the (shorter, still-linear) chain.
	if err := ts.Put(ctx, ChainEvidence, "e1", "deadbeefphantomhead", ports.TimestampToken{Authority: "tsa", Token: "tok"}); err != nil {
		t.Fatal(err)
	}
	rep, err := svc.Verify(ctx, "e1")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Intact {
		t.Fatal("tail-truncation must be detected: the latest retained head is missing from the chain")
	}
	if !strings.Contains(rep.Error, "tail-truncation") {
		t.Errorf("verify error should name tail-truncation, got %q", rep.Error)
	}
}

func TestVerifyPendingWhenTSAUnreachable(t *testing.T) {
	svc, _, _ := newVault(t, nil)
	svc.SetTimestamper(&stubTSA{fail: true}, newTSStore())
	ctx := context.Background()
	if _, err := svc.Seal(ctx, "e1", "scan", []byte("x"), "op"); err != nil {
		t.Fatal(err)
	}
	rep, err := svc.Verify(ctx, "e1")
	if err != nil {
		t.Fatalf("an unreachable TSA must not fail the verify: %v", err)
	}
	if rep.Anchored || rep.Timestamp != nil {
		t.Error("a failing TSA must leave the head pending-anchor")
	}
	if !rep.Intact {
		t.Error("the report must still be intact when anchoring fails")
	}
}

func TestVerifyNoAnchorWithoutTimestamper(t *testing.T) {
	svc, _, _ := newVault(t, nil)
	ctx := context.Background()
	if _, err := svc.Seal(ctx, "e1", "scan", []byte("x"), "op"); err != nil {
		t.Fatal(err)
	}
	rep, _ := svc.Verify(ctx, "e1")
	if rep.Anchored {
		t.Error("no timestamper configured → head must not be anchored")
	}
}

// TestSealConcurrentStaysLinear covers many writers sealing the SAME engagement
// chain concurrently must never fork it – the store's one-child-per-parent guard +
// re-chain-on-conflict keeps the chain strictly linear and intact.
func TestSealConcurrentStaysLinear(t *testing.T) {
	store := newConcurrentEvidenceStore()
	svc, err := NewService(store, nil, &capAudit{}, fixedClock{t: time.Unix(0, 0).UTC()}, &randomTestIDs{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const n = 60
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = svc.Seal(ctx, "eng1", "k", []byte{byte(i)}, "op")
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("concurrent seal %d failed: %v", i, e)
		}
	}
	chain, _ := store.ListByEngagement(ctx, "eng1")
	if len(chain) != n {
		t.Fatalf("expected %d links (no fork/loss), got %d", n, len(chain))
	}
	if chain[0].PreviousHash != "" {
		t.Errorf("genesis previous_hash = %q, want empty", chain[0].PreviousHash)
	}
	for j := 1; j < len(chain); j++ {
		if chain[j].PreviousHash != chain[j-1].Hash {
			t.Fatalf("chain FORKED at link %d: previous_hash=%s, want %s", j, chain[j].PreviousHash, chain[j-1].Hash)
		}
	}
}

func TestSealRejectsCrossTenantAppendWithoutChangingChain(t *testing.T) {
	store := newConcurrentEvidenceStore()
	svc, err := NewService(store, nil, &capAudit{}, fixedClock{t: time.Unix(0, 0).UTC()}, &randomTestIDs{})
	if err != nil {
		t.Fatal(err)
	}
	owner := shared.WithTenant(context.Background(), "tenant-owner")
	other := shared.WithTenant(context.Background(), "tenant-other")
	if _, err := svc.Seal(owner, "eng-tenant", "scan", []byte("owner"), "operator"); err != nil {
		t.Fatalf("owner seal: %v", err)
	}
	before, err := store.ListByEngagement(owner, "eng-tenant")
	if err != nil {
		t.Fatal(err)
	}
	head, err := store.Head(owner, "eng-tenant")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Seal(other, "eng-tenant", "scan", []byte("other"), "operator"); err == nil {
		t.Fatal("cross-tenant append unexpectedly succeeded")
	}
	after, err := store.ListByEngagement(owner, "eng-tenant")
	if err != nil {
		t.Fatal(err)
	}
	afterHead, err := store.Head(owner, "eng-tenant")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) || afterHead != head {
		t.Fatalf("cross-tenant append changed chain: before=%d/%s after=%d/%s", len(before), head, len(after), afterHead)
	}
}

func TestSealWithIDReusesReservedIdentityAndRejectsIdentityConflicts(t *testing.T) {
	svc, store, _ := newVault(t, nil)
	ctx := context.Background()

	first, err := svc.SealWithID(ctx, "reserved-scan", "eng-evidence", "scan", []byte("sealed"), "worker")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.SealWithID(ctx, "reserved-scan", "eng-evidence", "scan", []byte("altered telemetry"), "worker")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || string(second.Content) != "sealed" || len(store.items["eng-evidence"]) != 1 {
		t.Fatalf("reserved replay did not reuse committed evidence: first=%+v second=%+v items=%+v", first, second, store.items["eng-evidence"])
	}
	if _, err := svc.SealWithID(ctx, "reserved-scan", "eng-evidence", "other-kind", []byte("sealed"), "worker"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("altered kind replay error = %v, want ErrConflict", err)
	}
	if _, err := svc.SealWithID(ctx, "reserved-scan", "eng-evidence", "scan", []byte("sealed"), "other-worker"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("altered creator replay error = %v, want ErrConflict", err)
	}
}

func TestSealForFindingWithIDReplaysExactlyAndRejectsConflicts(t *testing.T) {
	store := newConcurrentEvidenceStore()
	svc, err := NewService(store, nil, &capAudit{}, fixedClock{t: time.Unix(0, 0).UTC()}, &randomTestIDs{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), "tenant-evidence")
	const n = 64
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = svc.SealForFindingWithID(ctx, "reserved-evidence", "eng-evidence", "finding-evidence", "promotion_application", []byte("sealed"), "", "system:promotion")
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("exact replay %d: %v", i, err)
		}
	}
	items, err := store.ListByEngagement(ctx, "eng-evidence")
	if err != nil || len(items) != 1 {
		t.Fatalf("reserved replay links=%d err=%v, want one", len(items), err)
	}
	if _, err := svc.SealForFindingWithID(ctx, "reserved-evidence", "eng-evidence", "finding-evidence", "promotion_application", []byte("altered"), "", "system:promotion"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("altered payload = %v, want conflict", err)
	}
	if _, err := svc.SealForFindingWithID(ctx, "reserved-evidence", "eng-evidence", "other-finding", "promotion_application", []byte("sealed"), "", "system:promotion"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("altered finding = %v, want conflict", err)
	}
	if _, err := svc.SealForFindingWithID(shared.WithTenant(context.Background(), "other-tenant"), "reserved-evidence", "eng-evidence", "finding-evidence", "promotion_application", []byte("sealed"), "", "system:promotion"); err == nil {
		t.Fatal("cross-tenant replay unexpectedly succeeded")
	}
}

func TestSealForFindingWithIDHighContentionStaysLinear(t *testing.T) {
	store := newConcurrentEvidenceStore()
	svc, err := NewService(store, nil, &capAudit{}, fixedClock{t: time.Unix(0, 0).UTC()}, &randomTestIDs{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(shared.WithTenant(context.Background(), "tenant-evidence"), 10*time.Second)
	defer cancel()
	const writers = 64
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := shared.ID("reserved-" + strconv.Itoa(i))
			_, errs[i] = svc.SealForFindingWithID(ctx, id, "eng-evidence", "finding-evidence", "promotion_application", []byte(strconv.Itoa(i)), "", "system:promotion")
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("writer %d: %v", i, err)
		}
	}
	items, err := store.ListByEngagement(ctx, "eng-evidence")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != writers {
		t.Fatalf("links = %d, want %d", len(items), writers)
	}
	ids := make(map[shared.ID]struct{}, len(items))
	for _, item := range items {
		if _, exists := ids[item.ID]; exists {
			t.Fatalf("duplicate evidence ID %s", item.ID)
		}
		ids[item.ID] = struct{}{}
	}
	if err := evdom.VerifyChain(items); err != nil {
		t.Fatalf("chain invalid: %v", err)
	}
}

func TestSealOnceIsIdempotentOnKey(t *testing.T) {
	svc, store, _ := newVault(t, nil)
	ctx := context.Background()
	const eng = shared.ID("eng-once")

	first, err := svc.SealOnce(ctx, eng, "detection", "d1", []byte(`{"x":1}`), "agent:1")
	if err != nil {
		t.Fatalf("first seal: %v", err)
	}
	// Same (engagement, kind, key) with the SAME content returns the SAME link and appends nothing — this
	// is the D3 closure: a seal-then-crash retry cannot add a second permanent link for one detection.
	again, err := svc.SealOnce(ctx, eng, "detection", "d1", []byte(`{"x":1}`), "agent:1")
	if err != nil {
		t.Fatalf("idempotent re-seal: %v", err)
	}
	if again.ID != first.ID {
		t.Fatalf("re-seal must return the first link id %s, got %s", first.ID, again.ID)
	}
	if chain, _ := store.ListByEngagement(ctx, eng); len(chain) != 1 {
		t.Fatalf("idempotent re-seal must not append a second link, chain has %d", len(chain))
	}

	// A different key is a distinct link.
	other, err := svc.SealOnce(ctx, eng, "detection", "d2", []byte(`{"x":2}`), "agent:1")
	if err != nil {
		t.Fatalf("second key seal: %v", err)
	}
	if other.ID == first.ID {
		t.Fatalf("a different idempotency key must seal a distinct link")
	}
	if chain, _ := store.ListByEngagement(ctx, eng); len(chain) != 2 {
		t.Fatalf("two distinct keys must be two links, chain has %d", len(chain))
	}

	// Reusing a key with DIFFERENT content is a conflict, not a silent overwrite (fail closed).
	if _, err := svc.SealOnce(ctx, eng, "detection", "d1", []byte(`{"x":999}`), "agent:1"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("conflicting content under a used key must be ErrConflict, got %v", err)
	}
}

func TestSealOnceValidates(t *testing.T) {
	svc, _, _ := newVault(t, nil)
	ctx := context.Background()
	if _, err := svc.SealOnce(ctx, "", "detection", "k", []byte("x"), "a"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty engagement must be ErrValidation, got %v", err)
	}
	if _, err := svc.SealOnce(ctx, "eng", "", "k", []byte("x"), "a"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty kind must be ErrValidation, got %v", err)
	}
	if _, err := svc.SealOnce(ctx, "eng", "detection", "", []byte("x"), "a"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty idempotency key must be ErrValidation, got %v", err)
	}
}

func TestVerifyChainErrorReflectsIntactness(t *testing.T) {
	svc, store, _ := newVault(t, nil)
	ctx := context.Background()
	const eng = shared.ID("eng-verify")
	if _, err := svc.SealOnce(ctx, eng, "detection", "d1", []byte("body"), "agent:1"); err != nil {
		t.Fatal(err)
	}
	if err := svc.VerifyChainError(ctx, eng); err != nil {
		t.Fatalf("an intact chain must verify with nil error, got %v", err)
	}
	// Tamper a stored link's attribution: VerifyChainError must surface it as an ErrChainBroken-wrapping
	// error (Verify itself returns Intact=false with a nil error, which a naive bridge would miss).
	chain := store.items[eng]
	chain[0].CreatedBy = "attacker"
	store.items[eng] = chain
	if err := svc.VerifyChainError(ctx, eng); !errors.Is(err, evdom.ErrChainBroken) {
		t.Fatalf("a tampered chain must return an ErrChainBroken-wrapping error, got %v", err)
	}
}
