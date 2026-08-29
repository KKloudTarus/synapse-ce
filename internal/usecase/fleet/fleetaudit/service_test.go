package fleetaudit

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// intentStoreStub is a durable-outbox twin: it hands out pending intentions and
// records which ones were acknowledged, so a test can prove that delivery
// precedes acknowledgement and that a failed delivery leaves the intention
// pending for the next run.
type intentStoreStub struct {
	mu       sync.Mutex
	pending  map[string]ports.FleetAuditIntent
	listErr  error
	ackErr   error
	acked    []string
	listCall int
}

func newIntentStore(intents ...ports.FleetAuditIntent) *intentStoreStub {
	s := &intentStoreStub{pending: map[string]ports.FleetAuditIntent{}}
	for _, intent := range intents {
		s.pending[intent.ID] = intent
	}
	return s
}

func (s *intentStoreStub) ListPendingFleetAudits(context.Context) ([]ports.FleetAuditIntent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listCall++
	if s.listErr != nil {
		return nil, s.listErr
	}
	out := make([]ports.FleetAuditIntent, 0, len(s.pending))
	for _, intent := range s.pending {
		out = append(out, intent)
	}
	return out, nil
}

func (s *intentStoreStub) AcknowledgeFleetAudit(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ackErr != nil {
		return s.ackErr
	}
	delete(s.pending, id)
	s.acked = append(s.acked, id)
	return nil
}

func (s *intentStoreStub) stillPending() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.pending))
	for id := range s.pending {
		out = append(out, id)
	}
	return out
}

// auditStub is the append-only chain: it counts deliveries per idempotency key so
// a test can assert exactly-once semantics and can fail a chosen key.
type auditStub struct {
	mu       sync.Mutex
	recorded map[string]int
	failOn   map[string]error
}

func newAuditStub() *auditStub {
	return &auditStub{recorded: map[string]int{}, failOn: map[string]error{}}
}

func (a *auditStub) Record(ctx context.Context, e ports.AuditEntry) error {
	return a.RecordOnce(ctx, e)
}

func (a *auditStub) RecordOnce(_ context.Context, e ports.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := e.Metadata["idempotency_key"]
	if err := a.failOn[key]; err != nil {
		return err
	}
	a.recorded[key]++
	return nil
}

func (a *auditStub) count(key string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.recorded[key]
}

func intent(id string) ports.FleetAuditIntent {
	return ports.FleetAuditIntent{
		ID: id,
		Entry: ports.AuditEntry{
			Actor:    "agent-1",
			Action:   "fleet.telemetry.batch_commit",
			Target:   "stream-1",
			At:       time.Date(2026, 8, 28, 9, 0, 0, 0, time.UTC),
			Metadata: map[string]string{"idempotency_key": id},
		},
	}
}

func TestNewReconcilerRejectsIncompleteDependencies(t *testing.T) {
	audit := newAuditStub()
	tests := []struct {
		name   string
		stores []ports.FleetAuditIntentStore
		audit  ports.IdempotentAuditLogger
	}{
		{name: "no stores", stores: nil, audit: audit},
		{name: "nil store", stores: []ports.FleetAuditIntentStore{nil}, audit: audit},
		{name: "no audit", stores: []ports.FleetAuditIntentStore{newIntentStore()}, audit: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewReconciler(tc.stores, tc.audit); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

// A committed intention must reach the audit chain BEFORE it is acknowledged, and
// must be acknowledged so a later run cannot re-deliver it.
func TestReconcileDeliversThenAcknowledges(t *testing.T) {
	store := newIntentStore(intent("a"), intent("b"))
	audit := newAuditStub()
	r, err := NewReconciler([]ports.FleetAuditIntentStore{store}, audit)
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	for _, id := range []string{"a", "b"} {
		if audit.count(id) != 1 {
			t.Fatalf("intention %s recorded %d times, want 1", id, audit.count(id))
		}
	}
	if left := store.stillPending(); len(left) != 0 {
		t.Fatalf("acknowledged intentions must not stay pending, got %v", left)
	}
	// A second pass has nothing to deliver: acknowledgement is what stops re-delivery.
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if audit.count("a") != 1 {
		t.Fatalf("intention a re-delivered %d times after acknowledgement", audit.count("a"))
	}
}

// Fail-closed: an audit-chain failure must leave the intention pending and
// unacknowledged, so state that already committed still gets audited later.
func TestReconcileKeepsIntentionPendingWhenAuditFails(t *testing.T) {
	store := newIntentStore(intent("a"))
	audit := newAuditStub()
	audit.failOn["a"] = errors.New("audit chain unavailable")
	r, err := NewReconciler([]ports.FleetAuditIntentStore{store}, audit)
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("a failed audit delivery must surface as an error, not a silent success")
	}
	if len(store.acked) != 0 {
		t.Fatalf("intention acknowledged despite audit failure: %v", store.acked)
	}
	if left := store.stillPending(); len(left) != 1 || left[0] != "a" {
		t.Fatalf("intention must stay pending, got %v", left)
	}
	// Once the chain recovers, the same intention is delivered and retired.
	delete(audit.failOn, "a")
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("recovery reconcile: %v", err)
	}
	if audit.count("a") != 1 || len(store.stillPending()) != 0 {
		t.Fatalf("recovery did not deliver and retire the intention (count=%d pending=%v)", audit.count("a"), store.stillPending())
	}
}

// One failing intention must not hide the others: the reconciler is a batch
// repair pass, so unrelated pending work still drains.
func TestReconcileContinuesPastOneFailure(t *testing.T) {
	store := newIntentStore(intent("a"), intent("b"))
	audit := newAuditStub()
	audit.failOn["a"] = errors.New("transient")
	r, err := NewReconciler([]ports.FleetAuditIntentStore{store}, audit)
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("want the failing intention surfaced")
	}
	if audit.count("b") != 1 {
		t.Fatalf("healthy intention not delivered, count=%d", audit.count("b"))
	}
	if left := store.stillPending(); len(left) != 1 || left[0] != "a" {
		t.Fatalf("only the failing intention must stay pending, got %v", left)
	}
}

// An acknowledgement failure is a real fault (the intention would be re-delivered
// forever otherwise), so it must not be swallowed.
func TestReconcileSurfacesAcknowledgementFailure(t *testing.T) {
	store := newIntentStore(intent("a"))
	store.ackErr = errors.New("acknowledge unavailable")
	audit := newAuditStub()
	r, err := NewReconciler([]ports.FleetAuditIntentStore{store}, audit)
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("want the acknowledgement failure surfaced")
	}
	if audit.count("a") != 1 {
		t.Fatalf("audit delivery must still have happened, count=%d", audit.count("a"))
	}
}

// An intention without an identity cannot be idempotently delivered, so it is
// rejected rather than recorded under an empty key.
func TestReconcileRejectsEmptyIntentionID(t *testing.T) {
	broken := intent("")
	broken.Entry.Metadata["idempotency_key"] = ""
	store := newIntentStore(broken)
	audit := newAuditStub()
	r, err := NewReconciler([]ports.FleetAuditIntentStore{store}, audit)
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	err = r.Reconcile(context.Background())
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want validation error, got %v", err)
	}
	if len(audit.recorded) != 0 {
		t.Fatalf("an unidentified intention must not be recorded: %v", audit.recorded)
	}
}

func TestReconcileHonoursCancellation(t *testing.T) {
	store := newIntentStore(intent("a"))
	audit := newAuditStub()
	r, err := NewReconciler([]ports.FleetAuditIntentStore{store}, audit)
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Reconcile(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if len(audit.recorded) != 0 {
		t.Fatalf("cancelled reconcile must not deliver: %v", audit.recorded)
	}
}

// Each configured store is drained independently; a broken store must not stop
// the others.
func TestReconcileDrainsEveryStore(t *testing.T) {
	healthy := newIntentStore(intent("a"))
	broken := newIntentStore(intent("b"))
	broken.listErr = errors.New("store unavailable")
	audit := newAuditStub()
	r, err := NewReconciler([]ports.FleetAuditIntentStore{broken, healthy}, audit)
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("want the broken store surfaced")
	}
	if audit.count("a") != 1 {
		t.Fatalf("healthy store not drained, count=%d", audit.count("a"))
	}
}

// NewReconciler must copy its store slice: a caller mutating the slice afterwards
// cannot silently retarget or disable audit recovery.
func TestNewReconcilerCopiesStores(t *testing.T) {
	store := newIntentStore(intent("a"))
	stores := []ports.FleetAuditIntentStore{store}
	audit := newAuditStub()
	r, err := NewReconciler(stores, audit)
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	stores[0] = newIntentStore(intent("hijacked"))
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if audit.count("a") != 1 || audit.count("hijacked") != 0 {
		t.Fatalf("reconciler followed a mutated caller slice: %v", audit.recorded)
	}
}

type tenantListerStub struct {
	tenants []shared.ID
	err     error
}

func (s tenantListerStub) ListTenantIDs(context.Context) ([]shared.ID, error) {
	return s.tenants, s.err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewReconciliationRunnerRejectsIncompleteDependencies(t *testing.T) {
	reconciler, err := NewReconciler([]ports.FleetAuditIntentStore{newIntentStore()}, newAuditStub())
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	tests := []struct {
		name       string
		tenants    TenantLister
		reconciler *Reconciler
		log        *slog.Logger
	}{
		{name: "no tenants", reconciler: reconciler, log: discardLogger()},
		{name: "no reconciler", tenants: tenantListerStub{}, log: discardLogger()},
		{name: "no logger", tenants: tenantListerStub{}, reconciler: reconciler},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewReconciliationRunner(tc.tenants, tc.reconciler, tc.log); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

// Recovery is per tenant: the reconciler only ever sees a tenant-scoped context,
// because a pending intention is readable only under its own tenant's RLS.
func TestRunOnceReconcilesEachTenantScoped(t *testing.T) {
	var seen []string
	store := &tenantObservingStore{onList: func(ctx context.Context) {
		tenantID, ok := shared.TenantFrom(ctx)
		if !ok {
			seen = append(seen, "<none>")
			return
		}
		seen = append(seen, tenantID.String())
	}}
	reconciler, err := NewReconciler([]ports.FleetAuditIntentStore{store}, newAuditStub())
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	runner, err := NewReconciliationRunner(
		tenantListerStub{tenants: []shared.ID{shared.ID("t-1"), shared.ID(""), shared.ID("t-2")}},
		reconciler, discardLogger(),
	)
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("run once: %v", err)
	}
	if len(seen) != 2 || seen[0] != "t-1" || seen[1] != "t-2" {
		t.Fatalf("want each valid tenant reconciled under its own scope, got %v", seen)
	}
}

func TestRunOnceSurfacesTenantEnumerationFailure(t *testing.T) {
	reconciler, err := NewReconciler([]ports.FleetAuditIntentStore{newIntentStore()}, newAuditStub())
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	runner, err := NewReconciliationRunner(
		tenantListerStub{err: errors.New("tenant enumeration unavailable")}, reconciler, discardLogger(),
	)
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	if err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("want the tenant enumeration failure surfaced")
	}
}

// A per-tenant failure must not abort the sweep: the remaining tenants still get
// their committed intentions delivered.
func TestRunOnceContinuesPastTenantFailure(t *testing.T) {
	audit := newAuditStub()
	audit.failOn["a"] = errors.New("transient")
	store := newIntentStore(intent("a"), intent("b"))
	reconciler, err := NewReconciler([]ports.FleetAuditIntentStore{store}, audit)
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	runner, err := NewReconciliationRunner(
		tenantListerStub{tenants: []shared.ID{shared.ID("t-1"), shared.ID("t-2")}}, reconciler, discardLogger(),
	)
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("a per-tenant failure must be logged, not returned: %v", err)
	}
	if store.listCall != 2 {
		t.Fatalf("want both tenants swept, got %d list calls", store.listCall)
	}
	if audit.count("b") != 1 {
		t.Fatalf("healthy intention delivered %d times, want 1", audit.count("b"))
	}
}

func TestRunOnceHonoursCancellation(t *testing.T) {
	reconciler, err := NewReconciler([]ports.FleetAuditIntentStore{newIntentStore()}, newAuditStub())
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	runner, err := NewReconciliationRunner(
		tenantListerStub{tenants: []shared.ID{shared.ID("t-1")}}, reconciler, discardLogger(),
	)
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runner.RunOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestRunPeriodicStopsOnCancellation(t *testing.T) {
	reconciler, err := NewReconciler([]ports.FleetAuditIntentStore{newIntentStore()}, newAuditStub())
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	runner, err := NewReconciliationRunner(
		tenantListerStub{tenants: []shared.ID{shared.ID("t-1")}}, reconciler, discardLogger(),
	)
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runner.RunPeriodic(ctx, time.Millisecond)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunPeriodic did not stop after cancellation")
	}
}

type tenantObservingStore struct {
	onList func(context.Context)
}

func (s *tenantObservingStore) ListPendingFleetAudits(ctx context.Context) ([]ports.FleetAuditIntent, error) {
	s.onList(ctx)
	return nil, nil
}

func (s *tenantObservingStore) AcknowledgeFleetAudit(context.Context, string) error { return nil }
