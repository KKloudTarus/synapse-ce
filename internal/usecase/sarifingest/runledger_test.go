package sarifingest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importreceipt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// withLedger wires the in-memory receipt store and transaction runner onto a service. The memory runner
// does not roll back the imported-finding store, which is why production leaves the ledger unwired
// without a database; here it is enough to drive the ledger's own state machine.
func withLedger(t *testing.T, svc *Service) *memory.ImportReceiptStore {
	t.Helper()
	receipts := memory.NewImportReceiptStore()
	if err := svc.SetRunLedger(receipts, memory.NewTenantTransactionRunner()); err != nil {
		t.Fatalf("set run ledger: %v", err)
	}
	return receipts
}

func receiptFor(t *testing.T, receipts *memory.ImportReceiptStore, sourceIdentity, digest string) importreceipt.Receipt {
	t.Helper()
	got, err := receipts.GetByIdentity(context.Background(), "t1", "eng1", sourceIdentity, digest)
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	return got
}

func TestSetRunLedgerRefusesAStoreWithoutATransaction(t *testing.T) {
	t.Parallel()

	svc, _, _ := newService(t)
	// A receipt written outside the transaction that writes the rows can claim an import completed while
	// those rows were rolled back, which is worse than no receipt at all.
	if err := svc.SetRunLedger(memory.NewImportReceiptStore(), nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("store without a runner = %v, want a validation error", err)
	}
	if err := svc.SetRunLedger(nil, memory.NewTenantTransactionRunner()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("runner without a store = %v, want a validation error", err)
	}
}

func TestIngestWithoutTheLedgerReportsNoRun(t *testing.T) {
	t.Parallel()

	svc, _, _ := newService(t)
	result, err := ingest(t, svc, docWith(resultA))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	// An unwired ledger must not invent a run id, because a caller reading the header would follow it to
	// a receipt that does not exist.
	if !result.RunID.IsZero() || result.Outcome != "" {
		t.Fatalf("unwired ledger reported run %q outcome %q", result.RunID, result.Outcome)
	}
}

func TestIngestRecordsACompleteRun(t *testing.T) {
	t.Parallel()

	svc, _, _ := newService(t)
	receipts := withLedger(t, svc)

	result, err := ingest(t, svc, docWith(resultA))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.RunID.IsZero() {
		t.Fatal("a wired ledger must report the run its rows were recorded under")
	}
	if result.Outcome != importreceipt.OutcomeComplete {
		t.Fatalf("outcome = %q, want complete", result.Outcome)
	}
	got := receiptFor(t, receipts, "sarif:semgrep", storedDigest(t, svc, docWith(resultA)))
	if got.ID != result.RunID {
		t.Fatalf("receipt %s does not match the reported run %s", got.ID, result.RunID)
	}
	if got.Outcome != importreceipt.OutcomeComplete {
		t.Fatalf("stored outcome = %q, want complete", got.Outcome)
	}
	want := importreceipt.Counters{Accepted: 1}
	if got.Counters != want {
		t.Fatalf("counters = %+v, want %+v", got.Counters, want)
	}
	if got.ParserVersion != parserVersion {
		t.Fatalf("parser version = %q, want %q", got.ParserVersion, parserVersion)
	}
}

// storedDigest recomputes the digest the parser assigns a document, so a test can look a receipt up by
// the same identity the service used.
func storedDigest(t *testing.T, _ *Service, doc string) string {
	t.Helper()
	return Digest([]byte(doc))
}

func TestARunThatRefusedSomeResultsIsPartialAndNeverComplete(t *testing.T) {
	t.Parallel()

	svc, _, _ := newService(t)
	receipts := withLedger(t, svc)

	// The second result names no rule, so it is refused while the first is stored.
	doc := docWith(resultA + `,{"level":"error","message":{"text":"no rule"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/b.go"},"region":{"startLine":7}}}]}`)
	result, err := ingest(t, svc, doc)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.Accepted == 0 || len(result.Refused) == 0 {
		t.Fatalf("fixture must accept one and refuse one, got %+v", result)
	}
	if result.Outcome != importreceipt.OutcomePartial {
		t.Fatalf("outcome = %q, want partial", result.Outcome)
	}
	got := receiptFor(t, receipts, "sarif:semgrep", storedDigest(t, svc, doc))
	if got.Outcome != importreceipt.OutcomePartial || got.Counters.Refused != len(result.Refused) {
		t.Fatalf("receipt = %+v, want partial carrying %d refusals", got, len(result.Refused))
	}
}

func TestARunThatStoredNothingIsFailed(t *testing.T) {
	t.Parallel()

	svc, _, _ := newService(t)
	receipts := withLedger(t, svc)

	// Every result is refused, so nothing landed. Calling that partial would imply something did.
	doc := docWith(`{"level":"error","message":{"text":"no rule"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/b.go"},"region":{"startLine":7}}}]}`)
	result, err := ingest(t, svc, doc)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.Accepted != 0 || result.Deduped != 0 || len(result.Refused) == 0 {
		t.Fatalf("fixture must store nothing and refuse everything, got %+v", result)
	}
	if result.Outcome != importreceipt.OutcomeFailed {
		t.Fatalf("outcome = %q, want failed", result.Outcome)
	}
	got := receiptFor(t, receipts, sourceIdentityPrefix, storedDigest(t, svc, doc))
	if got.Outcome != importreceipt.OutcomeFailed {
		t.Fatalf("stored outcome = %q, want failed", got.Outcome)
	}
}

func TestReplayingADocumentKeepsOneRunAndItsOriginalCounters(t *testing.T) {
	t.Parallel()

	svc, _, _ := newService(t)
	receipts := withLedger(t, svc)
	doc := docWith(resultA)

	first, err := ingest(t, svc, doc)
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	second, err := ingest(t, svc, doc)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}

	// One document is one run however many times it is posted.
	if second.RunID != first.RunID {
		t.Fatalf("replay opened run %s, want the original %s", second.RunID, first.RunID)
	}
	// The legacy body is what it always was for a replay: nothing newly accepted, everything deduplicated.
	if second.Accepted != 0 || second.Deduped != 1 {
		t.Fatalf("replay body = accepted %d deduplicated %d, want 0 and 1", second.Accepted, second.Deduped)
	}
	// The receipt keeps the counters that describe the stored rows. Overwriting them with the replay's
	// view would make the durable record say nothing was ever accepted.
	got := receiptFor(t, receipts, "sarif:semgrep", storedDigest(t, svc, doc))
	want := importreceipt.Counters{Accepted: 1}
	if got.Counters != want {
		t.Fatalf("counters after replay = %+v, want the original %+v", got.Counters, want)
	}
	if got.Outcome != importreceipt.OutcomeComplete || second.Outcome != importreceipt.OutcomeComplete {
		t.Fatalf("outcome drifted on replay: stored %q reported %q", got.Outcome, second.Outcome)
	}
}

// countingFailAudit fails its first calls and then succeeds, which is how a run is interrupted after the
// rows were written and then retried.
type countingFailAudit struct {
	failUntil int
	calls     int
	entries   []ports.AuditEntry
}

func (a *countingFailAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	a.calls++
	if a.calls <= a.failUntil {
		return errors.New("audit log unavailable")
	}
	a.entries = append(a.entries, entry)
	return nil
}

func TestAnInterruptedRunLeavesThePendingReceiptForTheRetry(t *testing.T) {
	t.Parallel()

	store := memory.NewImportedFindingStore()
	audit := &countingFailAudit{failUntil: 1}
	svc, err := NewService(store, fakeFindings{}, fakeEngagements{}, audit, fixedClock{}, &seqIDs{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	receipts := withLedger(t, svc)
	doc := docWith(resultA)

	if _, err := ingest(t, svc, doc); err == nil {
		t.Fatal("an audit failure must surface, not be swallowed")
	}

	// Pending is the repair obligation. A terminal outcome here would tell an operator the run is
	// settled when its effects never completed.
	got := receiptFor(t, receipts, "sarif:semgrep", storedDigest(t, svc, doc))
	if got.Outcome != importreceipt.OutcomePending {
		t.Fatalf("outcome after an interrupted run = %q, want pending", got.Outcome)
	}

	// The retry adopts that same receipt and finishes it instead of opening a second run.
	retry, err := ingest(t, svc, doc)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if retry.RunID != got.ID {
		t.Fatalf("retry opened run %s, want the pending %s", retry.RunID, got.ID)
	}
	settled := receiptFor(t, receipts, "sarif:semgrep", storedDigest(t, svc, doc))
	if !settled.Outcome.Terminal() {
		t.Fatalf("outcome after the retry = %q, want a terminal one", settled.Outcome)
	}
}

// spyRunner reports whether the ledger's writes happen inside the transaction it opened.
type spyRunner struct {
	inner ports.TenantTransactionRunner
	open  bool
	runs  int
}

func (r *spyRunner) Run(ctx context.Context, tenantID shared.ID, fn func(context.Context) error) error {
	r.runs++
	r.open = true
	defer func() { r.open = false }()
	return r.inner.Run(ctx, tenantID, fn)
}

// spyReceipts records the transaction state at each call.
type spyReceipts struct {
	*memory.ImportReceiptStore
	runner             *spyRunner
	createdInsideRun   bool
	finalizedInsideRun bool
	finalizeCalls      int
}

func (s *spyReceipts) CreateOrGet(ctx context.Context, tenantID shared.ID, receipt importreceipt.Receipt) (importreceipt.Receipt, bool, error) {
	s.createdInsideRun = s.runner.open
	return s.ImportReceiptStore.CreateOrGet(ctx, tenantID, receipt)
}

func (s *spyReceipts) Finalize(ctx context.Context, tenantID, receiptID shared.ID, outcome importreceipt.Outcome, counters importreceipt.Counters, updatedAt time.Time) (importreceipt.Receipt, error) {
	s.finalizeCalls++
	s.finalizedInsideRun = s.runner.open
	return s.ImportReceiptStore.Finalize(ctx, tenantID, receiptID, outcome, counters, updatedAt)
}

// TestTheReceiptIsOpenedOutsideTheRunAndFinalizedInsideIt locks the two placements the ledger depends on.
// Finalizing outside the transaction would let a receipt say "complete" after the rows it counted were
// rolled back. Opening the receipt inside it would destroy the receipt along with the failed work, losing
// the only record that the run was attempted and the marker the retry adopts.
func TestTheReceiptIsOpenedOutsideTheRunAndFinalizedInsideIt(t *testing.T) {
	t.Parallel()

	svc, _, _ := newService(t)
	runner := &spyRunner{inner: memory.NewTenantTransactionRunner()}
	receipts := &spyReceipts{ImportReceiptStore: memory.NewImportReceiptStore(), runner: runner}
	if err := svc.SetRunLedger(receipts, runner); err != nil {
		t.Fatalf("set run ledger: %v", err)
	}

	if _, err := ingest(t, svc, docWith(resultA)); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if runner.runs != 1 {
		t.Fatalf("transactions opened = %d, want exactly one per ingest", runner.runs)
	}
	if receipts.createdInsideRun {
		t.Fatal("the receipt was opened inside the transaction, so a rollback would erase the run record")
	}
	if !receipts.finalizedInsideRun {
		t.Fatal("the receipt was finalized outside the transaction that wrote the rows it counts")
	}
	if receipts.finalizeCalls != 1 {
		t.Fatalf("finalize calls = %d, want one", receipts.finalizeCalls)
	}
}
