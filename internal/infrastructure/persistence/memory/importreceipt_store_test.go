package memory

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importreceipt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func testImportReceipt(id, tenant string) importreceipt.Receipt {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	return importreceipt.Receipt{
		ID:             shared.ID(id),
		TenantID:       shared.ID(tenant),
		EngagementID:   "eng-import",
		SourceIdentity: "sarif",
		Digest:         "sha256:empty-report",
		ParserVersion:  "sarif-2.1.0/v1",
		Outcome:        importreceipt.OutcomeComplete,
		Counters:       importreceipt.Counters{},
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

func TestImportReceiptStorePersistsZeroFindingReceiptAndRetryResolvesIt(t *testing.T) {
	ctx := context.Background()
	store := NewImportReceiptStore()
	first := testImportReceipt("run-1", "tenant-a")

	got, created, err := store.CreateOrGet(ctx, "tenant-a", first)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !created || got.ID != first.ID || got.Counters != (importreceipt.Counters{}) {
		t.Fatalf("first create = (%+v, created=%v), want zero-finding receipt %s", got, created, first.ID)
	}

	retry := first
	retry.ID = "run-retry"
	retry.ParserVersion = "new-parser-version-must-not-split-logical-import"
	got, created, err = store.CreateOrGet(ctx, "tenant-a", retry)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if created || got.ID != first.ID || got.ParserVersion != first.ParserVersion {
		t.Fatalf("retry = (%+v, created=%v), want original receipt", got, created)
	}
}

func TestImportReceiptStoreTenantIsolation(t *testing.T) {
	ctx := context.Background()
	store := NewImportReceiptStore()
	if _, _, err := store.CreateOrGet(ctx, "tenant-a", testImportReceipt("run-a", "tenant-a")); err != nil {
		t.Fatalf("create tenant a: %v", err)
	}

	_, err := store.GetByIdentity(ctx, "tenant-b", "eng-import", "sarif", "sha256:empty-report")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant lookup err = %v, want ErrNotFound", err)
	}

	other := testImportReceipt("run-b", "tenant-b")
	got, created, err := store.CreateOrGet(ctx, "tenant-b", other)
	if err != nil {
		t.Fatalf("same logical identity in tenant b: %v", err)
	}
	if !created || got.ID != other.ID {
		t.Fatalf("tenant b create = (%+v, created=%v), want independent receipt", got, created)
	}
}

func TestImportReceiptStoreConcurrentCreateOrGet(t *testing.T) {
	ctx := context.Background()
	store := NewImportReceiptStore()
	const workers = 32

	var wg sync.WaitGroup
	wg.Add(workers)
	type result struct {
		receipt importreceipt.Receipt
		created bool
		err     error
	}
	results := make(chan result, workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			r := testImportReceipt(fmt.Sprintf("run-%02d", i), "tenant-a")
			got, created, err := store.CreateOrGet(ctx, "tenant-a", r)
			results <- result{receipt: got, created: created, err: err}
		}(i)
	}
	wg.Wait()
	close(results)

	createdCount := 0
	var resolved shared.ID
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent create: %v", result.err)
		}
		if result.created {
			createdCount++
		}
		if resolved.IsZero() {
			resolved = result.receipt.ID
		}
		if result.receipt.ID != resolved {
			t.Fatalf("workers resolved different receipts: %s and %s", resolved, result.receipt.ID)
		}
	}
	if createdCount != 1 {
		t.Fatalf("created count = %d, want exactly 1", createdCount)
	}
}

func TestImportReceiptStoreFinalizeIsNarrowAndIdempotent(t *testing.T) {
	ctx := context.Background()
	store := NewImportReceiptStore()
	pending := testImportReceipt("run-pending", "tenant-a")
	pending.Digest = "sha256:pending"
	pending.Outcome = importreceipt.OutcomePending
	if _, created, err := store.CreateOrGet(ctx, "tenant-a", pending); err != nil || !created {
		t.Fatalf("create pending = created:%v err:%v", created, err)
	}

	at := pending.CreatedAt.Add(time.Second)
	counters := importreceipt.Counters{Accepted: 2, Deduplicated: 1, Refused: 3}
	got, err := store.Finalize(ctx, "tenant-a", pending.ID, importreceipt.OutcomePartial, counters, at)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if got.Outcome != importreceipt.OutcomePartial || got.Counters != counters || !got.UpdatedAt.Equal(at) {
		t.Fatalf("finalized receipt = %+v", got)
	}
	if _, err := store.Finalize(ctx, "tenant-a", pending.ID, importreceipt.OutcomePartial, counters, at.Add(time.Second)); err != nil {
		t.Fatalf("same final result must be idempotent: %v", err)
	}
	if _, err := store.Finalize(ctx, "tenant-a", pending.ID, importreceipt.OutcomeComplete, counters, at.Add(2*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("rewrite terminal receipt err = %v, want ErrConflict", err)
	}
	invalidCounters := importreceipt.Counters{Accepted: -1}
	if _, err := store.Finalize(ctx, "tenant-a", pending.ID, importreceipt.OutcomePartial, invalidCounters, at.Add(3*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("invalid terminal rewrite err = %v, want ErrConflict", err)
	}
}
