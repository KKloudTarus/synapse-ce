package postgres

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func postgresDocumentCommand(id, key string, now time.Time) ports.DocumentCommand {
	target := docpublish.Target{IntegrationID: "doc-integration-a", SourceKind: docpublish.EngagementReport, SourceRef: "command-report", Scope: docpublish.Engagement, ScopeID: "doc-engagement-a", Container: "SEC"}
	intent := docpublish.Intent{ID: shared.ID(id), TenantID: "doc-a", Target: target, Action: docpublish.Create, RequestKey: key, PayloadDigest: strings.Repeat("a", 64), ContentHash: strings.Repeat("b", 64), Marker: docpublish.MarkerFor(shared.ID(id)), State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
	return ports.DocumentCommand{Intent: intent, Actor: ports.DocumentActor{UserID: "admin"}, ConnectionRevision: 1, CredentialRevision: 0, ReadGroup: "restricted", Artifact: ports.DocumentArtifact{Title: "Report", Paragraphs: []string{"body"}, PDF: []byte("pdf"), SourceRevision: "source-v1", GeneratedAt: now}, Progress: ports.DocumentProgress{Version: 1, IntentVersion: 1, Step: "shell", UpdatedAt: now}}
}

func TestDocumentCommandStorePostgresAdmissionProgressAndRLS(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	seedDocumentTenants(t, ctx, pool)
	store, err := NewDocumentStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	command := postgresDocumentCommand("doc-command-1", "command-one", now)
	first, created, err := store.CreateDocumentCommand(ctx, "doc-a", command)
	if err != nil || !created {
		t.Fatalf("create command created=%t err=%v", created, err)
	}
	if replay, created, err := store.CreateDocumentCommand(ctx, "doc-a", command); err != nil || created || replay.Intent.ID != first.Intent.ID {
		t.Fatalf("exact replay created=%t result=%+v err=%v", created, replay, err)
	}

	// Admission is serialized at the durable target fence even when request keys differ.
	second := postgresDocumentCommand("doc-command-2", "command-two", now.Add(time.Second))
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, candidate := range []ports.DocumentCommand{command, second} {
		wait.Add(1)
		go func(candidate ports.DocumentCommand) {
			defer wait.Done()
			<-start
			_, _, e := store.CreateDocumentCommand(context.Background(), "doc-a", candidate)
			results <- e
		}(candidate)
	}
	close(start)
	wait.Wait()
	close(results)
	var conflicts int
	for err := range results {
		if errors.Is(err, shared.ErrConflict) {
			conflicts++
		} else if err != nil {
			t.Fatalf("concurrent admission: %v", err)
		}
	}
	if conflicts == 0 {
		t.Fatal("distinct active command bypassed target fence")
	}

	lease := now.Add(time.Minute)
	claimed, err := store.TransitionIntent(ctx, "doc-a", first.Intent.ID, first.Intent.Version, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now)
	if err != nil {
		t.Fatal(err)
	}
	progress := first.Progress
	progress.IntentVersion, progress.LeaseUntil, progress.UpdatedAt = claimed.Version, &lease, now.Add(time.Second)
	progress.Step = "restrictions"
	checkpoint, err := store.SaveDocumentProgress(ctx, "doc-a", first.Intent.ID, first.Progress.Version, progress)
	if err != nil || checkpoint.Progress.Version != 2 {
		t.Fatalf("save checkpoint=%+v err=%v", checkpoint.Progress, err)
	}
	if _, err := store.SaveDocumentProgress(ctx, "doc-a", first.Intent.ID, 1, progress); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale checkpoint err=%v", err)
	}
	if _, err := store.GetDocumentCommand(ctx, "doc-b", first.Intent.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross tenant command err=%v", err)
	}
}

func TestDocumentCommandStorePostgresYieldRequiresCleanCheckpoint(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	seedDocumentTenants(t, ctx, pool)
	store, err := NewDocumentStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	command := postgresDocumentCommand("doc-yield", "yield", now)
	saved, _, err := store.CreateDocumentCommand(ctx, "doc-a", command)
	if err != nil {
		t.Fatal(err)
	}
	lease := now.Add(time.Minute)
	claimed, err := store.TransitionIntent(ctx, "doc-a", saved.Intent.ID, saved.Intent.Version, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now)
	if err != nil {
		t.Fatal(err)
	}
	progress := saved.Progress
	progress.IntentVersion, progress.LeaseUntil, progress.UpdatedAt = claimed.Version, &lease, now.Add(time.Second)
	progress.Step = "restrictions"
	progress.Remote = docpublish.RemotePage{ID: "page", Version: 1, Revision: "opaque", URL: "https://wiki.example/pages/page"}
	progress.UploadedReceipts = []ports.DocumentUploadReceipt{{Key: "attachment:0", Digest: strings.Repeat("c", 64)}}
	checkpoint, err := store.SaveDocumentProgress(ctx, "doc-a", saved.Intent.ID, saved.Progress.Version, progress)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.TransitionIntent(ctx, "doc-a", saved.Intent.ID, claimed.Version, docpublish.IntentTransition{Event: docpublish.CheckpointYield}, now.Add(2*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("generic yield err=%v, want conflict", err)
	}
	if _, err := store.YieldDocumentCommand(ctx, "doc-b", saved.Intent.ID, claimed.Version, checkpoint.Progress.Version, now.Add(2*time.Second)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross tenant yield err=%v, want not found", err)
	}
	yielded, err := store.YieldDocumentCommand(ctx, "doc-a", saved.Intent.ID, claimed.Version, checkpoint.Progress.Version, now.Add(2*time.Second))
	if err != nil || yielded.Intent.State != writeintent.Pending || yielded.Intent.Attempts != 0 || yielded.Progress.LeaseUntil != nil || yielded.Progress.Remote.Revision != "opaque" || len(yielded.Progress.UploadedReceipts) != 1 {
		t.Fatalf("yielded=%+v err=%v", yielded, err)
	}
	if _, err := store.YieldDocumentCommand(ctx, "doc-a", saved.Intent.ID, claimed.Version, checkpoint.Progress.Version, now.Add(3*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale yield err=%v, want conflict", err)
	}

	clean := postgresDocumentCommand("doc-yield-clean", "yield-clean", now)
	clean.Intent.SourceRef = "report-clean"
	cleanSaved, _, err := store.CreateDocumentCommand(ctx, "doc-a", clean)
	if err != nil {
		t.Fatal(err)
	}
	cleanClaimed, err := store.TransitionIntent(ctx, "doc-a", cleanSaved.Intent.ID, cleanSaved.Intent.Version, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now)
	if err != nil {
		t.Fatal(err)
	}
	cleanProgress := cleanSaved.Progress
	cleanProgress.IntentVersion, cleanProgress.LeaseUntil, cleanProgress.UpdatedAt = cleanClaimed.Version, &lease, now.Add(time.Second)
	cleanProgress.Step = "restrictions"
	cleanProgress.Remote = docpublish.RemotePage{ID: "page-clean", Version: 1, Revision: "opaque-clean", URL: "https://wiki.example/pages/clean"}
	cleanCheckpoint, err := store.SaveDocumentProgress(ctx, "doc-a", cleanSaved.Intent.ID, cleanSaved.Progress.Version, cleanProgress)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{lease, lease.Add(time.Nanosecond)} {
		if _, err := store.YieldDocumentCommand(ctx, "doc-a", cleanSaved.Intent.ID, cleanClaimed.Version, cleanCheckpoint.Progress.Version, at); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("clean checkpoint yielded at expired lease %s: %v", at, err)
		}
	}
}

func TestDocumentCommandStorePostgresFairQueueAdvancesPastUnresolvedCommands(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	seedDocumentTenants(t, ctx, pool)
	store, err := NewDocumentStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC)
	for n := 0; n < 21; n++ {
		command := postgresDocumentCommand("doc-fair-"+string(rune('a'+n)), "fair-"+string(rune('a'+n)), now)
		command.Intent.SourceRef = "fair-" + string(rune('a'+n))
		if _, _, err := store.CreateDocumentCommand(ctx, "doc-a", command); err != nil {
			t.Fatalf("create unresolved %d: %v", n, err)
		}
		lease := now.Add(time.Minute)
		claimed, err := store.TransitionIntent(ctx, "doc-a", command.Intent.ID, 1, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.TransitionIntent(ctx, "doc-a", command.Intent.ID, claimed.Version, docpublish.IntentTransition{Event: writeintent.Ambiguous}, now); err != nil {
			t.Fatal(err)
		}
	}
	pending := postgresDocumentCommand("doc-fair-z", "fair-z", now)
	pending.Intent.SourceRef = "fair-z"
	if _, _, err := store.CreateDocumentCommand(ctx, "doc-a", pending); err != nil {
		t.Fatal(err)
	}
	first, err := store.ListDocumentCommands(ctx, "doc-a", 20, now)
	if err != nil || len(first) != 20 {
		t.Fatalf("first fair list len=%d err=%v", len(first), err)
	}
	second, err := store.ListDocumentCommands(ctx, "doc-a", 20, now)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range second {
		if item.Intent.ID == pending.Intent.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("unvisited pending command was starved by unresolved commands: %+v", second)
	}

	create := func(id, key string) ports.DocumentCommand {
		command := postgresDocumentCommand(id, key, now)
		command.Intent.SourceRef = key
		if _, _, err := store.CreateDocumentCommand(ctx, "doc-a", command); err != nil {
			t.Fatalf("create queue state %s: %v", id, err)
		}
		return command
	}
	retryable := create("doc-fair-retryable", "fair-retryable")
	retryClaimed, err := store.TransitionIntent(ctx, "doc-a", retryable.Intent.ID, 1, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: ptrTime(now.Add(2 * time.Minute))}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.TransitionIntent(ctx, "doc-a", retryable.Intent.ID, retryClaimed.Version, docpublish.IntentTransition{Event: writeintent.Reject, ErrorCode: "provider_refused"}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	terminal := create("doc-fair-terminal", "fair-terminal")
	terminalClaimed, err := store.TransitionIntent(ctx, "doc-a", terminal.Intent.ID, 1, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: ptrTime(now.Add(2 * time.Minute))}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.TransitionIntent(ctx, "doc-a", terminal.Intent.ID, terminalClaimed.Version, docpublish.IntentTransition{Event: writeintent.Reject, ErrorCode: "provider_refused"}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE document_intents SET attempts=5 WHERE tenant_id='doc-a' AND id=$1`, terminal.Intent.ID.String()); err != nil {
		t.Fatal(err)
	}
	expired := create("doc-fair-expired", "fair-expired")
	if _, err = store.TransitionIntent(ctx, "doc-a", expired.Intent.ID, 1, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: ptrTime(now.Add(2 * time.Minute))}, now); err != nil {
		t.Fatal(err)
	}
	future := create("doc-fair-future", "fair-future")
	if _, err = store.TransitionIntent(ctx, "doc-a", future.Intent.ID, 1, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: ptrTime(now.Add(3 * time.Minute))}, now); err != nil {
		t.Fatal(err)
	}
	selected, err := store.ListDocumentCommands(ctx, "doc-a", 100, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[shared.ID]bool{}
	for _, item := range selected {
		seen[item.Intent.ID] = true
	}
	if !seen[retryable.Intent.ID] || !seen[expired.Intent.ID] || seen[terminal.Intent.ID] || seen[future.Intent.ID] {
		t.Fatalf("eligible queue states retryable=%t expired=%t terminal=%t future=%t", seen[retryable.Intent.ID], seen[expired.Intent.ID], seen[terminal.Intent.ID], seen[future.Intent.ID])
	}
	if other, err := store.ListDocumentCommands(ctx, "doc-b", 100, now.Add(2*time.Minute)); err != nil || len(other) != 0 {
		t.Fatalf("cross-tenant queue selection=%+v err=%v", other, err)
	}
}

func TestDocumentCommandStorePostgresDeferralRequiresLiveMatchingLease(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	seedDocumentTenants(t, ctx, pool)
	store, err := NewDocumentStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 17, 15, 0, 0, 0, time.UTC)
	command := postgresDocumentCommand("doc-defer-lease", "defer-lease", now)
	command.Intent.SourceRef = "report-defer-lease"
	saved, _, err := store.CreateDocumentCommand(ctx, "doc-a", command)
	if err != nil {
		t.Fatal(err)
	}
	lease := now.Add(time.Minute)
	claimed, err := store.TransitionIntent(ctx, "doc-a", saved.Intent.ID, saved.Intent.Version, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now)
	if err != nil {
		t.Fatal(err)
	}
	progress := saved.Progress
	progress.IntentVersion, progress.LeaseUntil, progress.UpdatedAt = claimed.Version, &lease, now.Add(time.Second)
	progress.Step = "restrictions"
	progress.Remote = docpublish.RemotePage{ID: "page-defer", Version: 1, Revision: "opaque-defer", URL: "https://wiki.example/pages/defer"}
	saved, err = store.SaveDocumentProgress(ctx, "doc-a", saved.Intent.ID, saved.Progress.Version, progress)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{lease, lease.Add(time.Nanosecond)} {
		if _, err := store.DeferDocumentCommand(ctx, "doc-a", saved.Intent.ID, claimed.Version, saved.Progress.Version, saved.QueueVersion, at.Add(time.Minute), at, ports.DocumentRetryUncertain, ""); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("uncertain deferral accepted at expired lease %s: %v", at, err)
		}
		if _, err := store.DeferDocumentCommand(ctx, "doc-a", saved.Intent.ID, claimed.Version, saved.Progress.Version, saved.QueueVersion, at.Add(time.Minute), at, ports.DocumentRetryReject, "provider_refused"); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("reject deferral accepted at expired lease %s: %v", at, err)
		}
	}
	mismatched := lease.Add(time.Second)
	if _, err := pool.Exec(ctx, `UPDATE document_commands
		SET progress=jsonb_set(progress,'{LeaseUntil}',to_jsonb($3::text),true)
		WHERE tenant_id=$1 AND intent_id=$2`, "doc-a", saved.Intent.ID.String(), mismatched.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("corrupt test progress lease: %v", err)
	}
	if _, err := store.DeferDocumentCommand(ctx, "doc-a", saved.Intent.ID, claimed.Version, saved.Progress.Version, saved.QueueVersion, now.Add(2*time.Minute), now.Add(2*time.Second), ports.DocumentRetryUncertain, ""); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("uncertain deferral accepted mismatched progress lease: %v", err)
	}
}

func TestDocumentCommandStorePostgresDeferralReturnsPersistedCommand(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	seedDocumentTenants(t, ctx, pool)
	store, err := NewDocumentStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 17, 16, 0, 0, 0, time.UTC)
	command := postgresDocumentCommand("doc-defer-return", "defer-return", now)
	command.Intent.SourceRef = "report-defer-return"
	saved, _, err := store.CreateDocumentCommand(ctx, "doc-a", command)
	if err != nil {
		t.Fatal(err)
	}
	lease := now.Add(time.Minute)
	claimed, err := store.TransitionIntent(ctx, "doc-a", saved.Intent.ID, saved.Intent.Version, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now)
	if err != nil {
		t.Fatal(err)
	}
	progress := saved.Progress
	progress.IntentVersion, progress.LeaseUntil, progress.UpdatedAt = claimed.Version, &lease, now.Add(time.Second)
	progress.Step = "attachments"
	progress.Remote = docpublish.RemotePage{ID: "page-return", Version: 7, Revision: "opaque-return", URL: "https://wiki.example/pages/return"}
	progress.OutstandingOperation, progress.OutstandingKey, progress.OutstandingDigest = "attachment", "attachment:0", strings.Repeat("d", 64)
	progress.ExpectedRemoteVersion, progress.ExpectedRemoteRevision = 7, "opaque-return"
	saved, err = store.SaveDocumentProgress(ctx, "doc-a", saved.Intent.ID, saved.Progress.Version, progress)
	if err != nil {
		t.Fatal(err)
	}
	deferred, err := store.DeferDocumentCommand(ctx, "doc-a", saved.Intent.ID, claimed.Version, saved.Progress.Version, saved.QueueVersion, now.Add(2*time.Minute), now.Add(2*time.Second), ports.DocumentRetryUncertain, "")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := store.GetDocumentCommand(ctx, "doc-a", saved.Intent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(deferred, fresh) || deferred.Progress.Remote.Revision != "opaque-return" || deferred.Progress.Version != fresh.Progress.Version || deferred.QueueVersion != fresh.QueueVersion || !deferred.NextAttemptAt.Equal(now.Add(2*time.Minute)) || !reflect.DeepEqual(deferred.Artifact, fresh.Artifact) {
		t.Fatalf("deferred=%+v fresh=%+v", deferred, fresh)
	}
}

func TestDocumentCommandStorePostgresClaimHonorsConcurrentRetryDeferral(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	seedDocumentTenants(t, ctx, pool)
	store, err := NewDocumentStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 17, 16, 0, 0, 0, time.UTC)
	command := postgresDocumentCommand("doc-defer-claim", "defer-claim", now)
	command.Intent.SourceRef = "report-defer-claim"
	saved, _, err := store.CreateDocumentCommand(ctx, "doc-a", command)
	if err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(time.Minute)
	deferred, err := store.DeferDocumentCommand(ctx, "doc-a", saved.Intent.ID, saved.Intent.Version, saved.Progress.Version, saved.QueueVersion, deadline, now, ports.DocumentRetryKeep, "")
	if err != nil {
		t.Fatal(err)
	}
	lease := deadline.Add(time.Minute)
	if _, err := store.TransitionIntent(ctx, "doc-a", saved.Intent.ID, saved.Intent.Version, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale claimant bypassed provider deferral: %v", err)
	}
	claimed, err := store.TransitionIntent(ctx, "doc-a", saved.Intent.ID, saved.Intent.Version, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, deadline)
	if err != nil || claimed.State != writeintent.InFlight || !deferred.NextAttemptAt.Equal(deadline) {
		t.Fatalf("claim at retry due intent=%+v deferred=%+v err=%v", claimed, deferred, err)
	}
}
