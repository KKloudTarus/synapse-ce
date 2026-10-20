package postgres

import (
	"context"
	"errors"
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
}
