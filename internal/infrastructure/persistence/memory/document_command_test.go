package memory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func documentCommandForTest(f, engagement, integration, id shared.ID, key string, now time.Time) ports.DocumentCommand {
	target := docpublish.Target{IntegrationID: integration, SourceKind: docpublish.EngagementReport, SourceRef: "report", Scope: docpublish.Engagement, ScopeID: engagement, Container: "SEC"}
	intent := docpublish.Intent{ID: id, TenantID: f, Target: target, Action: docpublish.Create, RequestKey: key, PayloadDigest: strings.Repeat("a", 64), ContentHash: strings.Repeat("b", 64), Marker: docpublish.MarkerFor(id), State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
	return ports.DocumentCommand{Intent: intent, Actor: ports.DocumentActor{UserID: "user"}, ConnectionRevision: 1, CredentialRevision: 0, ReadGroup: "restricted", Artifact: ports.DocumentArtifact{Title: "Report", Paragraphs: []string{"body"}, PDF: []byte("pdf"), EvidenceHead: "head", SourceRevision: "v1", GeneratedAt: now}, Progress: ports.DocumentProgress{Version: 1, IntentVersion: 1, Step: "shell", UpdatedAt: now}}
}

func TestDocumentCommandStoreMemoryAdmissionAndCheckpointCAS(t *testing.T) {
	store, fixture := newDocumentStoreForTest(t)
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	command := documentCommandForTest(fixture.Tenant, fixture.Engagement, fixture.Integration, "document-command", "request", now)
	saved, created, err := store.CreateDocumentCommand(context.Background(), fixture.Tenant, command)
	if err != nil || !created {
		t.Fatalf("create command created=%t err=%v", created, err)
	}
	replay, created, err := store.CreateDocumentCommand(context.Background(), fixture.Tenant, command)
	if err != nil || created || replay.Intent.ID != saved.Intent.ID {
		t.Fatalf("exact replay created=%t command=%+v err=%v", created, replay, err)
	}
	second := documentCommandForTest(fixture.Tenant, fixture.Engagement, fixture.Integration, "document-command-second", "request-second", now.Add(time.Second))
	if _, _, err := store.CreateDocumentCommand(context.Background(), fixture.Tenant, second); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("active target command err=%v, want conflict", err)
	}
	lease := now.Add(time.Minute)
	claimed, err := store.TransitionIntent(context.Background(), fixture.Tenant, saved.Intent.ID, saved.Intent.Version, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	progress := saved.Progress
	progress.IntentVersion, progress.LeaseUntil, progress.UpdatedAt = claimed.Version, &lease, now.Add(time.Second)
	checkpoint, err := store.SaveDocumentProgress(context.Background(), fixture.Tenant, saved.Intent.ID, saved.Progress.Version, progress)
	if err != nil || checkpoint.Progress.Version != 2 {
		t.Fatalf("checkpoint=%+v err=%v", checkpoint.Progress, err)
	}
	if _, err := store.SaveDocumentProgress(context.Background(), fixture.Tenant, saved.Intent.ID, 1, progress); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale progress checkpoint err=%v, want conflict", err)
	}
	if _, err := store.SaveDocumentProgress(context.Background(), fixture.Tenant, saved.Intent.ID, 2, ports.DocumentProgress{Version: 2, IntentVersion: claimed.Version, UpdatedAt: now.Add(time.Second)}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("lease-free in-flight checkpoint err=%v, want conflict", err)
	}
}

func TestDocumentCommandStoreMemoryResumeRequiresUncertainCAS(t *testing.T) {
	store, fixture := newDocumentStoreForTest(t)
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	command := documentCommandForTest(fixture.Tenant, fixture.Engagement, fixture.Integration, "document-resume", "resume", now)
	saved, _, err := store.CreateDocumentCommand(context.Background(), fixture.Tenant, command)
	if err != nil {
		t.Fatal(err)
	}
	lease := now.Add(time.Minute)
	claimed, err := store.TransitionIntent(context.Background(), fixture.Tenant, saved.Intent.ID, 1, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now)
	if err != nil {
		t.Fatal(err)
	}
	uncertain, err := store.TransitionIntent(context.Background(), fixture.Tenant, saved.Intent.ID, claimed.Version, docpublish.IntentTransition{Event: writeintent.Ambiguous}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	progress := saved.Progress
	progress.IntentVersion, progress.UpdatedAt, progress.OutstandingOperation = uncertain.Version, now.Add(2*time.Second), "body"
	resumed, err := store.ResumeDocumentCommand(context.Background(), fixture.Tenant, saved.Intent.ID, uncertain.Version, 1, progress, now.Add(2*time.Second))
	if err != nil || resumed.Intent.State != writeintent.Pending || resumed.Intent.Version != uncertain.Version+1 || resumed.Progress.Version != 2 {
		t.Fatalf("resume=%+v err=%v", resumed, err)
	}
	if _, err := store.ResumeDocumentCommand(context.Background(), fixture.Tenant, saved.Intent.ID, uncertain.Version, 1, progress, now.Add(3*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale resume err=%v, want conflict", err)
	}
}

func TestDocumentCommandStoreMemoryFairQueueAdvancesPastUnresolvedCommands(t *testing.T) {
	store, fixture := newDocumentStoreForTest(t)
	now := time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC)
	for n := 0; n < 21; n++ {
		id := shared.ID("fair-" + string(rune('a'+n)))
		command := documentCommandForTest(fixture.Tenant, fixture.Engagement, fixture.Integration, id, "fair-"+string(rune('a'+n)), now)
		command.Intent.SourceRef = "fair-" + string(rune('a'+n))
		if _, _, err := store.CreateDocumentCommand(context.Background(), fixture.Tenant, command); err != nil {
			t.Fatal(err)
		}
		lease := now.Add(time.Minute)
		claimed, err := store.TransitionIntent(context.Background(), fixture.Tenant, command.Intent.ID, 1, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.TransitionIntent(context.Background(), fixture.Tenant, command.Intent.ID, claimed.Version, docpublish.IntentTransition{Event: writeintent.Ambiguous}, now); err != nil {
			t.Fatal(err)
		}
	}
	pending := documentCommandForTest(fixture.Tenant, fixture.Engagement, fixture.Integration, "fair-z", "fair-z", now)
	pending.Intent.SourceRef = "fair-z"
	if _, _, err := store.CreateDocumentCommand(context.Background(), fixture.Tenant, pending); err != nil {
		t.Fatal(err)
	}
	if first, err := store.ListDocumentCommands(context.Background(), fixture.Tenant, 20, now); err != nil || len(first) != 20 {
		t.Fatalf("first fair list len=%d err=%v", len(first), err)
	}
	second, err := store.ListDocumentCommands(context.Background(), fixture.Tenant, 20, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range second {
		if item.Intent.ID == pending.Intent.ID {
			return
		}
	}
	t.Fatalf("unvisited pending command was starved by unresolved commands: %+v", second)
}
