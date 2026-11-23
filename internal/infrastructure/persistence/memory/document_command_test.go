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
	progress.Step = "restrictions"
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

func TestDocumentCommandStoreMemoryReplaysTrashWithoutArtifact(t *testing.T) {
	store, fixture := newDocumentStoreForTest(t)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	target := docpublish.Target{IntegrationID: fixture.Integration, SourceKind: docpublish.EngagementReport, SourceRef: "trash-report", Scope: docpublish.Engagement, ScopeID: fixture.Engagement, Container: "SEC"}
	link := docpublish.Link{ID: "trash-link", TenantID: fixture.Tenant, Target: target, RemotePageID: "page", RemoteVersion: 1, RemoteURL: "https://wiki.example/page", ContentHash: strings.Repeat("a", 64), AccessProfile: docpublish.DestinationManagedSnapshotProfile, Revision: 1, CreatedAt: now, UpdatedAt: now}
	store.links[fixture.Tenant] = map[shared.ID]docpublish.Link{link.ID: link}
	intent := docpublish.Intent{ID: "trash-intent", TenantID: fixture.Tenant, Target: target, LinkID: link.ID, ExpectedLinkRevision: link.Revision, Action: docpublish.Trash, RequestKey: "trash-request", PayloadDigest: strings.Repeat("b", 64), ContentHash: link.ContentHash, AccessProfile: docpublish.DestinationManagedSnapshotProfile, Marker: docpublish.MarkerFor("trash-intent"), State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
	command := ports.DocumentCommand{Intent: intent, Actor: ports.DocumentActor{UserID: "user"}, ConnectionRevision: 1, ReadGroup: "destination-owner", AccessProfile: intent.AccessProfile}
	first, created, err := store.CreateDocumentCommand(context.Background(), fixture.Tenant, command)
	if err != nil || !created {
		t.Fatalf("create trash command created=%t err=%v", created, err)
	}
	replay, created, err := store.CreateDocumentCommand(context.Background(), fixture.Tenant, command)
	if err != nil || created || replay.Intent.ID != first.Intent.ID {
		t.Fatalf("replay trash created=%t result=%+v err=%v", created, replay, err)
	}
}

func TestDocumentCommandStoreMemoryDefersCleanTrashRetry(t *testing.T) {
	store, fixture := newDocumentStoreForTest(t)
	now := time.Date(2026, 10, 26, 13, 0, 0, 0, time.UTC)
	target := docpublish.Target{IntegrationID: fixture.Integration, SourceKind: docpublish.EngagementReport, SourceRef: "trash-retry", Scope: docpublish.Engagement, ScopeID: fixture.Engagement, Container: "SEC"}
	link := docpublish.Link{ID: "trash-retry-link", TenantID: fixture.Tenant, Target: target, RemotePageID: "page", RemoteVersion: 1, RemoteURL: "https://wiki.example/page", ContentHash: strings.Repeat("a", 64), AccessProfile: docpublish.DestinationManagedSnapshotProfile, Revision: 1, CreatedAt: now, UpdatedAt: now}
	store.links[fixture.Tenant] = map[shared.ID]docpublish.Link{link.ID: link}
	intent := docpublish.Intent{ID: "trash-retry-intent", TenantID: fixture.Tenant, Target: target, LinkID: link.ID, ExpectedLinkRevision: link.Revision, Action: docpublish.Trash, RequestKey: "trash-retry-request", PayloadDigest: strings.Repeat("b", 64), ContentHash: link.ContentHash, AccessProfile: docpublish.DestinationManagedSnapshotProfile, Marker: docpublish.MarkerFor("trash-retry-intent"), State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
	saved, created, err := store.CreateDocumentCommand(context.Background(), fixture.Tenant, ports.DocumentCommand{Intent: intent, Actor: ports.DocumentActor{UserID: "user"}, ConnectionRevision: 1, ReadGroup: "destination-owner", AccessProfile: intent.AccessProfile})
	if err != nil || !created {
		t.Fatalf("create trash command created=%t err=%v", created, err)
	}
	lease := now.Add(5 * time.Minute)
	claimed, err := store.TransitionIntent(context.Background(), fixture.Tenant, saved.Intent.ID, saved.Intent.Version, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now)
	if err != nil {
		t.Fatalf("claim trash: %v", err)
	}
	progress := saved.Progress
	progress.IntentVersion, progress.LeaseUntil, progress.UpdatedAt = claimed.Version, &lease, now.Add(time.Second)
	saved, err = store.SaveDocumentProgress(context.Background(), fixture.Tenant, saved.Intent.ID, saved.Progress.Version, progress)
	if err != nil {
		t.Fatalf("checkpoint pre-dispatch trash: %v", err)
	}
	deadline := now.Add(2 * time.Minute)
	deferred, err := store.DeferDocumentCommand(context.Background(), fixture.Tenant, saved.Intent.ID, claimed.Version, saved.Progress.Version, saved.QueueVersion, deadline, now.Add(time.Second), ports.DocumentRetryRelease, "")
	if err != nil || deferred.Intent.State != writeintent.Pending || !deferred.NextAttemptAt.Equal(deadline) || deferred.Progress.Step != "trash" || deferred.Progress.Remote.ID != link.RemotePageID {
		t.Fatalf("defer clean trash=%+v err=%v", deferred, err)
	}
	if stored := store.links[fixture.Tenant][link.ID]; stored != link {
		t.Fatalf("pre-dispatch retry changed link: got=%+v want=%+v", stored, link)
	}
	if _, err := store.TransitionIntent(context.Background(), fixture.Tenant, saved.Intent.ID, deferred.Intent.Version, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, deadline); err != nil {
		t.Fatalf("resume deferred trash: %v", err)
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

func TestDocumentCommandStoreMemoryYieldRequiresCleanCheckpointAndFencesWorkers(t *testing.T) {
	store, fixture := newDocumentStoreForTest(t)
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	command := documentCommandForTest(fixture.Tenant, fixture.Engagement, fixture.Integration, "document-yield", "yield", now)
	saved, _, err := store.CreateDocumentCommand(context.Background(), fixture.Tenant, command)
	if err != nil {
		t.Fatal(err)
	}
	lease := now.Add(time.Minute)
	claimed, err := store.TransitionIntent(context.Background(), fixture.Tenant, saved.Intent.ID, saved.Intent.Version, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now)
	if err != nil {
		t.Fatal(err)
	}
	progress := saved.Progress
	progress.IntentVersion, progress.LeaseUntil, progress.UpdatedAt = claimed.Version, &lease, now.Add(time.Second)
	progress.Step = "restrictions"
	progress.Remote = docpublish.RemotePage{ID: "page", Version: 1, Revision: "opaque", URL: "https://wiki.example/pages/page"}
	progress.UploadedReceipts = []ports.DocumentUploadReceipt{{Key: "attachment:0", Digest: strings.Repeat("c", 64)}}
	checkpoint, err := store.SaveDocumentProgress(context.Background(), fixture.Tenant, saved.Intent.ID, saved.Progress.Version, progress)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.TransitionIntent(context.Background(), fixture.Tenant, saved.Intent.ID, claimed.Version, docpublish.IntentTransition{Event: docpublish.CheckpointYield}, now.Add(2*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("generic yield err=%v, want conflict", err)
	}
	if _, err := store.YieldDocumentCommand(context.Background(), fixture.Tenant, saved.Intent.ID, claimed.Version-1, checkpoint.Progress.Version, now.Add(2*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale intent yield err=%v, want conflict", err)
	}
	if _, err := store.YieldDocumentCommand(context.Background(), "other-tenant", saved.Intent.ID, claimed.Version, checkpoint.Progress.Version, now.Add(2*time.Second)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant yield err=%v, want not found", err)
	}
	yielded, err := store.YieldDocumentCommand(context.Background(), fixture.Tenant, saved.Intent.ID, claimed.Version, checkpoint.Progress.Version, now.Add(2*time.Second))
	if err != nil || yielded.Intent.State != writeintent.Pending || yielded.Intent.LeaseUntil != nil || yielded.Intent.Attempts != 0 || yielded.Progress.LeaseUntil != nil || yielded.Progress.Remote.Revision != "opaque" || len(yielded.Progress.UploadedReceipts) != 1 {
		t.Fatalf("yielded=%+v err=%v", yielded, err)
	}
	if _, err := store.TransitionIntent(context.Background(), fixture.Tenant, saved.Intent.ID, claimed.Version, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now.Add(3*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale claimant err=%v, want conflict", err)
	}
	if _, err := store.YieldDocumentCommand(context.Background(), fixture.Tenant, saved.Intent.ID, claimed.Version, checkpoint.Progress.Version, now.Add(3*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate yield err=%v, want conflict", err)
	}

	// A stored operation marker means the remote acknowledgement was not yet
	// proven locally; releasing its lease would permit an unsafe retry.
	dirty := documentCommandForTest(fixture.Tenant, fixture.Engagement, fixture.Integration, "document-yield-dirty", "yield-dirty", now)
	dirty.Intent.SourceRef = "report-dirty"
	dirtySaved, _, err := store.CreateDocumentCommand(context.Background(), fixture.Tenant, dirty)
	if err != nil {
		t.Fatal(err)
	}
	dirtyClaimed, err := store.TransitionIntent(context.Background(), fixture.Tenant, dirtySaved.Intent.ID, dirtySaved.Intent.Version, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now)
	if err != nil {
		t.Fatal(err)
	}
	dirtyProgress := dirtySaved.Progress
	dirtyProgress.IntentVersion, dirtyProgress.LeaseUntil, dirtyProgress.UpdatedAt = dirtyClaimed.Version, &lease, now.Add(time.Second)
	dirtyProgress.OutstandingOperation, dirtyProgress.OutstandingKey, dirtyProgress.OutstandingDigest = "attachment", "attachment:0", strings.Repeat("d", 64)
	dirtyCheckpoint, err := store.SaveDocumentProgress(context.Background(), fixture.Tenant, dirtySaved.Intent.ID, dirtySaved.Progress.Version, dirtyProgress)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.YieldDocumentCommand(context.Background(), fixture.Tenant, dirtySaved.Intent.ID, dirtyClaimed.Version, dirtyCheckpoint.Progress.Version, now.Add(2*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("outstanding yield err=%v, want conflict", err)
	}
	if _, err := store.YieldDocumentCommand(context.Background(), fixture.Tenant, dirtySaved.Intent.ID, dirtyClaimed.Version, dirtyCheckpoint.Progress.Version, lease); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expired lease yielded: %v", err)
	}

	fresh := documentCommandForTest(fixture.Tenant, fixture.Engagement, fixture.Integration, "document-yield-fresh", "yield-fresh", now)
	fresh.Intent.SourceRef = "report-fresh"
	freshSaved, _, err := store.CreateDocumentCommand(context.Background(), fixture.Tenant, fresh)
	if err != nil {
		t.Fatal(err)
	}
	freshClaimed, err := store.TransitionIntent(context.Background(), fixture.Tenant, freshSaved.Intent.ID, freshSaved.Intent.Version, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now)
	if err != nil {
		t.Fatal(err)
	}
	freshProgress := freshSaved.Progress
	freshProgress.IntentVersion, freshProgress.LeaseUntil, freshProgress.UpdatedAt = freshClaimed.Version, &lease, now.Add(time.Second)
	freshProgress.Step = "restrictions"
	freshProgress.Remote = docpublish.RemotePage{ID: "page-fresh", Version: 1, URL: "https://wiki.example/pages/fresh"}
	freshCheckpoint, err := store.SaveDocumentProgress(context.Background(), fixture.Tenant, freshSaved.Intent.ID, freshSaved.Progress.Version, freshProgress)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{lease, lease.Add(time.Nanosecond)} {
		if cleanDocumentYieldCheckpoint(freshCheckpoint.Progress, freshClaimed, at) {
			t.Fatalf("clean checkpoint eligibility accepted expired lease %s", at)
		}
		if _, err := store.YieldDocumentCommand(context.Background(), fixture.Tenant, freshSaved.Intent.ID, freshClaimed.Version, freshCheckpoint.Progress.Version, at); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("clean checkpoint yielded at expired lease %s: %v", at, err)
		}
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

func TestDocumentCommandStoreMemoryDeferralRequiresLiveMatchingLease(t *testing.T) {
	store, fixture := newDocumentStoreForTest(t)
	now := time.Date(2026, 10, 17, 15, 0, 0, 0, time.UTC)
	command := documentCommandForTest(fixture.Tenant, fixture.Engagement, fixture.Integration, "document-defer-lease", "defer-lease", now)
	command.Intent.SourceRef = "report-defer-lease"
	saved, _, err := store.CreateDocumentCommand(context.Background(), fixture.Tenant, command)
	if err != nil {
		t.Fatal(err)
	}
	lease := now.Add(time.Minute)
	claimed, err := store.TransitionIntent(context.Background(), fixture.Tenant, saved.Intent.ID, saved.Intent.Version, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now)
	if err != nil {
		t.Fatal(err)
	}
	progress := saved.Progress
	progress.IntentVersion, progress.LeaseUntil, progress.UpdatedAt = claimed.Version, &lease, now.Add(time.Second)
	progress.Step = "restrictions"
	progress.Remote = docpublish.RemotePage{ID: "page-defer", Version: 1, URL: "https://wiki.example/pages/defer"}
	saved, err = store.SaveDocumentProgress(context.Background(), fixture.Tenant, saved.Intent.ID, saved.Progress.Version, progress)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{lease, lease.Add(time.Nanosecond)} {
		if _, err := store.DeferDocumentCommand(context.Background(), fixture.Tenant, saved.Intent.ID, claimed.Version, saved.Progress.Version, saved.QueueVersion, at.Add(time.Minute), at, ports.DocumentRetryUncertain, ""); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("uncertain deferral accepted at expired lease %s: %v", at, err)
		}
		if _, err := store.DeferDocumentCommand(context.Background(), fixture.Tenant, saved.Intent.ID, claimed.Version, saved.Progress.Version, saved.QueueVersion, at.Add(time.Minute), at, ports.DocumentRetryReject, "provider_refused"); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("reject deferral accepted at expired lease %s: %v", at, err)
		}
	}

	mismatched := lease.Add(time.Second)
	store.mu.Lock()
	stored := store.commands[fixture.Tenant][saved.Intent.ID]
	stored.Progress.LeaseUntil = &mismatched
	store.commands[fixture.Tenant][saved.Intent.ID] = stored
	store.mu.Unlock()
	if _, err := store.DeferDocumentCommand(context.Background(), fixture.Tenant, saved.Intent.ID, claimed.Version, saved.Progress.Version, saved.QueueVersion, now.Add(2*time.Minute), now.Add(2*time.Second), ports.DocumentRetryUncertain, ""); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("uncertain deferral accepted mismatched progress lease: %v", err)
	}
}

func TestDocumentCommandStoreMemoryClaimHonorsConcurrentRetryDeferral(t *testing.T) {
	store, fixture := newDocumentStoreForTest(t)
	now := time.Date(2026, 10, 17, 16, 0, 0, 0, time.UTC)
	command := documentCommandForTest(fixture.Tenant, fixture.Engagement, fixture.Integration, "document-defer-claim", "defer-claim", now)
	command.Intent.SourceRef = "report-defer-claim"
	saved, _, err := store.CreateDocumentCommand(context.Background(), fixture.Tenant, command)
	if err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(time.Minute)
	deferred, err := store.DeferDocumentCommand(context.Background(), fixture.Tenant, saved.Intent.ID, saved.Intent.Version, saved.Progress.Version, saved.QueueVersion, deadline, now, ports.DocumentRetryKeep, "")
	if err != nil {
		t.Fatal(err)
	}
	lease := deadline.Add(time.Minute)
	if _, err := store.TransitionIntent(context.Background(), fixture.Tenant, saved.Intent.ID, saved.Intent.Version, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale claimant bypassed provider deferral: %v", err)
	}
	claimed, err := store.TransitionIntent(context.Background(), fixture.Tenant, saved.Intent.ID, saved.Intent.Version, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, deadline)
	if err != nil || claimed.State != writeintent.InFlight || !deferred.NextAttemptAt.Equal(deadline) {
		t.Fatalf("claim at retry due intent=%+v deferred=%+v err=%v", claimed, deferred, err)
	}
}
