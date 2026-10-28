package docpublish

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	document "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type reportNotificationRunner struct {
	next   ports.TenantTransactionRunner
	active bool
}

func (r *reportNotificationRunner) Run(ctx context.Context, tenant shared.ID, fn func(context.Context) error) error {
	return r.next.Run(ctx, tenant, func(txCtx context.Context) error {
		r.active = true
		defer func() { r.active = false }()
		return fn(txCtx)
	})
}

type transactionAwareProviderRegistry struct {
	next                ProviderRegistry
	active              *bool
	calledInTransaction bool
}

func (r *transactionAwareProviderRegistry) DocumentProvider(ctx context.Context, in integration.Integration) (ports.DocumentProvider, error) {
	if *r.active {
		r.calledInTransaction = true
	}
	return r.next.DocumentProvider(ctx, in)
}

func (r *transactionAwareProviderRegistry) DocumentReleasePreflighter(ctx context.Context, in integration.Integration) (ports.DocumentReleasePreflighter, error) {
	if *r.active {
		r.calledInTransaction = true
	}
	preflighter, ok := r.next.(DocumentReleasePreflightRegistry)
	if !ok {
		return nil, nil
	}
	return preflighter.DocumentReleasePreflighter(ctx, in)
}

type failingReportNotificationOutbox struct{ err error }

func (o failingReportNotificationOutbox) Append(context.Context, notification.SourceRecord) error {
	return o.err
}

var _ ports.NotificationOutbox = failingReportNotificationOutbox{}

func TestDocumentReleaseCapturesStoredArtifactAfterCommandCommitBoundary(t *testing.T) {
	f := newReleaseFixture(t)
	runner := &reportNotificationRunner{next: memory.NewTenantTransactionRunner()}
	registry := &transactionAwareProviderRegistry{next: f.service.providers, active: &runner.active}
	f.service.providers = registry
	outbox := memory.NewNotificationOutbox()
	outbox.Activate("tenant", f.clock.at.Add(-time.Second))
	if err := f.service.SetNotifications(runner, outbox); err != nil {
		t.Fatalf("enable notifications: %v", err)
	}

	first := f.publish(t)
	if _, err := f.service.Publish(t.Context(), "tenant", f.actor, f.input); err != nil {
		t.Fatalf("replay: %v", err)
	}
	records := outbox.Records("tenant")
	if len(records) != 1 {
		t.Fatalf("records=%d, want one durable source", len(records))
	}
	stored, err := f.store.GetDocumentCommand(t.Context(), "tenant", first.ID)
	if err != nil {
		t.Fatalf("read stored command: %v", err)
	}
	wantHash := artifactBytesDigest(stored.Artifact.PDF)
	if records[0].SourceID != "engagement_report:"+wantHash || records[0].SubjectID != wantHash {
		t.Fatalf("record does not use the persisted PDF: %+v", records[0])
	}
	if registry.calledInTransaction {
		t.Fatal("document provider ran inside the persistence transaction")
	}
	if len(f.audit.entries) != 1 {
		t.Fatalf("release audit entries=%d, want one created command", len(f.audit.entries))
	}
}

func TestDocumentReleaseUsesValidatedArtifactCycleForClosureReportNavigation(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2026, 10, 17, 1, 0, 0, 0, time.UTC)
	projects := memory.NewProjectRepository()
	projectRecord, err := project.New("project-a", "tenant", "Project A", "project-a", project.SourceBinding{Kind: project.SourceLocal, Value: "/tmp/project-a"}, nil, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err = projects.Create(shared.WithTenant(ctx, "tenant"), projectRecord); err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewDocumentStore(memory.NewEngagementRepository(), projects)
	if err != nil {
		t.Fatal(err)
	}
	clock := &releaseClock{at: now}
	source := &releaseSource{artifact: ports.DocumentArtifact{Title: "Closure report", Paragraphs: []string{"fact"}, PDF: []byte("%PDF-1.7\nsealed"), SourceRevision: "closure:sealed", GeneratedAt: now, CycleID: "cycle-a"}}
	service, err := NewService(store, &releaseIntegration{item: integration.Integration{ID: "connection", TenantID: "tenant", Provider: "confluence-cloud", Endpoint: "https://lab.atlassian.net", Config: []byte(`{"space":"LAB","read_group":"restricted-group","data_class":"detail"}`), Enabled: true, ConnectionRevision: 1, CredentialRevision: 1}}, releaseProviders{&releaseProvider{sharing: true}}, source, &releaseAuthority{allowed: true}, &releasePolicy{}, &releaseAudit{}, &releaseIDs{}, clock)
	if err != nil {
		t.Fatal(err)
	}
	outbox := memory.NewNotificationOutbox()
	outbox.Activate("tenant", now.Add(-time.Second))
	if err := service.SetNotifications(memory.NewTenantTransactionRunner(), outbox); err != nil {
		t.Fatalf("enable notifications: %v", err)
	}
	_, err = service.Publish(ctx, "tenant", ports.DocumentActor{UserID: "reviewer"}, PublishInput{IntegrationID: "connection", SourceKind: document.AssessmentClosureReport, ScopeID: "project-a", SourceRef: AssessmentClosureSourceRef("cycle-a"), RequestKey: "closure-report"})
	if err != nil {
		t.Fatalf("publish closure report: %v", err)
	}
	records := outbox.Records("tenant")
	if len(records) != 1 {
		t.Fatalf("records=%+v", records)
	}
	var data map[string]any
	if err := json.Unmarshal(records[0].Data, &data); err != nil {
		t.Fatalf("decode record data: %v", err)
	}
	if data["cycle_id"] != "cycle-a" {
		t.Fatalf("closure navigation used project scope instead of stored cycle: %v", data)
	}
}

func TestDocumentReleaseFailsWhenNotificationCaptureCannotCommit(t *testing.T) {
	f := newReleaseFixture(t)
	if err := f.service.SetNotifications(memory.NewTenantTransactionRunner(), failingReportNotificationOutbox{err: shared.ErrConflict}); err != nil {
		t.Fatalf("enable notifications: %v", err)
	}
	if _, err := f.service.Publish(t.Context(), "tenant", f.actor, f.input); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("publish error=%v, want outbox failure", err)
	}
	if len(f.audit.entries) != 0 {
		t.Fatalf("release audit entries=%+v, want none after outbox failure", f.audit.entries)
	}
}

func TestDocumentReleaseNotificationConfigurationRejectsPartialDependencies(t *testing.T) {
	f := newReleaseFixture(t)
	if err := f.service.SetNotifications(nil, memory.NewNotificationOutbox()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil transaction error=%v", err)
	}
	if err := f.service.SetNotifications(memory.NewTenantTransactionRunner(), nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil outbox error=%v", err)
	}
}
