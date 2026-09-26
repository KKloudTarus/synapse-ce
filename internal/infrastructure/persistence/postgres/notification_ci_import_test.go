package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/codequality"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
	"github.com/jackc/pgx/v5"
)

type ciNotificationRules struct{}

func (ciNotificationRules) List(context.Context) ([]rule.Rule, error) {
	return nil, nil
}

func (ciNotificationRules) Get(context.Context, rule.Key) (rule.Rule, error) {
	return rule.Rule{}, shared.ErrNotFound
}

type ciNotificationAudit struct{}

func (ciNotificationAudit) Record(context.Context, ports.AuditEntry) error { return nil }

func ciNotificationResult() *scauc.ScanResult {
	return &scauc.ScanResult{
		Target: "/ci/project",
		SourceRef: "main",
		CodeQuality: &codequality.Report{
			Inventory: measure.Inventory{Files: []measure.FileInventory{
				{Path: "src/main.go", Language: "go", CodeLines: 12},
			}},
		},
	}
}

// TestNotificationCIImportCapture exercises the real import path with the
// PostgreSQL notification capture trigger, source projection and delivery store.
func TestNotificationCIImportCapture(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("notify-ci")
	ctx := shared.WithTenant(context.Background(), tenant)
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)

	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,'CI notifications'),('notify-other','Other')", tenant); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	channel := notification.Channel{
		TenantID: tenant, ID: "ci-channel", Name: "CI hook", Type: notification.ChannelWebhook,
		Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now,
	}
	if _, err := repo.CreateChannel(ctx, channel, "sealed"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateRule(ctx, notification.Rule{
		TenantID: tenant, ID: "ci-rule", Name: "CI completed", Enabled: true,
		EventType: notification.EventScanCompleted, ChannelIDs: []shared.ID{channel.ID},
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	source := NewNotificationSource(pool, repo, time.Minute, true)
	if _, err := source.Poll(ctx, now, 100); err != nil {
		t.Fatal(err)
	}

	engagements := memory.NewEngagementRepository()
	clock := &notificationTestClock{at: now.Add(time.Second)}
	ids := &notificationTestIDs{}
	svc := projectuc.NewService(memory.NewProjectRepository(), engagements, clock, ids, ciNotificationAudit{}, true)
	svc.SetAnalysisStore(memory.NewProjectAnalysisStore())
	svc.SetScanJobs(NewScanJobStore(pool))
	svc.SetRuleCatalog(ciNotificationRules{})
	p, err := svc.Create(ctx, projectuc.CreateInput{
		TenantID: tenant, CreatedBy: "ci-bot", Name: "CI project", Key: "ci-project",
		SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/ci/project"},
	})
	if err != nil {
		t.Fatal(err)
	}
	e, err := engagements.GetByProjectID(ctx, tenant, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'CI')", e.ID, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// A server scan and multiple CI imports must coexist in PostgreSQL.
	// The one-running-job index still rejects a second server scan.
	jobStore := NewScanJobStore(pool)
	running := func(id, kind string) ports.ScanJob {
		return ports.ScanJob{
			ID: id, EngagementID: e.ID.String(), Target: "/ci/project",
			Kind: kind, Status: ports.ScanRunning, Stage: "scanning",
			StartedAt: now, DebugEvents: []ports.ScanDebugEvent{},
		}
	}
	if err := jobStore.CreateRunning(ctx, running("ci-active-server", "git")); err != nil {
		t.Fatalf("start server scan: %v", err)
	}
	for _, id := range []string{"ci-parallel-1", "ci-parallel-2"} {
		if err := jobStore.CreateRunning(ctx, running(id, "ci-import")); err != nil {
			t.Fatalf("CI import %s blocked by a running scan: %v", id, err)
		}
	}
	if err := jobStore.CreateRunning(ctx, running("ci-second-server", "git")); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("a second server scan must conflict: %v", err)
	}

	rejected := ciNotificationResult()
	rejected.CodeQuality.Inventory.Files = append(rejected.CodeQuality.Inventory.Files,
		measure.FileInventory{Path: "src/main.go", Language: "go", CodeLines: 1})
	if _, err := svc.ImportAnalysis(ctx, tenant, "ci-project", projectuc.ImportAnalysisInput{
		Actor: "ci-bot", Result: rejected,
	}); err == nil || !strings.Contains(err.Error(), "duplicate canonical file path") {
		t.Fatalf("expected rejected import, got %v", err)
	}
	if _, err := source.Poll(ctx, now.Add(2*time.Second), 100); err != nil {
		t.Fatal(err)
	}
	page, err := repo.ListDeliveries(ctx, ports.NotificationDeliveryFilter{TenantID: tenant})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("rejected import deliveries = %d, err = %v; want zero", len(page.Items), err)
	}
	var captured int
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND source_kind='scan_job'", tenant).Scan(&captured)
	}); err != nil || captured != 0 {
		t.Fatalf("rejected import captured sources = %d, err = %v; want zero", captured, err)
	}

	accepted, err := svc.ImportAnalysis(ctx, tenant, "ci-project", projectuc.ImportAnalysisInput{
		Actor: "ci-bot", Result: ciNotificationResult(),
	})
	if err != nil {
		t.Fatalf("accepted import: %v", err)
	}
	for _, at := range []time.Time{now.Add(3 * time.Second), now.Add(4 * time.Second)} {
		if _, err := source.Poll(ctx, at, 100); err != nil {
			t.Fatal(err)
		}
	}
	page, err = repo.ListDeliveries(ctx, ports.NotificationDeliveryFilter{TenantID: tenant})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("accepted import deliveries = %d, err = %v; want one", len(page.Items), err)
	}
	work, err := repo.LoadWork(ctx, tenant, page.Items[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if work.Event.Type != notification.EventScanCompleted || work.Event.SourceID != accepted.ID {
		t.Fatalf("unexpected accepted event: %+v", work.Event)
	}
	if relevant, err := repo.DeliveryStillRelevant(ctx, work); err != nil || !relevant {
		t.Fatalf("accepted import relevant = %v, err = %v; want true", relevant, err)
	}

	// The relevance query cannot be tricked into reading another tenant's job.
	other := work
	other.Event.TenantID = "notify-other"
	if relevant, err := repo.DeliveryStillRelevant(shared.WithTenant(context.Background(), "notify-other"), other); err != nil || relevant {
		t.Fatalf("cross-tenant scan relevant = %v, err = %v; want false", relevant, err)
	}

	// Simulate a correction before a pending delivery is sent. The queued
	// event is immutable, but a failed job is no longer a success notification.
	finished := clock.at
	if err := NewScanJobStore(pool).Save(ctx, ports.ScanJob{
		ID: accepted.ID, EngagementID: e.ID.String(), Kind: "ci-import",
		Status: ports.ScanFailed, Stage: "import-rejected", StartedAt: clock.at,
		FinishedAt: &finished,
	}); err != nil {
		t.Fatal(err)
	}
	if relevant, err := repo.DeliveryStillRelevant(ctx, work); err != nil || relevant {
		t.Fatalf("rejected queued delivery relevant = %v, err = %v; want false", relevant, err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND source_kind='scan_job'", tenant).Scan(&captured)
	}); err != nil || captured != 1 {
		t.Fatalf("accepted import captured sources = %d, err = %v; want one", captured, err)
	}
}
