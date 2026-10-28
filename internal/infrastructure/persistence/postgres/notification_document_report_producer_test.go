package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	documentdomain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	documentuc "github.com/KKloudTarus/synapse-ce/internal/usecase/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

type documentReportIntegrationStore struct {
	ports.IntegrationStore
	item integration.Integration
}

func (s documentReportIntegrationStore) GetIntegration(context.Context, shared.ID) (integration.Integration, error) {
	return s.item, nil
}

type documentReportAuthority struct{}

func (documentReportAuthority) CanReleaseDocument(context.Context, shared.ID, ports.DocumentActor) (bool, error) {
	return true, nil
}

type documentReportPolicy struct{}

func (documentReportPolicy) CheckDocumentSource(context.Context, shared.ID, documentdomain.Target) error {
	return nil
}

type documentReportSource struct{}

func (documentReportSource) BuildDocumentArtifact(context.Context, shared.ID, documentdomain.Target) (ports.DocumentArtifact, error) {
	return ports.DocumentArtifact{}, errors.New("unexpected live artifact build")
}

type documentReportProviderRegistry struct{ provider ports.DocumentProvider }

func (r documentReportProviderRegistry) DocumentProvider(context.Context, integration.Integration) (ports.DocumentProvider, error) {
	return r.provider, nil
}

type documentReportProvider struct{}

func (documentReportProvider) CreateDocumentShell(context.Context, string, string) (documentdomain.RemotePage, error) {
	return documentdomain.RemotePage{}, errors.New("unexpected remote write")
}
func (documentReportProvider) RestrictDocument(context.Context, string, string) error {
	return errors.New("unexpected remote write")
}
func (documentReportProvider) VerifyDocumentRestriction(context.Context, string, string, string) error {
	return errors.New("unexpected remote read")
}
func (documentReportProvider) GetDocument(context.Context, string) (ports.DocumentRemoteState, error) {
	return ports.DocumentRemoteState{}, errors.New("unexpected remote read")
}
func (documentReportProvider) FindDocumentMarker(context.Context, string, string) ([]ports.DocumentRemoteState, error) {
	return nil, errors.New("unexpected remote read")
}
func (documentReportProvider) UploadDocumentAttachment(context.Context, string, ports.DocumentImage) error {
	return errors.New("unexpected remote write")
}
func (documentReportProvider) WriteDocument(context.Context, string, int, string, string, string) (documentdomain.RemotePage, error) {
	return documentdomain.RemotePage{}, errors.New("unexpected remote write")
}
func (documentReportProvider) PurgeDocument(context.Context, string, func(context.Context) error) error {
	return errors.New("unexpected remote write")
}
func (documentReportProvider) ValidateDocumentText(string) error { return nil }

type failingDocumentReportOutbox struct {
	next ports.NotificationOutbox
	err  error
}

func (o failingDocumentReportOutbox) Append(ctx context.Context, record notification.SourceRecord) error {
	if err := o.next.Append(ctx, record); err != nil {
		return err
	}
	return o.err
}

func TestDocumentReportProducerPostgresRollsBackCommandWhenOutboxCaptureFails(t *testing.T) {
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

	tenant := shared.ID("doc-a")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at)
			VALUES($1,'framework','activation','v1',true,$2)
			ON CONFLICT(tenant_id,source_kind,source_id) DO UPDATE SET active=TRUE,observed_at=excluded.observed_at`, tenant, now.Add(-time.Second))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	store, err := NewDocumentStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	integrationItem := integration.Integration{ID: "doc-integration-a", TenantID: tenant, Provider: integration.Provider("confluence-cloud"), Endpoint: "https://docs.example.test", Config: []byte(`{"space":"SEC","read_group":"restricted","data_class":"detail"}`), Enabled: true, ConnectionRevision: 1, CredentialRevision: 0}
	service, err := documentuc.NewService(
		store,
		documentReportIntegrationStore{item: integrationItem},
		documentReportProviderRegistry{provider: documentReportProvider{}},
		documentReportSource{},
		documentReportAuthority{},
		documentReportPolicy{},
		NewAuditLog(pool),
		&notificationTestIDs{},
		&notificationTestClock{at: now},
	)
	if err != nil {
		t.Fatal(err)
	}
	runner, outbox := NewTenantTransactionRunner(pool), NewNotificationOutbox(pool)
	injected := errors.New("capture unavailable")
	if err = service.SetNotifications(runner, failingDocumentReportOutbox{next: outbox, err: injected}); err != nil {
		t.Fatal(err)
	}
	input := documentuc.PublishInput{IntegrationID: integrationItem.ID, SourceKind: documentdomain.EngagementReport, ScopeID: "doc-engagement-a", SourceRef: "engagement:doc-engagement-a", RequestKey: "report-capture-rollback"}
	artifact := ports.DocumentArtifact{Title: "Stored report", Paragraphs: []string{"verified fact"}, PDF: []byte("%PDF-1.7\\nreport"), SourceRevision: "sealed-v1", GeneratedAt: now}
	if _, err = service.PublishArtifact(ctx, tenant, ports.DocumentActor{UserID: "reviewer"}, input, artifact); !errors.Is(err, injected) {
		t.Fatalf("publish error=%v, want capture failure", err)
	}
	if _, err = store.FindDocumentCommand(ctx, tenant, integrationItem.ID, input.RequestKey); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("command escaped rollback: %v", err)
	}
	var sources int
	if err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND event_type=$2`, tenant, notification.EventReportGenerated).Scan(&sources)
	}); err != nil {
		t.Fatal(err)
	}
	if sources != 0 {
		t.Fatalf("source record escaped rollback: %d", sources)
	}

	if err = service.SetNotifications(runner, outbox); err != nil {
		t.Fatal(err)
	}
	result, err := service.PublishArtifact(ctx, tenant, ports.DocumentActor{UserID: "reviewer"}, input, artifact)
	if err != nil || result.Intent == nil {
		t.Fatalf("recovery result=%+v err=%v", result, err)
	}
	if _, err = store.FindDocumentCommand(ctx, tenant, integrationItem.ID, input.RequestKey); err != nil {
		t.Fatalf("command missing after recovery: %v", err)
	}
	if err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND event_type=$2`, tenant, notification.EventReportGenerated).Scan(&sources)
	}); err != nil {
		t.Fatal(err)
	}
	if sources != 1 {
		t.Fatalf("sources=%d, want one recovered durable source", sources)
	}
}

type documentReportSchedulePolicy struct{}

func (documentReportSchedulePolicy) CheckReportSource(context.Context, shared.ID, documentdomain.Source) error {
	return nil
}

type documentReportScheduleArtifacts struct{ artifact ports.DocumentArtifact }

func (a documentReportScheduleArtifacts) BuildSourceArtifact(context.Context, shared.ID, documentdomain.Source) (ports.DocumentArtifact, error) {
	return a.artifact, nil
}

type documentReportScheduleChannels struct{ channel notification.Channel }

func (s documentReportScheduleChannels) GetChannel(context.Context, shared.ID, shared.ID) (notification.Channel, error) {
	return s.channel, nil
}
func (s documentReportScheduleChannels) ListChannels(context.Context, shared.ID) ([]notification.Channel, error) {
	return []notification.Channel{s.channel}, nil
}

type documentReportScheduleEmailConfig struct{}

func (documentReportScheduleEmailConfig) EmailChannelConfig(context.Context, ports.NotificationWork, ports.NotificationChannelConfig) (ports.NotificationChannelConfig, string) {
	return ports.EmailChannelConfig{Recipients: []string{"reviewer@example.test"}, Relay: &ports.SMTPRelayConfig{CacheKey: "test-relay"}}, ""
}

type documentReportScheduleSender struct{}

func (documentReportScheduleSender) SendDocumentPDF(context.Context, ports.DocumentPDFMail) ports.DocumentEmailResult {
	return ports.DocumentEmailResult{Accepted: true}
}

type documentReportSchedulePublisher struct{}

func (documentReportSchedulePublisher) ValidateDocumentDestination(context.Context, shared.ID, shared.ID) error {
	return nil
}
func (documentReportSchedulePublisher) PublishArtifact(context.Context, shared.ID, ports.DocumentActor, documentuc.PublishInput, ports.DocumentArtifact) (documentuc.ReleaseResult, error) {
	return documentuc.ReleaseResult{}, errors.New("unexpected document schedule publication")
}

type documentReportScheduleExecutor struct{}

func (documentReportScheduleExecutor) Execute(context.Context, shared.ID, shared.ID) (documentdomain.Intent, error) {
	return documentdomain.Intent{}, errors.New("unexpected document schedule execution")
}

type documentReportScheduleAudit struct{}

func (documentReportScheduleAudit) Record(context.Context, ports.AuditEntry) error { return nil }

func TestDocumentReportProducerPostgresRollsBackScheduleFreezeWhenOutboxCaptureFails(t *testing.T) {
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

	tenant := shared.ID("doc-a")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at)
			VALUES($1,'framework','activation','v1',true,$2)
			ON CONFLICT(tenant_id,source_kind,source_id) DO UPDATE SET active=TRUE,observed_at=excluded.observed_at`, tenant, now.Add(-time.Second))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	store, err := NewDocumentStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	artifact := ports.DocumentArtifact{Title: "Stored report", Paragraphs: []string{"verified fact"}, PDF: []byte("%PDF-1.7\nscheduled-" + now.Format(time.RFC3339Nano)), SourceRevision: "sealed-v1", GeneratedAt: now}
	digest := sha256.Sum256(artifact.PDF)
	contentHash := hex.EncodeToString(digest[:])
	channelID := shared.ID("doc-report-mail-" + now.Format("150405.000000"))
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_channels(tenant_id,id,name,channel_type,created_at,updated_at) VALUES($1,$2,'Document report mail','email',$3,$3)`, tenant, channelID, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	channel := notification.Channel{TenantID: tenant, ID: channelID, Name: "mail", Type: notification.ChannelEmail, Enabled: true, Recipients: []string{"reviewer@example.test"}, Revision: 1, SecretVersion: 1, DataClass: notification.DataClassDetail, CreatedAt: now, UpdatedAt: now}
	clock := &notificationTestClock{at: now}
	service, err := documentuc.NewScheduleService(documentuc.ScheduleDependencies{
		Store: store, Authority: documentReportAuthority{}, ReportPolicy: documentReportSchedulePolicy{},
		Artifacts: documentReportScheduleArtifacts{artifact: artifact},
		Channels:  documentReportScheduleChannels{channel: channel}, Integrations: documentReportIntegrationStore{item: integration.Integration{ID: "doc-integration-a", TenantID: tenant}},
		EmailConfig: documentReportScheduleEmailConfig{}, EmailSender: documentReportScheduleSender{}, Publisher: documentReportSchedulePublisher{}, Executor: documentReportScheduleExecutor{},
		Audit: documentReportScheduleAudit{}, IDs: &notificationTestIDs{}, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	runner, outbox := NewTenantTransactionRunner(pool), NewNotificationOutbox(pool)
	injected := errors.New("capture unavailable")
	if err := service.SetNotifications(runner, failingDocumentReportOutbox{next: outbox, err: injected}); err != nil {
		t.Fatal(err)
	}
	schedule, err := service.SaveSchedule(ctx, tenant, ports.DocumentActor{UserID: "admin"}, documentuc.ScheduleInput{
		ID: "schedule-report-capture", Source: documentdomain.Source{SourceKind: documentdomain.EngagementReport, SourceRef: "engagement:doc-engagement-a", Scope: documentdomain.Engagement, ScopeID: "doc-engagement-a"},
		Destination: documentdomain.ScheduleEmail, EmailChannelID: channel.ID, Timezone: "UTC", Frequency: documentdomain.ScheduleWeekly, Weekday: int(now.Weekday()), Hour: now.Hour(), Minute: now.Minute(), Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	schedule.NextDueAt = now.Add(-time.Minute)
	if schedule, err = store.SaveDocumentSchedule(ctx, tenant, schedule, schedule.Version); err != nil {
		t.Fatal(err)
	}
	if err := service.Tick(ctx, tenant, 1); !errors.Is(err, injected) {
		t.Fatalf("first tick error=%v, want capture failure", err)
	}
	var artifactStored bool
	var sources int
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT artifact <> 'null'::jsonb FROM document_schedule_occurrences WHERE tenant_id=$1 AND schedule_id=$2`, tenant, schedule.ID).Scan(&artifactStored); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND event_type=$2 AND data->>'content_hash'=$3`, tenant, notification.EventReportGenerated, contentHash).Scan(&sources)
	}); err != nil {
		t.Fatal(err)
	}
	if artifactStored || sources != 0 {
		t.Fatalf("freeze or source escaped rollback: artifact_stored=%t sources=%d", artifactStored, sources)
	}

	clock.at = now.Add(6 * time.Minute)
	if err := service.SetNotifications(runner, outbox); err != nil {
		t.Fatal(err)
	}
	if err := service.Tick(ctx, tenant, 1); err != nil {
		t.Fatalf("retry tick: %v", err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT artifact <> 'null'::jsonb FROM document_schedule_occurrences WHERE tenant_id=$1 AND schedule_id=$2`, tenant, schedule.ID).Scan(&artifactStored); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND event_type=$2 AND data->>'content_hash'=$3`, tenant, notification.EventReportGenerated, contentHash).Scan(&sources)
	}); err != nil {
		t.Fatal(err)
	}
	if !artifactStored || sources != 1 {
		t.Fatalf("retry did not freeze and capture exactly once: artifact_stored=%t sources=%d", artifactStored, sources)
	}
}
