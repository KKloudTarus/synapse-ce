package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	incidenttriage "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/incidenttriage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/incidentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

type producerFailAfterAppend struct{ next ports.NotificationOutbox }

func (o producerFailAfterAppend) Append(ctx context.Context, record notification.SourceRecord) error {
	if err := o.next.Append(ctx, record); err != nil {
		return err
	}
	return errors.New("injected source append failure")
}

type tamperedPostgresEvidenceStore struct{ *EvidenceStore }

func (s tamperedPostgresEvidenceStore) ListByEngagement(ctx context.Context, engagementID shared.ID) ([]evdom.Evidence, error) {
	items, err := s.EvidenceStore.ListByEngagement(ctx, engagementID)
	if len(items) > 0 {
		items[0].CreatedBy = "tampered-attribution"
	}
	return items, err
}

func TestIncidentUpdatedProducerPostgresTransactionSnapshotAndReplay(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("incident-notification-events")
	ctx := shared.WithTenant(context.Background(), tenant)
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	engagementID, incidentID := shared.ID("incident-notification-engagement"), shared.ID("incident-notification-case")
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Captured engagement')`, engagementID, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at) VALUES($1,'framework','activation','v1',true,$2)`, tenant, at.Add(-time.Second))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	repo := NewIncidentEventRepository(pool)
	incidents, err := incidentuc.NewService(repo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := incidents.Append(ctx, incidentID, 0, []incident.IncidentEvent{{IncidentID: incidentID, Kind: incident.EventCreated, At: at, Actor: "correlator", AssetID: "asset", EngagementID: engagementID, Severity: shared.SeverityHigh, Title: "Target https://alice:secret@example.test"}}); err != nil {
		t.Fatal(err)
	}
	triage, err := incidenttriage.NewService(incidents, NewAuditLog(pool), func() time.Time { return at.Add(time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	runner, outbox, facts := NewTenantTransactionRunner(pool), NewNotificationOutbox(pool), NewNotificationLifecycleFactsReader(pool)
	if err := triage.SetNotifications(runner, producerFailAfterAppend{next: outbox}, facts); err != nil {
		t.Fatal(err)
	}
	if _, err := triage.AssignOwner(ctx, "operator", incidentID, "owner"); err == nil {
		t.Fatal("want source failure")
	}
	stored, err := incidents.Get(ctx, incidentID)
	if err != nil || stored.Revision != 1 {
		t.Fatalf("source failure escaped incident transaction: %+v %v", stored, err)
	}
	if err := triage.SetNotifications(runner, outbox, facts); err != nil {
		t.Fatal(err)
	}
	if _, err := triage.AssignOwner(ctx, "operator", incidentID, "owner"); err != nil {
		t.Fatal(err)
	}
	var source notification.SourceRecord
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT source_kind,source_id,event_type,engagement_id,severity,schema_version,occurred_at,data,context,capture_version FROM notification_source_records WHERE tenant_id=$1 AND event_type=$2`, tenant, notification.EventIncidentUpdated).Scan(&source.SourceKind, &source.SourceID, &source.EventType, &source.EngagementID, &source.Severity, &source.SchemaVersion, &source.OccurredAt, &source.Data, &source.Context, &source.CaptureVersion)
	}); err != nil {
		t.Fatal(err)
	}
	if source.EventType != notification.EventIncidentUpdated || source.SourceID != incidentID.String()+":2" || source.CaptureVersion != 3 {
		t.Fatalf("incident source=%+v", source)
	}
	assertCapturedProducerSchema(t, tenant, source)
	var data map[string]any
	if err := json.Unmarshal(source.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data["update_kind"] != "owner" || data["incident_id"] != incidentID.String() || data["engagement_id"] != engagementID.String() {
		t.Fatalf("incident source data=%#v", data)
	}
	encoded, _ := json.Marshal(data)
	if strings.Contains(string(encoded), "secret") {
		t.Fatalf("incident source leaked credential: %s", encoded)
	}
	if sealed, err := notification.DecodeTemplateContext(source.Context); err != nil || sealed.Vars["incident_title"] == "" {
		t.Fatalf("incident immutable snapshot=%+v err=%v", sealed, err)
	}
}

func TestEvidenceChainBrokenProducerPostgresIndependentOfReportRollback(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("evidence-notification-events")
	ctx := shared.WithTenant(context.Background(), tenant)
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	engagementID := shared.ID("evidence-notification-engagement")
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Captured engagement')`, engagementID, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at) VALUES($1,'framework','activation','v1',true,$2)`, tenant, at.Add(-time.Second))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	store := tamperedPostgresEvidenceStore{EvidenceStore: NewEvidenceStore(pool)}
	svc, err := evidenceuc.NewService(store, blob.NewMemory(), NewAuditLog(pool), &notificationTestClock{at: at}, &notificationTestIDs{})
	if err != nil {
		t.Fatal(err)
	}
	runner, outbox := NewTenantTransactionRunner(pool), NewNotificationOutbox(pool)
	if err := svc.SetNotifications(runner, outbox, NewNotificationLifecycleFactsReader(pool)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SealOnce(ctx, engagementID, "detection", "first", []byte("body"), "agent"); err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("rollback report")
	err = runner.Run(ctx, tenant, func(reportCtx context.Context) error {
		if err := svc.VerifyChainError(reportCtx, engagementID); !errors.Is(err, evdom.ErrChainBroken) {
			t.Fatalf("VerifyChainError=%v", err)
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("outer report rollback=%v", err)
	}
	var source notification.SourceRecord
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT source_kind,source_id,event_type,engagement_id,severity,schema_version,occurred_at,data,context,capture_version FROM notification_source_records WHERE tenant_id=$1`, tenant).Scan(&source.SourceKind, &source.SourceID, &source.EventType, &source.EngagementID, &source.Severity, &source.SchemaVersion, &source.OccurredAt, &source.Data, &source.Context, &source.CaptureVersion)
	}); err != nil {
		t.Fatal(err)
	}
	if source.EventType != notification.EventEvidenceChainBroken || source.Severity != shared.SeverityCritical || source.CaptureVersion != 3 {
		t.Fatalf("evidence source=%+v", source)
	}
	assertCapturedProducerSchema(t, tenant, source)
	var data map[string]any
	if err := json.Unmarshal(source.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data["engagement_id"] != engagementID.String() || data["reason_code"] != "chain_invalid" {
		t.Fatalf("evidence source data=%#v", data)
	}
	if err := svc.VerifyChainError(ctx, engagementID); !errors.Is(err, evdom.ErrChainBroken) {
		t.Fatalf("replay VerifyChainError=%v", err)
	}
	var count int
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1`, tenant).Scan(&count)
	}); err != nil || count != 1 {
		t.Fatalf("chain alert replay count=%d err=%v", count, err)
	}
}

type unavailableEvidenceNotificationFacts struct{}

func (unavailableEvidenceNotificationFacts) SnapshotNotificationLifecycleFacts(context.Context, shared.ID, shared.ID, string) (ports.NotificationLifecycleFacts, error) {
	return ports.NotificationLifecycleFacts{}, shared.ErrNotFound
}

func TestEvidenceChainBrokenProducerPostgresNotificationFailurePreservesAudit(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("evidence-notification-fallback")
	ctx := shared.WithTenant(context.Background(), tenant)
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at) VALUES($1,'framework','activation','v1',true,$2)`, tenant, at.Add(-time.Second))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ids := &notificationTestIDs{}
	for _, failure := range []string{"facts", "outbox"} {
		t.Run(failure, func(t *testing.T) {
			engagementID := shared.ID("evidence-fallback-" + failure)
			if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Captured engagement')`, engagementID, tenant)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			store := tamperedPostgresEvidenceStore{EvidenceStore: NewEvidenceStore(pool)}
			clock := &notificationTestClock{at: at}
			svc, err := evidenceuc.NewService(store, blob.NewMemory(), NewAuditLog(pool), clock, ids)
			if err != nil {
				t.Fatal(err)
			}
			runner, outbox, facts := NewTenantTransactionRunner(pool), NewNotificationOutbox(pool), NewNotificationLifecycleFactsReader(pool)
			var failingOutbox ports.NotificationOutbox = outbox
			var failingFacts ports.NotificationLifecycleFactsReader = facts
			if failure == "facts" {
				failingFacts = unavailableEvidenceNotificationFacts{}
			} else {
				failingOutbox = producerFailAfterAppend{next: outbox}
			}
			if err := svc.SetNotifications(runner, failingOutbox, failingFacts); err != nil {
				t.Fatal(err)
			}
			if _, err := svc.SealOnce(ctx, engagementID, "detection", "first", []byte("body"), "agent"); err != nil {
				t.Fatal(err)
			}
			verifyAndRollback := func(observedAt time.Time) {
				t.Helper()
				clock.at = observedAt
				rollback := errors.New("rollback report")
				err := runner.Run(ctx, tenant, func(reportCtx context.Context) error {
					if err := svc.VerifyChainError(reportCtx, engagementID); !errors.Is(err, evdom.ErrChainBroken) {
						return err
					}
					return rollback
				})
				if !errors.Is(err, rollback) {
					t.Fatalf("outer report rollback=%v", err)
				}
			}
			assertCounts := func(wantSources int, wantAuditAt time.Time) {
				t.Helper()
				var audits, sources int
				var auditAt time.Time
				err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
					if err := tx.QueryRow(ctx, `SELECT count(*), min(created_at) FROM audit_log WHERE tenant_id=$1 AND action='evidence.tampered' AND target=$2`, tenant, engagementID).Scan(&audits, &auditAt); err != nil {
						return err
					}
					return tx.QueryRow(ctx, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND engagement_id=$2`, tenant, engagementID).Scan(&sources)
				})
				if err != nil || audits != 1 || sources != wantSources || !auditAt.Equal(wantAuditAt) {
					t.Fatalf("tamper audits=%d sources=%d audit_at=%s want=1,%d,%s err=%v", audits, sources, auditAt, wantSources, wantAuditAt, err)
				}
				if wantSources == 1 {
					report, verifyErr := NewAuditLog(pool).Verify(ctx)
					if verifyErr != nil || !report.Intact {
						t.Fatalf("first observation audit chain report=%+v err=%v", report, verifyErr)
					}
				}
			}
			firstObservation := at.Add(time.Second)
			verifyAndRollback(firstObservation)
			verifyAndRollback(firstObservation.Add(time.Second))
			assertCounts(0, firstObservation)
			if err := svc.SetNotifications(runner, outbox, facts); err != nil {
				t.Fatal(err)
			}
			verifyAndRollback(firstObservation.Add(2 * time.Second))
			assertCounts(1, firstObservation)
		})
	}
}

func assertCapturedProducerSchema(t *testing.T, tenant shared.ID, source notification.SourceRecord) {
	t.Helper()
	assertPublishedEventSchema(t, notification.Event{
		TenantID: tenant, ID: "captured-producer-schema",
		Type: source.EventType, SourceKind: source.SourceKind, SourceID: source.SourceID, EngagementID: source.EngagementID,
		Severity: source.Severity, SchemaVersion: source.SchemaVersion, OccurredAt: source.OccurredAt, Data: source.Data,
		SubjectKind: source.SubjectKind, SubjectID: source.SubjectID, Context: source.Context,
	})
}
