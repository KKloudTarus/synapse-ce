package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestDocumentScheduleStorePostgresConcurrentAdmissionAndRLS(t *testing.T) {
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
	if err := WithTenant(ctx, pool, "doc-a", func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `DELETE FROM document_schedule_deliveries WHERE tenant_id=$1`, "doc-a"); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `DELETE FROM document_schedule_occurrences WHERE tenant_id=$1`, "doc-a"); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `DELETE FROM document_schedules WHERE tenant_id=$1`, "doc-a")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	store, err := NewDocumentStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	schedule := docpublish.Schedule{ID: shared.ID(fmt.Sprintf("schedule-pg-%d", time.Now().UnixNano())), TenantID: "doc-a", Source: docpublish.Source{SourceKind: docpublish.EngagementReport, SourceRef: "engagement:doc-engagement-a", Scope: docpublish.Engagement, ScopeID: "doc-engagement-a"}, Destination: docpublish.ScheduleConfluence, IntegrationID: "doc-integration-a", OwnerUserID: "admin", Timezone: "UTC", Frequency: docpublish.ScheduleWeekly, Weekday: int(now.Weekday()), Hour: 11, Enabled: true, Version: 1, NextDueAt: now.Add(-time.Minute), CreatedAt: now, UpdatedAt: now}
	if _, err := store.SaveDocumentSchedule(ctx, "doc-a", schedule, 0); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan []ports.DocumentScheduleWork, 2)
	failures := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			work, e := store.ClaimDueDocumentScheduleOccurrences(context.Background(), "doc-a", 20, now)
			if e != nil {
				failures <- e
				return
			}
			results <- work
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(failures)
	for e := range failures {
		t.Fatal(e)
	}
	claimed := 0
	for work := range results {
		claimed += len(work)
	}
	if claimed != 1 {
		t.Fatalf("concurrent claims=%d", claimed)
	}
	oid := pgScheduleOccurrenceID(schedule.ID, schedule.NextDueAt)
	occurrence, err := store.GetDocumentScheduleOccurrence(ctx, "doc-a", oid)
	if err != nil {
		t.Fatal(err)
	}
	if occurrence.ArtifactStored {
		t.Fatal("new occurrence falsely claims a stored artifact")
	}
	occurrence, err = store.SaveDocumentScheduleOccurrence(ctx, "doc-a", occurrence, occurrence.Occurrence.Version, now)
	if err != nil || occurrence.ArtifactStored {
		t.Fatalf("lease-only checkpoint invented artifact: stored=%v err=%v", occurrence.ArtifactStored, err)
	}
	occurrence.ArtifactStored = true
	occurrence.Artifact = ports.DocumentArtifact{Title: "Stored report", PDF: []byte("%PDF-1.7\nfrozen"), GeneratedAt: now}
	occurrence.Occurrence.ArtifactDigest = strings.Repeat("a", 64)
	occurrence, err = store.SaveDocumentScheduleOccurrence(ctx, "doc-a", occurrence, occurrence.Occurrence.Version, now)
	if err != nil || !occurrence.ArtifactStored || string(occurrence.Artifact.PDF) != "%PDF-1.7\nfrozen" {
		t.Fatalf("freeze=%+v err=%v", occurrence, err)
	}
	changed := occurrence
	changed.Artifact.Title = "Changed stored artifact"
	if _, err = store.SaveDocumentScheduleOccurrence(ctx, "doc-a", changed, changed.Occurrence.Version, now); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("changed frozen artifact accepted: %v", err)
	}
	leaseOnly := occurrence
	leaseOnly.ArtifactStored = false
	leaseOnly.Artifact = ports.DocumentArtifact{}
	leaseOnly.Occurrence.ArtifactDigest = ""
	occurrence, err = store.SaveDocumentScheduleOccurrence(ctx, "doc-a", leaseOnly, leaseOnly.Occurrence.Version, now)
	if err != nil || !occurrence.ArtifactStored || occurrence.Artifact.Title != "Stored report" {
		t.Fatalf("lease erased frozen artifact: %+v %v", occurrence, err)
	}
	delivery := ports.DocumentScheduleDelivery{ID: "rls-mail-" + schedule.ID, TenantID: "doc-a", OccurrenceID: oid, Recipient: "reviewer@example.test", RecipientHash: strings.Repeat("b", 64), MessageID: "rls-message-" + schedule.ID, State: ports.DocumentScheduleDeliveryPending, Version: 1, CreatedAt: now, UpdatedAt: now}
	if _, err = store.SaveDocumentScheduleDelivery(ctx, "doc-a", delivery, 0, now); err != nil {
		t.Fatal(err)
	}
	assertScheduleRuntimeRLS(t, ctx, pool)
	occurrence.Occurrence.State = docpublish.OccurrenceFailed
	occurrence.Occurrence.LeaseUntil = nil
	occurrence, err = store.SaveDocumentScheduleOccurrence(ctx, "doc-a", occurrence, occurrence.Occurrence.Version, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if retry, err := store.ClaimDueDocumentScheduleOccurrences(ctx, "doc-a", 20, now.Add(2*time.Second)); err != nil || len(retry) != 1 {
		t.Fatalf("failed retry=%d err=%v", len(retry), err)
	}
	occurrence, err = store.GetDocumentScheduleOccurrence(ctx, "doc-a", oid)
	if err != nil {
		t.Fatal(err)
	}
	past := now.Add(-time.Second)
	occurrence.Occurrence.State = docpublish.OccurrenceInFlight
	occurrence.Occurrence.LeaseUntil = &past
	occurrence, err = store.SaveDocumentScheduleOccurrence(ctx, "doc-a", occurrence, occurrence.Occurrence.Version, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if retry, err := store.ClaimDueDocumentScheduleOccurrences(ctx, "doc-a", 20, now.Add(4*time.Second)); err != nil || len(retry) != 1 {
		t.Fatalf("expired retry=%d err=%v", len(retry), err)
	}
	occurrence, err = store.GetDocumentScheduleOccurrence(ctx, "doc-a", oid)
	if err != nil {
		t.Fatal(err)
	}
	occurrence.Occurrence.State = docpublish.OccurrenceUncertain
	occurrence.Occurrence.LeaseUntil = nil
	if _, err = store.SaveDocumentScheduleOccurrence(ctx, "doc-a", occurrence, occurrence.Occurrence.Version, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if retry, err := store.ClaimDueDocumentScheduleOccurrences(ctx, "doc-a", 20, now.Add(6*time.Second)); err != nil || len(retry) != 0 {
		t.Fatalf("uncertain retry=%d err=%v", len(retry), err)
	}
	if repeat, err := store.ClaimDueDocumentScheduleOccurrences(ctx, "doc-a", 20, now); err != nil || len(repeat) != 0 {
		t.Fatalf("repeat=%d err=%v", len(repeat), err)
	}
	if _, err := store.GetDocumentSchedule(ctx, "doc-b", schedule.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross tenant=%v", err)
	}
	if err := store.DeleteDocumentSchedule(ctx, "doc-a", schedule.ID, 99, now); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale delete=%v", err)
	}
}

func TestDocumentScheduleStorePostgresClaimsFreshWorkAfterFailedRecoveryBacklog(t *testing.T) {
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
	if err := WithTenant(ctx, pool, "doc-a", func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `DELETE FROM document_schedule_deliveries WHERE tenant_id=$1`, "doc-a"); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `DELETE FROM document_schedule_occurrences WHERE tenant_id=$1`, "doc-a"); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `DELETE FROM document_schedules WHERE tenant_id=$1`, "doc-a")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	store, err := NewDocumentStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	newSchedule := func(id shared.ID) docpublish.Schedule {
		return docpublish.Schedule{ID: id, TenantID: "doc-a", Source: docpublish.Source{SourceKind: docpublish.EngagementReport, SourceRef: "engagement:doc-engagement-a", Scope: docpublish.Engagement, ScopeID: "doc-engagement-a"}, Destination: docpublish.ScheduleConfluence, IntegrationID: "doc-integration-a", OwnerUserID: "admin", Timezone: "UTC", Frequency: docpublish.ScheduleWeekly, Weekday: int(now.Weekday()), Hour: 11, Enabled: true, Version: 1, NextDueAt: now.Add(-time.Minute), CreatedAt: now, UpdatedAt: now}
	}
	for i := range 20 {
		if _, err := store.SaveDocumentSchedule(ctx, "doc-a", newSchedule(shared.ID(fmt.Sprintf("fair-failed-%02d", i))), 0); err != nil {
			t.Fatal(err)
		}
	}
	healthy := newSchedule("fair-healthy")
	if _, err := store.SaveDocumentSchedule(ctx, "doc-a", healthy, 0); err != nil {
		t.Fatal(err)
	}
	first, err := store.ClaimDueDocumentScheduleOccurrences(ctx, "doc-a", 20, now)
	if err != nil || len(first) != 20 {
		t.Fatalf("initial claim=%d err=%v", len(first), err)
	}
	for _, work := range first {
		work.Occurrence.Occurrence.State = docpublish.OccurrenceFailed
		work.Occurrence.Occurrence.LeaseUntil = nil
		if _, err := store.SaveDocumentScheduleOccurrence(ctx, "doc-a", work.Occurrence, work.Occurrence.Occurrence.Version, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	second, err := store.ClaimDueDocumentScheduleOccurrences(ctx, "doc-a", 1, now.Add(2*time.Second))
	if err != nil || len(second) != 1 || second[0].Schedule.ID != healthy.ID {
		t.Fatalf("fresh work starved by failed backlog: work=%+v err=%v", second, err)
	}
	third, err := store.ClaimDueDocumentScheduleOccurrences(ctx, "doc-a", 1, now.Add(3*time.Second))
	if err != nil || len(third) != 1 || third[0].Schedule.ID == healthy.ID {
		t.Fatalf("recovery did not resume after fresh work: work=%+v err=%v", third, err)
	}
}

func assertScheduleRuntimeRLS(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	role := "schedule_rls_" + randHex(t)
	quoted := pgx.Identifier{role}.Sanitize()
	for _, sql := range []string{"CREATE ROLE " + quoted + " NOSUPERUSER NOBYPASSRLS", "GRANT USAGE ON SCHEMA public TO " + quoted, "GRANT SELECT,INSERT,UPDATE,DELETE ON document_schedules,document_schedule_occurrences,document_schedule_deliveries TO " + quoted} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP OWNED BY "+quoted)
		_, _ = pool.Exec(context.Background(), "DROP ROLE "+quoted)
	})
	asRole := func(tenant string, fn func(pgx.Tx) error) error {
		return WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+quoted); err != nil {
				return err
			}
			return fn(tx)
		})
	}
	for _, table := range []string{"document_schedules", "document_schedule_occurrences", "document_schedule_deliveries"} {
		var count int
		var enabled, forced bool
		if err := pool.QueryRow(ctx, `SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&enabled, &forced); err != nil || !enabled || !forced {
			t.Fatalf("RLS %s %v %v %v", table, enabled, forced, err)
		}
		if err := asRole("doc-a", func(tx pgx.Tx) error { return tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&count) }); err != nil || count < 1 {
			t.Fatalf("owned %s count=%d err=%v", table, count, err)
		}
		for _, tenant := range []string{"doc-b", ""} {
			if err := asRole(tenant, func(tx pgx.Tx) error {
				if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil {
					return err
				}
				if count != 0 {
					return fmt.Errorf("foreign rows %d", count)
				}
				for _, sql := range []string{"UPDATE " + table + " SET tenant_id=tenant_id", "DELETE FROM " + table} {
					tag, err := tx.Exec(ctx, sql)
					if err != nil {
						return err
					}
					if tag.RowsAffected() != 0 {
						return fmt.Errorf("foreign mutation %d", tag.RowsAffected())
					}
				}
				return nil
			}); err != nil {
				t.Fatalf("%s tenant=%q %v", table, tenant, err)
			}
		}
		err := asRole("doc-a", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "INSERT INTO "+table+" SELECT (jsonb_populate_record(NULL::"+table+",to_jsonb(src)||jsonb_build_object('tenant_id','doc-b','id','forged','message_id','forged'))).* FROM "+table+" src LIMIT 1")
			return err
		})
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
			t.Fatalf("forged %s expected RLS 42501 got %v", table, err)
		}
	}
}
