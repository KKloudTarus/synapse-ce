package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing/storetest"
)

func TestTicketStoreRejectsNilPool(t *testing.T) {
	if store, err := NewTicketStore(nil); store != nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil PostgreSQL pool: store=%v error=%v", store, err)
	}
}

func TestTicketStoreConformanceAndRLS(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate ticket schema: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	for _, tenant := range []string{"ticket-a", "ticket-b"} {
		suffix := "a"
		if tenant == "ticket-b" {
			suffix = "b"
		}
		eng := "ticket-engagement-" + suffix
		finding := "ticket-finding-" + suffix
		integration := "ticket-integration-" + suffix
		project := "ticket-project-" + suffix
		if _, e := pool.Exec(ctx, `INSERT INTO tenants (id,name) VALUES ($1,$1) ON CONFLICT(id) DO NOTHING`, tenant); e != nil {
			t.Fatal(e)
		}
		err = WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO projects (id,tenant_id,name,key,source_binding)
				VALUES ($1,$2,'Ticket project',$1,'{}'::jsonb) ON CONFLICT(id) DO NOTHING`, project, tenant)
			if e != nil {
				return e
			}
			_, e = tx.Exec(ctx, `INSERT INTO engagements (id,tenant_id,name,project_id)
				VALUES ($1,$2,'Ticket engagement',$3)
				ON CONFLICT(id) DO UPDATE SET project_id=EXCLUDED.project_id`, eng, tenant, project)
			if e != nil {
				return e
			}
			_, e = tx.Exec(ctx, `INSERT INTO findings (id,tenant_id,engagement_id,title)
				VALUES ($1,$2,$3,'Ticket finding') ON CONFLICT(id) DO NOTHING`, finding, tenant, eng)
			if e != nil {
				return e
			}
			_, e = tx.Exec(ctx, `INSERT INTO integrations
                (id,tenant_id,provider,display_name,endpoint,created_at,updated_at)
				VALUES ($1,$2,'jenkins','Ticket fixture','https://jenkins.example',now(),now())
                ON CONFLICT(id) DO NOTHING`, integration, tenant)
			return e
		})
		if err != nil {
			t.Fatalf("fixture %s: %v", tenant, err)
		}
	}
	t.Cleanup(func() {
		for _, tenant := range []string{"ticket-a", "ticket-b"} {
			if err := WithTenant(context.Background(), pool, tenant, func(tx pgx.Tx) error {
				if err := deleteTicketFixtureRows(context.Background(), tx, tenant); err != nil {
					return err
				}
				for _, statement := range []string{
					`DELETE FROM findings WHERE tenant_id=$1 AND id LIKE 'ticket-finding-%'`,
					`DELETE FROM integrations WHERE tenant_id=$1 AND id LIKE 'ticket-integration-%'`,
					`DELETE FROM engagements WHERE tenant_id=$1 AND id LIKE 'ticket-engagement-%'`,
					`DELETE FROM projects WHERE tenant_id=$1 AND id LIKE 'ticket-project-%'`,
				} {
					if _, err := tx.Exec(context.Background(), statement, tenant); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Errorf("clean ticket fixture %s: %v", tenant, err)
			}
		}
	})
	fixture := storetest.Fixture{Tenant: "ticket-a", Other: "ticket-b",
		Integration: "ticket-integration-a", Project: "ticket-project-a", Engagement: "ticket-engagement-a", Finding: "ticket-finding-a"}
	store, err := NewTicketStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	assertTicketAutoPushReceiptQueue(t, ctx, pool, store, "ticket-a")
	storetest.Run(t, store, fixture)
	storetest.ConcurrentReplay(t, store, fixture)
	storetest.ConcurrentClaim(t, store, fixture)
	storetest.ConcurrentCompletionConflict(t, store, fixture)
	storetest.CanceledContext(t, store, fixture)
	assertTicketAuditedCreateFence(t, ctx, pool, store, fixture)
	storetest.Dispatch(t, store, fixture)
	storetest.StatusRefusalDoesNotGateTuple(t, store, fixture)
	storetest.InboundTombstone(t, store, fixture)
	assertTicketInboundTargetCatchup(t, ctx, pool, store, fixture)
	assertTicketRetryAuditRollback(t, ctx, pool, store, fixture)
	assertTicketStoreAuthoritativeProjectReferences(t, ctx, pool, store, fixture)
	for _, table := range []string{"ticket_mappings", "ticket_links", "ticket_intents", "ticket_dispatch_breakers", "ticket_auto_push_receipts", "ticket_external_observations", "ticket_retest_proposals", "ticket_external_comments", "ticket_inbound_poll_progress", "ticket_inbound_poll_backfill_cursors"} {
		var enabled, forced bool
		err = pool.QueryRow(ctx, `SELECT relrowsecurity,relforcerowsecurity
            FROM pg_class WHERE oid=$1::regclass`, table).Scan(&enabled, &forced)
		if err != nil || !enabled || !forced {
			t.Fatalf("%s RLS enabled=%v forced=%v error=%v", table, enabled, forced, err)
		}
	}
	// The default test DSN usually bypasses RLS. Verify isolation under a real
	// NOSUPERUSER / NOBYPASSRLS role, not just through WHERE tenant_id.
	const role = "ticket_rls_probe"
	_, _ = pool.Exec(ctx, `DROP OWNED BY `+role)
	_, _ = pool.Exec(ctx, `DROP ROLE IF EXISTS `+role)
	for _, statement := range []string{
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT,INSERT,UPDATE,DELETE ON ticket_mappings,ticket_links,ticket_intents,ticket_dispatch_breakers,ticket_auto_push_receipts,ticket_external_observations,ticket_retest_proposals,ticket_external_comments,ticket_inbound_poll_progress,ticket_inbound_poll_backfill_cursors TO ` + role,
	} {
		if _, err = pool.Exec(ctx, statement); err != nil {
			t.Fatalf("RLS role: %v", err)
		}
	}
	var superuser, bypassRLS bool
	if err := pool.QueryRow(ctx, `SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=$1`, role).Scan(&superuser, &bypassRLS); err != nil || superuser || bypassRLS {
		t.Fatalf("RLS probe role superuser=%t bypassrls=%t err=%v", superuser, bypassRLS, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP OWNED BY `+role)
		_, _ = pool.Exec(context.Background(), `DROP ROLE IF EXISTS `+role)
	})
	withRole := func(tenant string, fn func(pgx.Tx) error) error {
		return WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
			if _, e := tx.Exec(ctx, `SET LOCAL ROLE `+role); e != nil {
				return e
			}
			return fn(tx)
		})
	}
	for _, tenant := range []string{"ticket-b", ""} {
		for _, table := range []string{"ticket_mappings", "ticket_links", "ticket_intents", "ticket_dispatch_breakers", "ticket_auto_push_receipts", "ticket_external_observations", "ticket_retest_proposals", "ticket_external_comments", "ticket_inbound_poll_progress"} {
			err = withRole(tenant, func(tx pgx.Tx) error {
				var n int
				if e := tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); e != nil {
					return e
				}
				if n != 0 {
					return fmt.Errorf("tenant %q saw %d rows of %s", tenant, n, table)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("RLS isolation for tenant %q on %s: %v", tenant, table, err)
			}
		}
	}
	for _, attempt := range []struct {
		table string
		query string
	}{
		{"ticket_mappings", `INSERT INTO ticket_mappings
            (id,tenant_id,integration_id,engagement_id,project_key,issue_type,version,created_at,updated_at)
            VALUES ('ticket-forged-mapping','ticket-a','ticket-integration-a','ticket-engagement-a','SEC','Bug',1,now(),now())`},
		{"ticket_links", `INSERT INTO ticket_links
            (id,tenant_id,finding_id,engagement_id,external_url,created_at)
            VALUES ('ticket-forged-link','ticket-a','ticket-finding-a',
                    'ticket-engagement-a','https://jira.example/browse/FORGED',now())`},
		{"ticket_intents", `INSERT INTO ticket_intents
            (id,tenant_id,integration_id,mapping_id,finding_id,engagement_id,action,request_key,payload_digest,correlation_marker,created_at,updated_at)
            VALUES ('ticket-forged-intent','ticket-a','ticket-integration-a','ticket-map-a','ticket-finding-a','ticket-engagement-a','create','forged',repeat('a',64),'synapse-intent-ticket-forged-intent',now(),now())`},
		{"ticket_dispatch_breakers", `INSERT INTO ticket_dispatch_breakers
            (tenant_id,integration_id,project_key,issue_type,updated_at)
            VALUES ('ticket-a','ticket-integration-a','RLS','RLS',now())`},
	} {
		err = withRole("ticket-b", func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, attempt.query)
			return e
		})
		if err == nil {
			t.Fatalf("cross-tenant forged insert into %s passed RLS WITH CHECK", attempt.table)
		}
		err = withRole("", func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, attempt.query)
			return e
		})
		if err == nil {
			t.Fatalf("unbound forged insert into %s passed RLS WITH CHECK", attempt.table)
		}
	}
	for _, table := range []string{"ticket_mappings", "ticket_links", "ticket_intents", "ticket_dispatch_breakers"} {
		var affected int64
		err = withRole("ticket-b", func(tx pgx.Tx) error {
			tag, e := tx.Exec(ctx, "UPDATE "+table+" SET tenant_id=tenant_id WHERE tenant_id='ticket-a'")
			affected = tag.RowsAffected()
			return e
		})
		if err != nil || affected != 0 {
			t.Fatalf("cross-tenant update on %s affected %d rows: %v", table, affected, err)
		}
	}
	// Bypass the domain deliberately: the database should still reject userinfo URLs.
	err = WithTenant(ctx, pool, "ticket-a", func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO ticket_links
            (id,tenant_id,finding_id,engagement_id,external_url,created_at)
			VALUES ('ticket-bad-url','ticket-a','ticket-finding-a',
                    'ticket-engagement-a','https://user:token@jira.example/browse/SEC-1',now())`)
		return e
	})
	if err == nil {
		t.Fatal("database accepted credential-bearing link URL")
	}
	// FK constraints must reject a cross-tenant finding even under an elevated role.
	err = WithTenant(ctx, pool, "ticket-b", func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO ticket_links
            (id,tenant_id,finding_id,engagement_id,external_url,created_at)
			VALUES ('ticket-cross-fk','ticket-b','ticket-finding-a',
                    'ticket-engagement-a','https://jira.example/browse/CROSS',now())`)
		return e
	})
	if err == nil {
		t.Fatal("cross-tenant finding passed composite FK")
	}
	_, err = store.GetMapping(ctx, "ticket-b", "ticket-map-a")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("other tenant mapping visible: %v", err)
	}
}

func assertTicketInboundTargetCatchup(t *testing.T, ctx context.Context, pool *pgxpool.Pool, store *TicketStore, f storetest.Fixture) {
	t.Helper()
	now := time.Date(2026, 2, 4, 10, 0, 0, 0, time.UTC)
	makeIntent := func(id string) ticketing.Intent {
		return ticketing.Intent{ID: shared.ID(id), TenantID: f.Tenant, IntegrationID: f.Integration, MappingID: "ticket-map-a", FindingID: f.Finding, EngagementID: f.Engagement, Action: ticketing.Create, RequestKey: "catchup-" + id, PayloadDigest: strings.Repeat("c", 64), Marker: "synapse-intent-" + id, State: writeintent.Pending, Version: 1, MappingVersion: 1, ConnectionRevision: 1, CredentialRevision: 1, Snapshot: []byte(`{"fields":{"project":{"key":"SEC"},"issuetype":{"id":"Bug"}}}`), CreatedAt: now, UpdatedAt: now}
	}
	ineligible := []ticketing.Intent{makeIntent("a-catchup-00"), makeIntent("a-catchup-01")}
	eligible := []ticketing.Intent{makeIntent("a-catchup-02"), makeIntent("a-catchup-03")}
	for _, intent := range append(append([]ticketing.Intent{}, ineligible...), eligible...) {
		if _, created, err := store.CreateOrGetIntent(ctx, f.Tenant, intent); err != nil || !created {
			t.Fatalf("create catchup intent %s: created=%t err=%v", intent.ID, created, err)
		}
	}
	for index, intent := range eligible {
		lease := now.Add(time.Minute)
		claimed, err := store.TransitionIntent(ctx, f.Tenant, intent.ID, 1, ticketing.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now.Add(time.Duration(index+1)*time.Second))
		if err != nil {
			t.Fatalf("claim catchup intent %s: %v", intent.ID, err)
		}
		remote := ticketing.RemoteTicket{ID: "SEC-CATCHUP-" + string(rune('2'+index)), URL: "https://jira.example/browse/SEC-CATCHUP-" + string(rune('2'+index))}
		if _, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, claimed.Version, ticketing.IntentTransition{Event: writeintent.Acknowledge, Remote: &remote}, now.Add(time.Duration(index+2)*time.Second)); err != nil {
			t.Fatalf("complete catchup intent %s: %v", intent.ID, err)
		}
	}
	if err := WithTenant(ctx, pool, f.Tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM ticket_inbound_poll_progress WHERE tenant_id=$1 AND intent_id LIKE 'a-catchup-%'`, f.Tenant.String()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM ticket_inbound_poll_backfill_cursors WHERE tenant_id=$1`, f.Tenant.String())
		return err
	}); err != nil {
		t.Fatalf("reset catchup state: %v", err)
	}
	if _, err := store.ListInboundTicketTargets(ctx, f.Tenant, 2); err != nil {
		t.Fatalf("first bounded catchup scan: %v", err)
	}
	assertCatchupCursor(t, ctx, pool, f.Tenant, "a-catchup-01", false, 0)
	if _, err := store.ListInboundTicketTargets(ctx, f.Tenant, 2); err != nil {
		t.Fatalf("second bounded catchup scan: %v", err)
	}
	assertCatchupCursor(t, ctx, pool, f.Tenant, "a-catchup-03", false, 2)
	for attempt := 0; attempt < 100; attempt++ {
		if _, err := store.ListInboundTicketTargets(ctx, f.Tenant, 2); err != nil {
			t.Fatalf("complete catchup scan %d: %v", attempt, err)
		}
		if catchupComplete(t, ctx, pool, f.Tenant) {
			break
		}
	}
	if !catchupComplete(t, ctx, pool, f.Tenant) {
		t.Fatal("bounded catchup did not finish scanning historical intents")
	}
	assertCatchupProgress(t, ctx, pool, f.Tenant, 2)
}

func assertCatchupCursor(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant shared.ID, after string, complete bool, progress int) {
	t.Helper()
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		var gotAfter string
		var gotComplete bool
		if err := tx.QueryRow(ctx, `SELECT after_intent_id,complete FROM ticket_inbound_poll_backfill_cursors WHERE tenant_id=$1`, tenant.String()).Scan(&gotAfter, &gotComplete); err != nil {
			return err
		}
		if gotAfter != after || gotComplete != complete {
			return fmt.Errorf("cursor after=%q complete=%t", gotAfter, gotComplete)
		}
		return nil
	}); err != nil {
		t.Fatalf("catchup cursor want after=%q complete=%t progress=%d: %v", after, complete, progress, err)
	}
	assertCatchupProgress(t, ctx, pool, tenant, progress)
}

func catchupComplete(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant shared.ID) bool {
	t.Helper()
	complete := false
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT complete FROM ticket_inbound_poll_backfill_cursors WHERE tenant_id=$1`, tenant.String()).Scan(&complete)
	}); err != nil {
		t.Fatalf("read catchup completion: %v", err)
	}
	return complete
}

func assertCatchupProgress(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant shared.ID, want int) {
	t.Helper()
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		var got int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM ticket_inbound_poll_progress WHERE tenant_id=$1 AND intent_id LIKE 'a-catchup-%'`, tenant.String()).Scan(&got); err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("progress=%d", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("catchup progress want=%d: %v", want, err)
	}
}

func assertTicketAutoPushReceiptQueue(t *testing.T, ctx context.Context, pool *pgxpool.Pool, store *TicketStore, tenant shared.ID) {
	t.Helper()
	id := shared.ID("ticket-auto-event-" + time.Now().UTC().Format("20060102150405.000000000"))
	err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_events
            (tenant_id,id,event_type,source_kind,source_id,engagement_id,severity,schema_version,occurred_at,data,subject_kind,subject_id)
            VALUES($1,$2,'finding.status_changed','finding_status',$3,'ticket-engagement-a','high',1,now(),'{"to_status":"confirmed"}'::jsonb,'finding','ticket-finding-a')`, tenant.String(), id.String(), id.String())
		return err
	})
	if err != nil {
		t.Fatalf("append status event: %v", err)
	}
	events, err := store.ListAutoPushEvents(ctx, tenant, time.Now().UTC().Add(time.Second), 10)
	if err != nil {
		t.Fatal(err)
	}
	var event ports.TicketAutoPushEvent
	for _, candidate := range events {
		if candidate.ID == id {
			event = candidate
			break
		}
	}
	if event.ID != id || event.FindingID != "ticket-finding-a" || event.ToStatus != "confirmed" {
		t.Fatalf("receipt event=%+v all=%+v", event, events)
	}
	if err = store.CompleteAutoPushEvent(ctx, tenant, event, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	events, err = store.ListAutoPushEvents(ctx, tenant, time.Now().UTC().Add(time.Second), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range events {
		if candidate.ID == id {
			t.Fatal("completed receipt was returned")
		}
	}
}

func assertTicketAuditedCreateFence(t *testing.T, ctx context.Context, pool *pgxpool.Pool, store *TicketStore, f storetest.Fixture) {
	t.Helper()
	now := time.Date(2026, 2, 4, 0, 0, 0, 0, time.UTC)
	seedFinding := func(id string) {
		t.Helper()
		if err := WithTenant(ctx, pool, f.Tenant.String(), func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO findings(id,tenant_id,engagement_id,title) VALUES($1,$2,$3,'Ticket audited fence')`, id, f.Tenant.String(), f.Engagement.String())
			return e
		}); err != nil {
			t.Fatal(err)
		}
	}
	makeIntent := func(id, findingID, key string) ticketing.Intent {
		return ticketing.Intent{ID: shared.ID(id), TenantID: f.Tenant, IntegrationID: f.Integration, MappingID: "ticket-map-a", FindingID: shared.ID(findingID), EngagementID: f.Engagement, Action: ticketing.Create, RequestKey: key, PayloadDigest: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", Marker: "synapse-intent-" + id, State: writeintent.Pending, Version: 1, MappingVersion: 1, ConnectionRevision: 1, Snapshot: []byte(`{"fields":{"project":{"key":"SEC"},"issuetype":{"id":"Bug"}}}`), CreatedAt: now, UpdatedAt: now}
	}
	audit := func(target string, at time.Time) ports.AuditEntry {
		return ports.AuditEntry{Actor: "admin", Action: "ticket.intent.created", Target: target, At: at}
	}
	const findingID = "ticket-finding-audited-fence"
	seedFinding(findingID)
	first := makeIntent("ticket-audited-fence-first", findingID, "audited-first")
	if _, created, err := store.CreateOrGetIntentAudited(ctx, f.Tenant, first, audit(first.ID.String(), now)); err != nil || !created {
		t.Fatalf("first audited create: created=%t err=%v", created, err)
	}
	replay := first
	replay.ID, replay.Marker = "ticket-audited-fence-replay", "synapse-intent-ticket-audited-fence-replay"
	if got, created, err := store.CreateOrGetIntentAudited(ctx, f.Tenant, replay, audit(replay.ID.String(), now)); err != nil || created || got.ID != first.ID {
		t.Fatalf("audited replay=%+v created=%t err=%v", got, created, err)
	}
	blocked := makeIntent("ticket-audited-fence-blocked", findingID, "audited-blocked")
	if _, _, err := store.CreateOrGetIntentAudited(ctx, f.Tenant, blocked, audit(blocked.ID.String(), now)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("pending create bypassed fence: %v", err)
	}
	lease := now.Add(time.Minute)
	claimed, err := store.TransitionIntent(ctx, f.Tenant, first.ID, 1, ticketing.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.TransitionIntent(ctx, f.Tenant, first.ID, claimed.Version, ticketing.IntentTransition{Event: writeintent.Acknowledge, Remote: &ticketing.RemoteTicket{ID: "SEC-AUDIT-1", URL: "https://jira.example/browse/SEC-AUDIT-1"}}, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	afterDone := makeIntent("ticket-audited-fence-done", findingID, "audited-after-done")
	if _, created, err := store.CreateOrGetIntentAudited(ctx, f.Tenant, afterDone, audit(afterDone.ID.String(), now.Add(3*time.Second))); err != nil || !created {
		t.Fatalf("after done: created=%t err=%v", created, err)
	}
	lateReplay := first
	lateReplay.ID, lateReplay.Marker = "ticket-audited-fence-late-replay", "synapse-intent-ticket-audited-fence-late-replay"
	if got, created, err := store.CreateOrGetIntentAudited(ctx, f.Tenant, lateReplay, audit(lateReplay.ID.String(), now.Add(3*time.Second))); err != nil || created || got.ID != first.ID {
		t.Fatalf("late audited replay=%+v created=%t err=%v", got, created, err)
	}
	alteredReplay := lateReplay
	alteredReplay.PayloadDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, _, err := store.CreateOrGetIntentAudited(ctx, f.Tenant, alteredReplay, audit(alteredReplay.ID.String(), now.Add(3*time.Second))); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("altered late replay accepted: %v", err)
	}
	claimed, err = store.TransitionIntent(ctx, f.Tenant, afterDone.ID, 1, ticketing.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.TransitionIntent(ctx, f.Tenant, afterDone.ID, claimed.Version, ticketing.IntentTransition{Event: writeintent.LeaseExpired}, lease); err != nil {
		t.Fatal(err)
	}
	uncertain := makeIntent("ticket-audited-fence-uncertain", findingID, "audited-uncertain")
	if _, _, err = store.CreateOrGetIntentAudited(ctx, f.Tenant, uncertain, audit(uncertain.ID.String(), lease)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("uncertain create bypassed fence: %v", err)
	}
	const racingFinding = "ticket-finding-audited-race"
	seedFinding(racingFinding)
	left, right := makeIntent("ticket-audited-race-left", racingFinding, "audited-race-left"), makeIntent("ticket-audited-race-right", racingFinding, "audited-race-right")
	results := make(chan error, 2)
	for _, candidate := range []ticketing.Intent{left, right} {
		go func(i ticketing.Intent) {
			_, _, e := store.CreateOrGetIntentAudited(ctx, f.Tenant, i, audit(i.ID.String(), now))
			results <- e
		}(candidate)
	}
	wins := 0
	for range 2 {
		e := <-results
		if e == nil {
			wins++
		} else if !errors.Is(e, shared.ErrConflict) {
			t.Fatalf("concurrent audited create: %v", e)
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent audited creates admitted=%d", wins)
	}
	const failureFinding = "ticket-finding-audited-failure"
	seedFinding(failureFinding)
	const function = "ticket_test_fail_create_audit"
	_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS `+function+` ON audit_log`)
	_, _ = pool.Exec(ctx, `DROP FUNCTION IF EXISTS `+function+`()`)
	if _, err = pool.Exec(ctx, `CREATE FUNCTION `+function+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced ticket create audit failure'; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `CREATE TRIGGER `+function+` BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION `+function+`()`); err != nil {
		t.Fatal(err)
	}
	failedAudit := makeIntent("ticket-audited-fence-audit-failure", failureFinding, "audited-audit-failure")
	if _, _, err = store.CreateOrGetIntentAudited(ctx, f.Tenant, failedAudit, audit(failedAudit.ID.String(), now)); err == nil {
		t.Fatal("audited create accepted audit failure")
	}
	if _, err = store.GetIntent(ctx, f.Tenant, failedAudit.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("audit failure published intent: %v", err)
	}
	_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS `+function+` ON audit_log`)
	_, _ = pool.Exec(ctx, `DROP FUNCTION IF EXISTS `+function+`()`)
}

func assertTicketRetryAuditRollback(t *testing.T, ctx context.Context, pool *pgxpool.Pool, store *TicketStore, f storetest.Fixture) {
	t.Helper()
	now := time.Date(2026, 2, 3, 0, 0, 0, 0, time.UTC)
	intent := ticketing.Intent{ID: "ticket-retry-audit-failure", TenantID: f.Tenant, IntegrationID: f.Integration,
		MappingID: "ticket-map-a", FindingID: f.Finding, EngagementID: f.Engagement, Action: ticketing.Create,
		RequestKey: "retry-audit-failure", PayloadDigest: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		Marker: "synapse-intent-ticket-retry-audit-failure", State: writeintent.Pending, Version: 1,
		MappingVersion: 1, ConnectionRevision: 1, Snapshot: []byte(`{"fields":{"project":{"key":"SEC"},"issuetype":{"id":"Bug"}}}`), CreatedAt: now, UpdatedAt: now}
	if _, created, err := store.CreateOrGetIntent(ctx, f.Tenant, intent); err != nil || !created {
		t.Fatalf("create retry audit intent: created=%t err=%v", created, err)
	}
	claimed, ok, err := store.AcquireDispatch(ctx, f.Tenant, intent.ID, 1, now, now.Add(time.Minute))
	if err != nil || !ok {
		t.Fatalf("claim retry audit intent: ok=%t err=%v", ok, err)
	}
	failed, err := store.FinishDispatch(ctx, f.Tenant, intent.ID, claimed.Version, ticketing.IntentTransition{Event: writeintent.Reject, ErrorCode: "provider_rejected"}, now.Add(time.Second), nil, "http_401")
	if err != nil || failed.State != writeintent.Failed {
		t.Fatalf("fail retry audit intent: %+v err=%v", failed, err)
	}
	const function = "ticket_test_fail_retry_audit"
	_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS `+function+` ON audit_log`)
	_, _ = pool.Exec(ctx, `DROP FUNCTION IF EXISTS `+function+`()`)
	if _, err = pool.Exec(ctx, `CREATE FUNCTION `+function+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced ticket audit failure'; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `CREATE TRIGGER `+function+` BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION `+function+`()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+function+` ON audit_log`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+function+`()`)
	})
	_, err = store.RetryIntentAudited(ctx, f.Tenant, intent.ID, failed.Version, now.Add(2*time.Second), ports.AuditEntry{Actor: "admin", Action: "ticket.intent.retry_duplicate_risk", Target: intent.ID.String(), At: now.Add(2 * time.Second)})
	if err == nil {
		t.Fatal("retry accepted forced audit failure")
	}
	if err = store.ResetBreaker(ctx, f.Tenant, f.Integration, "SEC", "Bug", ports.AuditEntry{Actor: "admin", Action: "ticket.breaker.reset", Target: f.Integration.String(), At: now.Add(2 * time.Second)}); err == nil {
		t.Fatal("reset accepted forced audit failure")
	}
	if err = WithTenant(ctx, pool, f.Tenant.String(), func(tx pgx.Tx) error {
		var code string
		var gate time.Time
		if e := tx.QueryRow(ctx, `SELECT breaker_code,gate_until FROM ticket_dispatch_breakers WHERE tenant_id=$1 AND integration_id=$2 AND project_key='SEC' AND issue_type='Bug'`, f.Tenant.String(), f.Integration.String()).Scan(&code, &gate); e != nil {
			return e
		}
		if code != "http_401" || !gate.After(now.AddDate(99, 0, 0)) {
			return fmt.Errorf("audit failure cleared gate: code=%s gate=%s", code, gate)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetIntent(ctx, f.Tenant, intent.ID)
	if err != nil || got.State != writeintent.Failed || got.Version != failed.Version {
		t.Fatalf("audit failure published retry: %+v err=%v", got, err)
	}
}

func assertTicketStoreAuthoritativeProjectReferences(t *testing.T, ctx context.Context, pool *pgxpool.Pool, store *TicketStore, f storetest.Fixture) {
	t.Helper()
	now := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)
	projectMapping := ticketing.Mapping{ID: "ticket-project-map-a", TenantID: f.Tenant, IntegrationID: f.Integration,
		Scope: ticketing.Project, ScopeID: f.Project, ProjectKey: "SEC", IssueType: "Bug",
		Labels: []string{}, PriorityMap: map[string]string{}, Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := store.CreateMapping(ctx, f.Tenant, projectMapping); err != nil {
		t.Fatalf("create project-scoped mapping: %v", err)
	}
	intent := ticketing.Intent{ID: "ticket-project-intent-a", TenantID: f.Tenant, IntegrationID: f.Integration,
		MappingID: projectMapping.ID, FindingID: f.Finding, EngagementID: f.Engagement, Action: ticketing.Create,
		RequestKey: "project-context", PayloadDigest: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		Marker: "synapse-intent-ticket-project-intent-a", State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
	if _, created, err := store.CreateOrGetIntent(ctx, f.Tenant, intent); err != nil || !created {
		t.Fatalf("create intent against authoritative project context: created=%t err=%v", created, err)
	}

	const otherProject = "ticket-project-other-a"
	if err := WithTenant(ctx, pool, f.Tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO projects(id,tenant_id,name,key,source_binding)
            VALUES($1,$2,'Other ticket project',$1,'{}'::jsonb)`, otherProject, f.Tenant.String())
		return err
	}); err != nil {
		t.Fatalf("seed unrelated project: %v", err)
	}
	t.Cleanup(func() {
		_ = WithTenant(context.Background(), pool, f.Tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), `DELETE FROM projects WHERE tenant_id=$1 AND id=$2`, f.Tenant.String(), otherProject)
			return err
		})
	})
	wrongMapping := projectMapping
	wrongMapping.ID = "ticket-project-map-other-a"
	wrongMapping.ScopeID = otherProject
	wrongMapping.CreatedAt = now.Add(time.Second)
	wrongMapping.UpdatedAt = wrongMapping.CreatedAt
	if err := store.CreateMapping(ctx, f.Tenant, wrongMapping); err != nil {
		t.Fatalf("create unrelated project mapping: %v", err)
	}
	wrongIntent := intent
	wrongIntent.ID = "ticket-project-intent-other-a"
	wrongIntent.MappingID = wrongMapping.ID
	wrongIntent.RequestKey = "wrong-project-context"
	wrongIntent.Marker = "synapse-intent-" + wrongIntent.ID.String()
	if _, _, err := store.CreateOrGetIntent(ctx, f.Tenant, wrongIntent); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("project mapping accepted another project's engagement: %v", err)
	}
	missingFinding := intent
	missingFinding.ID = "ticket-project-intent-missing-a"
	missingFinding.FindingID = "ticket-finding-missing-a"
	missingFinding.RequestKey = "missing-finding"
	missingFinding.Marker = "synapse-intent-" + missingFinding.ID.String()
	if _, _, err := store.CreateOrGetIntent(ctx, f.Tenant, missingFinding); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing finding accepted for ticket intent: %v", err)
	}
}

func TestTicketStorePersistsAfterPoolReopen(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate ticket schema: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}

	const tenant = "ticket-reopen"
	const engagement = "ticket-reopen-engagement"
	const finding = "ticket-reopen-finding"
	const integration = "ticket-reopen-integration"
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id,name) VALUES ($1,$1) ON CONFLICT(id) DO NOTHING`, tenant); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO engagements (id,tenant_id,name) VALUES ($1,$2,'Ticket reopen engagement') ON CONFLICT(id) DO NOTHING`, []any{engagement, tenant}},
			{`INSERT INTO findings (id,tenant_id,engagement_id,title) VALUES ($1,$2,$3,'Ticket reopen finding') ON CONFLICT(id) DO NOTHING`, []any{finding, tenant, engagement}},
			{`INSERT INTO integrations (id,tenant_id,provider,display_name,endpoint,created_at,updated_at)
                VALUES ($1,$2,'jenkins','Ticket reopen fixture','https://jenkins.example',now(),now()) ON CONFLICT(id) DO NOTHING`, []any{integration, tenant}},
		} {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		pool.Close()
		t.Fatalf("seed reopen fixture: %v", err)
	}

	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	store, err := NewTicketStore(pool)
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	mapping := ticketing.Mapping{ID: "ticket-reopen-mapping", TenantID: tenant, IntegrationID: integration,
		Scope: ticketing.Engagement, ScopeID: engagement, ProjectKey: "SEC", IssueType: "Bug",
		Labels: []string{}, PriorityMap: map[string]string{}, Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := store.CreateMapping(ctx, tenant, mapping); err != nil {
		pool.Close()
		t.Fatalf("create mapping before reopen: %v", err)
	}
	intent := ticketing.Intent{ID: "ticket-reopen-intent", TenantID: tenant, IntegrationID: integration,
		MappingID: mapping.ID, FindingID: finding, EngagementID: engagement, Action: ticketing.Create,
		RequestKey: "reopen", PayloadDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Marker: "synapse-intent-ticket-reopen-intent", State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
	if _, created, err := store.CreateOrGetIntent(ctx, tenant, intent); err != nil || !created {
		pool.Close()
		t.Fatalf("create intent before reopen: created=%v err=%v", created, err)
	}
	lease := now.Add(time.Minute)
	claimed, err := store.TransitionIntent(ctx, tenant, intent.ID, 1, ticketing.IntentTransition{
		Event: writeintent.Claim, LeaseUntil: &lease,
	}, now)
	if err != nil || claimed.State != writeintent.InFlight || claimed.Version != 2 || claimed.Attempts != 1 {
		pool.Close()
		t.Fatalf("claim intent before reopen: %+v, %v", claimed, err)
	}
	pool.Close()

	pool, err = Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	t.Cleanup(func() {
		assertTicketFixtureRowsAbsent(t, pool, tenant)
	})
	t.Cleanup(func() {
		if err := WithTenant(context.Background(), pool, tenant, func(tx pgx.Tx) error {
			if err := deleteTicketFixtureRows(context.Background(), tx, tenant); err != nil {
				return err
			}
			for _, statement := range []struct {
				query string
				args  []any
			}{
				{`DELETE FROM findings WHERE tenant_id=$1 AND id=$2`, []any{tenant, finding}},
				{`DELETE FROM integrations WHERE tenant_id=$1 AND id=$2`, []any{tenant, integration}},
				{`DELETE FROM engagements WHERE tenant_id=$1 AND id=$2`, []any{tenant, engagement}},
			} {
				if _, err := tx.Exec(context.Background(), statement.query, statement.args...); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Errorf("clean reopen ticket fixture: %v", err)
		}
	})

	store, err = NewTicketStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	gotMapping, err := store.GetMapping(ctx, tenant, mapping.ID)
	if err != nil || gotMapping.ID != mapping.ID || gotMapping.ProjectKey != mapping.ProjectKey {
		t.Fatalf("mapping after pool reopen: %+v, %v", gotMapping, err)
	}
	gotIntent, err := store.GetIntent(ctx, tenant, intent.ID)
	if err != nil || gotIntent.ID != intent.ID || gotIntent.State != writeintent.InFlight || gotIntent.Version != 2 || gotIntent.Attempts != 1 || gotIntent.LeaseUntil == nil || !gotIntent.LeaseUntil.Equal(lease) {
		t.Fatalf("intent after pool reopen: %+v, %v", gotIntent, err)
	}
	if _, err := store.TransitionIntent(ctx, tenant, intent.ID, 2, ticketing.IntentTransition{
		Event: writeintent.Acknowledge, Remote: &ticketing.RemoteTicket{ID: "SEC-INVALID", URL: "https://user:token@jira.example/browse/SEC-INVALID"},
	}, lease); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid completion remote accepted: %v", err)
	}
	unchanged, err := store.GetIntent(ctx, tenant, intent.ID)
	if err != nil || unchanged.State != writeintent.InFlight || unchanged.Version != 2 || unchanged.RemoteID != "" || unchanged.RemoteURL != "" || unchanged.ErrorCode != "" {
		t.Fatalf("invalid completion partially changed intent: %+v, %v", unchanged, err)
	}
	if links, listErr := store.ListLinks(ctx, tenant, finding); listErr != nil || len(links) != 0 {
		t.Fatalf("invalid completion created a link: %+v, %v", links, listErr)
	}
	uncertain, err := store.TransitionIntent(ctx, tenant, intent.ID, 2, ticketing.IntentTransition{
		Event: writeintent.LeaseExpired,
	}, lease)
	if err != nil || uncertain.State != writeintent.Uncertain {
		t.Fatalf("expired lease after pool reopen: %+v, %v", uncertain, err)
	}
	if _, err := store.TransitionIntent(ctx, tenant, intent.ID, 3, ticketing.IntentTransition{
		Event: writeintent.Claim, LeaseUntil: &lease,
	}, lease.Add(time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("blind claim after reopened uncertain intent: %v", err)
	}
	remote := ticketing.RemoteTicket{ID: "SEC-REOPEN-1", URL: "https://jira.example/browse/SEC-REOPEN-1"}
	done, err := store.TransitionIntent(ctx, tenant, intent.ID, 3, ticketing.IntentTransition{
		Event: writeintent.ReconcileFound, Remote: &remote,
	}, lease.Add(2*time.Second))
	if err != nil || done.State != writeintent.Done || done.Version != 4 || done.RemoteID != remote.ID ||
		done.RemoteURL != remote.URL || done.ErrorCode != "" {
		t.Fatalf("reconcile completed intent before second reopen: %+v, %v", done, err)
	}

	pool.Close()
	pool, err = Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	store, err = NewTicketStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	durable, err := store.GetIntent(ctx, tenant, intent.ID)
	if err != nil || durable.State != writeintent.Done || durable.Version != 4 || durable.RemoteID != remote.ID ||
		durable.RemoteURL != remote.URL || durable.ErrorCode != "" {
		t.Fatalf("completed intent after second pool reopen: %+v, %v", durable, err)
	}
	links, err := store.ListLinks(ctx, tenant, finding)
	if err != nil || len(links) != 1 || links[0].ID != intent.ID || links[0].IntegrationID != integration ||
		links[0].ExternalID != remote.ID || links[0].ExternalURL != remote.URL {
		t.Fatalf("completion link after second pool reopen: %+v, %v", links, err)
	}
}

// deleteTicketFixtureRows removes every ticketing table that can retain a
// reference to the fixture's mappings, intents, findings, or integrations.
// The order follows the foreign-key graph, keeping cleanup failures observable.
func deleteTicketFixtureRows(ctx context.Context, tx pgx.Tx, tenant string) error {
	for _, table := range []string{
		"ticket_external_comments",
		"ticket_retest_proposals",
		"ticket_external_observations",
		"ticket_inbound_poll_progress",
		"ticket_inbound_poll_backfill_cursors",
		"ticket_inbound_config",
		"ticket_status_sync",
		"ticket_group_members",
		"ticket_groups",
		"ticket_auto_push_receipts",
		"ticket_dispatch_breakers",
		"ticket_intents",
		"ticket_links",
		"ticket_mappings",
	} {
		if _, err := tx.Exec(ctx, "DELETE FROM "+table+" WHERE tenant_id=$1", tenant); err != nil {
			return fmt.Errorf("delete %s: %w", table, err)
		}
	}
	return nil
}

func assertTicketFixtureRowsAbsent(t *testing.T, pool *pgxpool.Pool, tenant string) {
	t.Helper()
	if err := WithTenant(context.Background(), pool, tenant, func(tx pgx.Tx) error {
		for _, table := range []string{"ticket_intents", "ticket_inbound_poll_progress", "ticket_inbound_poll_backfill_cursors"} {
			var count int
			if err := tx.QueryRow(context.Background(), "SELECT count(*) FROM "+table+" WHERE tenant_id=$1", tenant).Scan(&count); err != nil {
				return fmt.Errorf("count %s: %w", table, err)
			}
			if count != 0 {
				return fmt.Errorf("%s retained %d rows", table, count)
			}
		}
		return nil
	}); err != nil {
		t.Errorf("assert ticket fixture cleanup: %v", err)
	}
}
