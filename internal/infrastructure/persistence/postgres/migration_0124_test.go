package postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0124TelemetryAgentGapRevisionGuards(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	var rls, forced bool
	if err := pool.QueryRow(ctx, `SELECT relrowsecurity,relforcerowsecurity
		FROM pg_class WHERE oid='telemetry_agent_gap_revisions'::regclass`).Scan(&rls, &forced); err != nil {
		t.Fatalf("inspect signed gap revision RLS: %v", err)
	}
	if !rls || !forced {
		t.Fatalf("signed gap revision RLS/forced=%t/%t, want true/true", rls, forced)
	}
	for _, trigger := range []string{"telemetry_agent_gap_revisions_append_only", "telemetry_agent_gap_revisions_no_truncate"} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_trigger
			WHERE tgrelid='telemetry_agent_gap_revisions'::regclass AND tgname=$1 AND NOT tgisinternal)`, trigger).Scan(&exists); err != nil {
			t.Fatalf("inspect signed gap trigger %s: %v", trigger, err)
		}
		if !exists {
			t.Fatalf("migration 0124 did not install %s", trigger)
		}
	}
	for _, constraint := range []string{
		"telemetry_agent_gap_revisions_digest_sha256",
		"telemetry_agent_gap_revisions_authenticated_agent",
		"telemetry_agent_gap_revisions_authenticated_host",
		"telemetry_agent_gap_revisions_sequence_shape",
		"telemetry_agent_gap_revision_projection_fk",
	} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_constraint
			WHERE conrelid='telemetry_agent_gap_revisions'::regclass AND conname=$1)`, constraint).Scan(&exists); err != nil {
			t.Fatalf("inspect signed gap constraint %s: %v", constraint, err)
		}
		if !exists {
			t.Fatalf("migration 0124 did not install %s", constraint)
		}
	}

	suffix := randHex(t)
	tenant := "mig0124-" + suffix
	agent := "agent-" + suffix
	asset := "asset-" + suffix
	gap := "gap-" + suffix
	stream := "stream-" + suffix
	at := time.Now().UTC().Truncate(time.Microsecond)
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `SET session_replication_role = replica`)
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_agent_gap_revisions WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_agent_gaps WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(bg, `DELETE FROM fleet_agents WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tenant)
		_, _ = pool.Exec(bg, `SET session_replication_role = origin`)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatalf("seed migration tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_agents(id,tenant_id,name,token_hash,state) VALUES($1,$2,$1,$3,'active')`, agent, tenant, "hash-"+suffix); err != nil {
		t.Fatalf("seed migration agent: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_assets(id,tenant_id,kind,"key",name) VALUES($1,$2,'host',$1,$1)`, asset, tenant); err != nil {
		t.Fatalf("seed migration asset: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO telemetry_agent_gaps
		(tenant_id,gap_id,agent_id,asset_id,stream_id,priority,epoch,known_sequence,from_sequence,to_sequence,count,reason,from_at,to_at,first_reported_at,updated_at)
		VALUES($1,$2,$3,$4,$5,3,1,true,1,2,2,'quota_eviction',$6,$7,$7,$7)`, tenant, gap, agent, asset, stream, at.Add(-time.Minute), at); err != nil {
		t.Fatalf("seed signed gap projection: %v", err)
	}
	insert := `INSERT INTO telemetry_agent_gap_revisions
		(tenant_id,signed_content_digest,gap_id,revision,authenticated_agent_id,agent_id,host_id,agent_session_id,
		 asset_id,stream_id,priority,epoch,known_sequence,from_sequence,to_sequence,count,reason,
		 from_at,to_at,from_at_unix_nano,to_at_unix_nano,protocol_version,key_id,signature,received_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,3,1,$11,$12,$13,$14,'quota_eviction',$15,$16,$17,$18,2,$19,$20,$16)`
	validArgs := []any{
		tenant, strings.Repeat("a", 64), gap, 1, agent, agent, agent, "session-" + suffix,
		asset, stream, true, 1, 2, 2, at.Add(-time.Minute), at,
		at.Add(-time.Minute).UnixNano(), at.UnixNano(), "key-" + suffix, "signature-" + suffix,
	}
	if _, err := pool.Exec(ctx, insert, validArgs...); err != nil {
		t.Fatalf("seed signed gap revision: %v", err)
	}

	role := "telemetry_gap_revision_runtime_" + randHex(t)
	if _, err := pool.Exec(ctx, `CREATE ROLE `+role+` NOSUPERUSER NOBYPASSRLS`); err != nil {
		t.Fatalf("create signed gap RLS role: %v", err)
	}
	if _, err := pool.Exec(ctx, `GRANT USAGE ON SCHEMA public TO `+role); err != nil {
		t.Fatalf("grant signed gap schema usage: %v", err)
	}
	if _, err := pool.Exec(ctx, `GRANT SELECT ON telemetry_agent_gap_revisions TO `+role); err != nil {
		t.Fatalf("grant signed gap reads: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DROP OWNED BY `+role)
		_, _ = pool.Exec(bg, `DROP ROLE IF EXISTS `+role)
	})
	visible := func(tenantID string) int {
		t.Helper()
		var count int
		if err := WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
				return err
			}
			return tx.QueryRow(ctx, `SELECT count(*) FROM telemetry_agent_gap_revisions WHERE gap_id=$1`, gap).Scan(&count)
		}); err != nil {
			t.Fatalf("query signed gap history through RLS role: %v", err)
		}
		return count
	}
	if visible(tenant) != 1 || visible("another-tenant") != 0 || visible("") != 0 {
		t.Fatal("signed gap revision RLS did not isolate tenant history")
	}

	for _, mutation := range []struct {
		name, query string
	}{
		{"UPDATE", `UPDATE telemetry_agent_gap_revisions SET signature='tampered' WHERE tenant_id='` + tenant + `'`},
		{"DELETE", `DELETE FROM telemetry_agent_gap_revisions WHERE tenant_id='` + tenant + `'`},
		{"TRUNCATE", `TRUNCATE telemetry_agent_gap_revisions`},
	} {
		_, err := pool.Exec(ctx, mutation.query)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
			t.Fatalf("%s immutable signed gap history error=%v, want SQLSTATE P0001", mutation.name, err)
		}
	}
	invalid := []struct {
		name string
		args []any
	}{
		{name: "digest", args: func() []any {
			args := append([]any(nil), validArgs...)
			args[1], args[3] = "not-sha256", 2
			return args
		}()},
		{name: "authenticated identity", args: func() []any {
			args := append([]any(nil), validArgs...)
			args[1], args[3], args[4] = strings.Repeat("b", 64), 2, "other-agent"
			return args
		}()},
		{name: "sequence shape", args: func() []any {
			args := append([]any(nil), validArgs...)
			args[1], args[3], args[13] = strings.Repeat("c", 64), 2, 3
			return args
		}()},
	}
	for _, tc := range invalid {
		if _, err := pool.Exec(ctx, insert, tc.args...); err == nil {
			t.Fatalf("invalid %s signed gap revision unexpectedly inserted", tc.name)
		}
	}
}

func TestMigration0124RefusesRollbackWithSignedGapHistory(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db := openLockedGooseDB(t, dsn)
	const tenant = "migration-0124-probe"
	const agent = "migration-0124-agent"
	const asset = "migration-0124-asset"
	const gap = "migration-0124-gap"
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `SET session_replication_role = replica`)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM telemetry_agent_gap_revisions WHERE tenant_id=$1`, tenant)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM telemetry_agent_gaps WHERE tenant_id=$1`, tenant)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM fleet_assets WHERE tenant_id=$1`, tenant)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM fleet_agents WHERE tenant_id=$1`, tenant)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant)
		_, _ = db.ExecContext(context.Background(), `SET session_replication_role = origin`)
		_ = db.Close()
	})
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("dialect: %v", err)
	}

	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatalf("seed rollback tenant: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO fleet_agents(id,tenant_id,name,token_hash,state) VALUES($1,$2,$1,'hash','active')`, agent, tenant); err != nil {
		t.Fatalf("seed rollback agent: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO fleet_assets(id,tenant_id,kind,"key",name) VALUES($1,$2,'host',$1,$1)`, asset, tenant); err != nil {
		t.Fatalf("seed rollback asset: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO telemetry_agent_gaps
		(tenant_id,gap_id,agent_id,asset_id,stream_id,priority,epoch,known_sequence,count,reason,from_at,to_at,first_reported_at,updated_at)
		VALUES($1,$2,$3,$4,'migration-0124-stream',3,1,false,1,'state_recovery',$5,$5,$5,$5)`, tenant, gap, agent, asset, at); err != nil {
		t.Fatalf("seed rollback projection: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO telemetry_agent_gap_revisions
		(tenant_id,signed_content_digest,gap_id,revision,authenticated_agent_id,agent_id,host_id,agent_session_id,asset_id,stream_id,
		 priority,epoch,known_sequence,count,reason,from_at,to_at,from_at_unix_nano,to_at_unix_nano,protocol_version,key_id,signature,received_at)
		VALUES($1,$2,$3,1,$4,$4,$4,'session',$5,'migration-0124-stream',3,1,false,1,'state_recovery',$6,$6,$7,$7,2,'key','signature',$6)`,
		tenant, strings.Repeat("c", 64), gap, agent, asset, at, at.UnixNano()); err != nil {
		t.Fatalf("seed rollback signed revision: %v", err)
	}
	// DownTo, not Down: Down rolls back only the NEWEST applied migration, so once a later
	// migration exists it would absorb this assertion instead of exercising 0124's guard.
	// DownTo unwinds every migration above the target, which drops those later tables, so
	// re-apply them before returning or the rest of the suite runs against a partial schema.
	t.Cleanup(func() {
		if err := goose.Up(db, "."); err != nil {
			t.Errorf("restore migrations after rollback probe: %v", err)
		}
	})
	if err := goose.DownTo(db, ".", 123); err == nil || !strings.Contains(err.Error(), "cannot roll back 0124") {
		t.Fatalf("down migration error=%v, want signed-gap-history refusal", err)
	}
	var version int64
	if err := db.QueryRowContext(ctx, `SELECT version_id FROM goose_db_version WHERE is_applied ORDER BY id DESC LIMIT 1`).Scan(&version); err != nil && err != sql.ErrNoRows {
		t.Fatalf("read migration version after refused down: %v", err)
	}
	if version != 124 {
		t.Fatalf("migration version after refused down=%d, want 124", version)
	}
}
