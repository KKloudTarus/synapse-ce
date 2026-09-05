package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestFleetAgentRepository(t *testing.T) {
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
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ('ft','FT') ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM fleet_enrol_tokens WHERE tenant_id='ft'`)
		_, _ = pool.Exec(bg, `DELETE FROM fleet_agents WHERE tenant_id='ft'`)
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id='ft'`)
	})

	repo := NewFleetAgentRepository(pool)
	now := time.Now().UTC().Truncate(time.Second)

	// FORCE RLS on both tables.
	for _, tbl := range []string{"fleet_agents", "fleet_enrol_tokens"} {
		var forced bool
		if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname=$1`, tbl).Scan(&forced); err != nil {
			t.Fatalf("relforce %s: %v", tbl, err)
		}
		if !forced {
			t.Fatalf("FORCE RLS not set on %s", tbl)
		}
	}

	// Enrol token: create, then single-use consume.
	tok, err := fleetagent.NewEnrolToken("hash-1", "ft", "op", now.Add(time.Hour), now)
	if err != nil {
		t.Fatalf("new token: %v", err)
	}
	if err := repo.CreateEnrolToken(ctx, tok); err != nil {
		t.Fatalf("create token: %v", err)
	}
	if _, err := repo.ConsumeEnrolToken(ctx, "ft", "hash-1", now); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if _, err := repo.ConsumeEnrolToken(ctx, "ft", "hash-1", now); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("second consume must fail (single-use), got %v", err)
	}

	// Agent: create, get, heartbeat, revoke.
	agent, err := fleetagent.NewAgent("ag1", "ft", "agent-1", "linux", "5.15", "0.1.0", []string{"scan.host"}, "tokhash", now)
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	if err := repo.CreateAgent(ctx, agent); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	got, err := repo.GetAgent(ctx, "ft", "ag1")
	if err != nil || got.Name != "agent-1" || len(got.Capabilities) != 1 {
		t.Fatalf("get agent mismatch: %+v err=%v", got, err)
	}
	if err := repo.Heartbeat(ctx, "ft", "ag1", "linux", "5.16", "0.2.0", []string{"scan.host", "detect.rules"}, now.Add(time.Minute)); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	got, _ = repo.GetAgent(ctx, "ft", "ag1")
	if got.AgentVersion != "0.2.0" || len(got.Capabilities) != 2 {
		t.Fatalf("heartbeat did not update: %+v", got)
	}
	if err := repo.Revoke(ctx, "ft", "ag1", "op", "test", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, _ = repo.GetAgent(ctx, "ft", "ag1")
	if !got.Revoked() {
		t.Fatalf("agent should be revoked")
	}

	// Decommission (#412): a second, healthy agent cleanly decommissions and round-trips the terminal
	// state + timestamp; decommissioning the already-revoked ag1 is a silent no-op that does not
	// downgrade the revocation.
	ag2, err := fleetagent.NewAgent("ag2", "ft", "agent-2", "linux", "5.15", "0.1.0", []string{"scan.host"}, "tokhash2", now)
	if err != nil {
		t.Fatalf("new agent 2: %v", err)
	}
	if err := repo.CreateAgent(ctx, ag2); err != nil {
		t.Fatalf("create agent 2: %v", err)
	}
	if err := repo.Decommission(ctx, "ft", "ag2", now.Add(3*time.Minute)); err != nil {
		t.Fatalf("decommission ag2: %v", err)
	}
	got, _ = repo.GetAgent(ctx, "ft", "ag2")
	if !got.Decommissioned() || got.DecommissionedAt == nil {
		t.Fatalf("ag2 should be decommissioned with a timestamp: %+v", got)
	}
	if err := repo.Decommission(ctx, "ft", "ag1", now.Add(4*time.Minute)); err != nil {
		t.Fatalf("decommission of a revoked agent must be a silent no-op, got %v", err)
	}
	got, _ = repo.GetAgent(ctx, "ft", "ag1")
	if !got.Revoked() || got.Decommissioned() {
		t.Fatalf("revoked ag1 must stay revoked after a decommission no-op: %s", got.State)
	}
	if err := repo.Decommission(ctx, "ft", "missing", now); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("decommission of a missing agent must be ErrNotFound, got %v", err)
	}

	if _, err := repo.GetAgent(ctx, "ft", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing agent, got %v", err)
	}
}

// TestMigration0060 exercises the migration down and back up.
func TestMigration0060(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db := openLockedGooseDB(t, dsn)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("dialect: %v", err)
	}
	if err := goose.DownTo(db, ".", 59); err != nil {
		t.Fatalf("down to 59: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	_, err = pool.Exec(ctx, `SELECT 1 FROM fleet_agents LIMIT 1`)
	var pgErr *pgconn.PgError
	if err == nil || !errors.As(err, &pgErr) || pgErr.Code != "42P01" {
		t.Fatalf("fleet_agents should be undefined after down to 59, got %v", err)
	}
	if err := goose.UpTo(db, ".", 60); err != nil {
		t.Fatalf("up to 60: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT 1 FROM fleet_agents LIMIT 1`); err != nil {
		t.Fatalf("fleet_agents should exist after up to 60: %v", err)
	}
}
