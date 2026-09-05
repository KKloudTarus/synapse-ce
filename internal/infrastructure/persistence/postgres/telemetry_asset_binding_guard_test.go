package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestTelemetryAssetBindingTriggerRejectsCrossAgentTakeover(t *testing.T) {
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

	suffix := uuid.NewString()
	tenant := "binding-tenant-" + suffix
	agentA := "binding-agent-a-" + suffix
	agentB := "binding-agent-b-" + suffix
	assetID := "binding-asset-" + suffix
	now := time.Now().UTC().Truncate(time.Microsecond)

	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	for i, agentID := range []string{agentA, agentB} {
		if _, err := pool.Exec(ctx, `INSERT INTO fleet_agents(id,tenant_id,name,token_hash,state) VALUES($1,$2,$1,$3,'active')`, agentID, tenant, "binding-token-"+suffix+string(rune('a'+i))); err != nil {
			t.Fatalf("seed fleet agent %s: %v", agentID, err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_asset_bindings WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(bg, `DELETE FROM fleet_agents WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tenant)
	})

	if _, err := pool.Exec(ctx, `INSERT INTO fleet_assets(id,tenant_id,kind,"key",name,attributes,created_at,updated_at)
		VALUES($1,$2,'host',$3,$3,jsonb_build_object('reporting_agent_id',$4::text),$5,$5)`,
		assetID, tenant, "machine-id/"+suffix, agentA, now); err != nil {
		t.Fatalf("seed host asset: %v", err)
	}

	_, updateErr := pool.Exec(ctx, `UPDATE fleet_assets
		SET attributes=jsonb_build_object('reporting_agent_id',$3::text), updated_at=$4
		WHERE tenant_id=$1 AND id=$2`, tenant, assetID, agentB, now.Add(time.Second))
	if updateErr == nil {
		t.Fatal("cross-agent host update unexpectedly displaced telemetry asset binding")
	}
	var pgErr *pgconn.PgError
	if !errors.As(updateErr, &pgErr) {
		t.Fatalf("cross-agent host update error = %T %v, want PgError", updateErr, updateErr)
	}
	if pgErr.Code != "23505" || pgErr.ConstraintName != "uq_telemetry_asset_bindings_asset" {
		t.Fatalf("cross-agent host update SQLSTATE/constraint = %s/%s, want 23505/uq_telemetry_asset_bindings_asset", pgErr.Code, pgErr.ConstraintName)
	}
	if err := normalizePersistenceError(updateErr); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("normalized cross-agent host update error = %v, want ErrConflict", err)
	}

	var boundAgent string
	if err := pool.QueryRow(ctx, `SELECT agent_id FROM telemetry_asset_bindings WHERE tenant_id=$1 AND asset_id=$2`, tenant, assetID).Scan(&boundAgent); err != nil {
		t.Fatalf("read surviving telemetry binding: %v", err)
	}
	if boundAgent != agentA {
		t.Fatalf("asset rebound to %q, want original %q", boundAgent, agentA)
	}

	var reportingAgent string
	if err := pool.QueryRow(ctx, `SELECT attributes->>'reporting_agent_id' FROM fleet_assets WHERE tenant_id=$1 AND id=$2`, tenant, assetID).Scan(&reportingAgent); err != nil {
		t.Fatalf("read surviving host attribution: %v", err)
	}
	if reportingAgent != agentA {
		t.Fatalf("failed takeover mutated host attribution to %q, want %q", reportingAgent, agentA)
	}
}
