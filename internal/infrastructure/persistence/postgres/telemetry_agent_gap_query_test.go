package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTelemetryAgentGapQueryableAcrossRestartAndNotResolvedByACKFill(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	suffix := uuid.NewString()
	tenant := shared.ID("agent-gap-" + suffix)
	otherTenant := shared.ID("agent-gap-other-" + suffix)
	agent := shared.ID("agent-" + suffix)
	asset := shared.ID("asset-" + suffix)
	stream := shared.ID("stream-" + suffix)
	now := time.Now().UTC().Truncate(time.Microsecond)

	for _, id := range []shared.ID{tenant, otherTenant} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, id.String()); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_agents(id,tenant_id,name,token_hash,state) VALUES($1,$2,$3,$4,'active')`,
		agent.String(), tenant.String(), "agent-gap-test", "hash-"+suffix); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_assets(id,tenant_id,kind,"key",name,attributes,created_at,updated_at)
		VALUES($1,$2,'host',$3,$4,jsonb_build_object('reporting_agent_id',$5::text),$6,$6)`,
		asset.String(), tenant.String(), "machine/"+suffix, "host-"+suffix, agent.String(), now); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, table := range []string{"telemetry_agent_gaps", "telemetry_transport_gaps", "telemetry_stream_positions", "telemetry_asset_bindings"} {
			_, _ = pool.Exec(bg, `DELETE FROM `+table+` WHERE tenant_id IN ($1,$2)`, tenant.String(), otherTenant.String())
		}
		_, _ = pool.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM fleet_agents WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ($1,$2)`, tenant.String(), otherTenant.String())
	})

	repo := NewTelemetryTransportRepository(pool)
	tenantCtx := shared.WithTenant(ctx, tenant)
	gap := ports.TelemetryAgentGap{
		GapID: shared.ID("gap-" + suffix), AgentID: agent, AssetID: asset, StreamID: stream,
		Priority: fleetagent.PriorityP3, Epoch: 1, Count: 3, Reason: fleetagent.TelemetryGapQuotaEviction,
		FromAt: now.Add(-5 * time.Minute), ToAt: now.Add(5 * time.Minute),
		FirstReportedAt: now, UpdatedAt: now,
	}
	if err := repo.RecordAgentGap(tenantCtx, gap); err != nil {
		t.Fatalf("record agent gap: %v", err)
	}
	if err := repo.RecordAgentGap(tenantCtx, gap); err != nil {
		t.Fatalf("retry agent gap: %v", err)
	}

	priority := fleetagent.PriorityP3
	q := ports.TelemetryGapQuery{AgentID: agent, AssetID: asset, Priority: &priority, Since: now.Add(-time.Minute), Until: now.Add(time.Minute)}
	got, err := repo.QueryAgentGaps(tenantCtx, q)
	if err != nil || len(got) != 1 {
		t.Fatalf("agent gap query = %+v, %v; want one", got, err)
	}
	if got[0].FromSequence != 0 || got[0].ToSequence != 0 || !got[0].FromAt.Equal(gap.FromAt) || !got[0].ToAt.Equal(gap.ToAt) {
		t.Fatalf("agent gap coverage = %+v", got[0])
	}

	coverage, err := repo.QueryDeliveryGaps(tenantCtx, q)
	if err != nil || len(coverage) != 1 {
		t.Fatalf("delivery coverage = %+v, %v; want one agent-origin gap", coverage, err)
	}
	if coverage[0].FromSequence != 0 || coverage[0].ToSequence != 0 || !coverage[0].FromAt.Equal(gap.FromAt) || !coverage[0].ToAt.Equal(gap.ToAt) {
		t.Fatalf("delivery coverage did not preserve agent-origin loss = %+v", coverage[0])
	}

	restarted := NewTelemetryTransportRepository(pool)
	got, err = restarted.QueryAgentGaps(tenantCtx, q)
	if err != nil || len(got) != 1 {
		t.Fatalf("agent gap after repository restart = %+v, %v; want one", got, err)
	}

	if err := restarted.SaveStreamState(tenantCtx, ports.TelemetryStreamState{
		AgentID: agent, StreamID: stream, Epoch: 1, Contiguous: 10, UpdatedAt: now.Add(time.Second),
	}); err != nil {
		t.Fatalf("advance delivery ACK state: %v", err)
	}
	got, err = restarted.QueryAgentGaps(tenantCtx, q)
	if err != nil || len(got) != 1 {
		t.Fatalf("agent gap disappeared after ACK fill: %+v, %v", got, err)
	}

	other := shared.WithTenant(ctx, otherTenant)
	got, err = restarted.QueryAgentGaps(other, q)
	if err != nil || len(got) != 0 {
		t.Fatalf("cross-tenant agent gap visibility = %+v, %v; want none", got, err)
	}
}
