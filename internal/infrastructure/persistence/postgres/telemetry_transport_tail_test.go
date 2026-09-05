package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTelemetryTransportTailBindingAndDurableGaps(t *testing.T) {
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
	tenant := shared.ID("ttail-" + suffix)
	otherTenant := shared.ID("ttail-other-" + suffix)
	agent := shared.ID("agent-" + suffix)
	otherAgent := shared.ID("agent-other-" + suffix)
	asset := shared.ID("asset-" + suffix)
	stream := shared.ID("stream-" + suffix)
	now := time.Now().UTC().Truncate(time.Microsecond)

	for _, tenantID := range []shared.ID{tenant, otherTenant} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenantID.String()); err != nil {
			t.Fatalf("seed tenant %s: %v", tenantID, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_agents(id,tenant_id,name,token_hash,state) VALUES($1,$2,$3,$4,'active')`, agent.String(), tenant.String(), "telemetry-tail-agent", "hash-1"); err != nil {
		t.Fatalf("seed fleet agent: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_agents(id,tenant_id,name,token_hash,state) VALUES($1,$2,$3,$4,'active')`, otherAgent.String(), otherTenant.String(), "other-agent", "hash-2"); err != nil {
		t.Fatalf("seed other fleet agent: %v", err)
	}

	t.Cleanup(func() {
		bg := context.Background()
		for _, table := range []string{"telemetry_agent_gaps", "telemetry_transport_gaps", "telemetry_batch_events", "telemetry_batch_commits", "telemetry_stream_positions", "telemetry_asset_bindings"} {
			_, _ = pool.Exec(bg, `DELETE FROM `+table+` WHERE tenant_id IN ($1,$2)`, tenant.String(), otherTenant.String())
		}
		_, _ = pool.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id IN ($1,$2)`, tenant.String(), otherTenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM fleet_agents WHERE tenant_id IN ($1,$2)`, tenant.String(), otherTenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ($1,$2)`, tenant.String(), otherTenant.String())
	})

	if _, err := pool.Exec(ctx, `INSERT INTO fleet_assets(id,tenant_id,kind,"key",name,attributes,created_at,updated_at)
		VALUES($1,$2,'host',$3,$4,jsonb_build_object('reporting_agent_id',$5::text),$6,$6)`,
		asset.String(), tenant.String(), "machine/"+suffix, "host-"+suffix, agent.String(), now); err != nil {
		t.Fatalf("seed host asset and trigger telemetry binding: %v", err)
	}

	repo := mustNewTelemetryTransportRepository(t, pool)
	tenantCtx := shared.WithTenant(ctx, tenant)
	resolved, err := repo.ResolveTelemetryAsset(tenantCtx, agent)
	if err != nil || resolved != asset {
		t.Fatalf("server-authoritative asset binding = %q, %v; want %q", resolved, err, asset)
	}
	if _, err := repo.ResolveTelemetryAsset(shared.WithTenant(ctx, otherTenant), agent); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant asset binding must be invisible, got %v", err)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO telemetry_asset_bindings(tenant_id,agent_id,asset_id,updated_at) VALUES($1,$2,$3,$4)`,
		tenant.String(), otherAgent.String(), asset.String(), now); err == nil {
		t.Fatal("cross-tenant agent/tenant binding unexpectedly satisfied the composite FK")
	}

	beforeAt := now.Add(-10 * time.Minute)
	afterAt := now.Add(10 * time.Minute)
	before := ports.TelemetryEventBatch{
		BatchID: shared.ID("batch-before-" + suffix), PayloadDigest: "payload-before-" + suffix,
		AgentID: agent, StreamID: stream, AssetID: asset, Priority: fleetagent.PriorityP3, Epoch: 1, Sequence: 1, SchemaVersion: 2,
		EventTimeMin: beforeAt, EventTimeMax: beforeAt,
		ObservedCount: 1, KeptCount: 1, SamplingPolicyDigest: "test-policy-digest",
		Events: []ports.StoredTelemetryEvent{{
			EventID: shared.ID("event-before-" + suffix), Class: detection.ClassProcess, Digest: "digest-before-" + suffix, RedactionPolicyDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Payload: []byte("before"), ObservedAt: beforeAt,
		}},
	}
	after := ports.TelemetryEventBatch{
		BatchID: shared.ID("batch-after-" + suffix), PayloadDigest: "payload-after-" + suffix,
		AgentID: agent, StreamID: stream, AssetID: asset, Priority: fleetagent.PriorityP3, Epoch: 1, Sequence: 4, SchemaVersion: 2,
		EventTimeMin: afterAt, EventTimeMax: afterAt,
		ObservedCount: 1, KeptCount: 1, SamplingPolicyDigest: "test-policy-digest",
		Events: []ports.StoredTelemetryEvent{{
			EventID: shared.ID("event-after-" + suffix), Class: detection.ClassProcess, Digest: "digest-after-" + suffix, RedactionPolicyDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Payload: []byte("after"), ObservedAt: afterAt,
		}},
	}
	if err := repo.CommitBatch(tenantCtx, before); err != nil {
		t.Fatalf("commit predecessor batch: %v", err)
	}
	if err := repo.CommitBatch(tenantCtx, after); err != nil {
		t.Fatalf("commit successor batch: %v", err)
	}

	state := ports.TelemetryStreamState{
		AgentID: agent, StreamID: stream, Epoch: 1,
		Contiguous: 1, Pending: []uint64{4}, UpdatedAt: now,
	}
	if err := repo.SaveStreamState(tenantCtx, state); err != nil {
		t.Fatalf("save gapped stream state: %v", err)
	}
	gaps, err := repo.ListGaps(tenantCtx, agent, stream)
	if err != nil || len(gaps) != 1 || gaps[0].FromSequence != 2 || gaps[0].ToSequence != 3 {
		t.Fatalf("persisted gap = %+v, %v; want [2,3]", gaps, err)
	}
	if gaps[0].AssetID != asset || gaps[0].Priority != fleetagent.PriorityP3 || !gaps[0].FromAt.Equal(beforeAt) || !gaps[0].ToAt.Equal(afterAt) {
		t.Fatalf("gap coverage metadata = %+v; want asset=%s priority=P3 span=%s..%s", gaps[0], asset, beforeAt, afterAt)
	}

	priority := fleetagent.PriorityP3
	inside := ports.TelemetryGapQuery{
		AgentID: agent, AssetID: asset, Priority: &priority,
		Since: now.Add(-time.Minute), Until: now.Add(time.Minute),
	}
	coverage, err := repo.QueryDeliveryGaps(tenantCtx, inside)
	if err != nil || len(coverage) != 1 || coverage[0].FromSequence != 2 || coverage[0].ToSequence != 3 {
		t.Fatalf("delivery-gap overlap query = %+v, %v; want persisted [2,3]", coverage, err)
	}

	restarted := mustNewTelemetryTransportRepository(t, pool)
	gaps, err = restarted.ListGaps(tenantCtx, agent, stream)
	if err != nil || len(gaps) != 1 || gaps[0].FromSequence != 2 || gaps[0].ToSequence != 3 {
		t.Fatalf("gap after repository restart = %+v, %v; want [2,3]", gaps, err)
	}
	coverage, err = restarted.QueryDeliveryGaps(tenantCtx, inside)
	if err != nil || len(coverage) != 1 {
		t.Fatalf("coverage gap after repository restart = %+v, %v; want one", coverage, err)
	}
	otherCtx := shared.WithTenant(ctx, otherTenant)
	if gaps, err := restarted.ListGaps(otherCtx, agent, stream); err != nil || len(gaps) != 0 {
		t.Fatalf("cross-tenant gap visibility = %+v, %v; want none", gaps, err)
	}
	if gaps, err := restarted.QueryDeliveryGaps(otherCtx, inside); err != nil || len(gaps) != 0 {
		t.Fatalf("cross-tenant delivery-gap visibility = %+v, %v; want none", gaps, err)
	}

	current, err := restarted.StreamState(tenantCtx, agent, stream, 1)
	if err != nil {
		t.Fatal(err)
	}
	current.Contiguous = 4
	current.Pending = nil
	current.UpdatedAt = now.Add(time.Second)
	if err := restarted.SaveStreamState(tenantCtx, current); err != nil {
		t.Fatalf("fill telemetry gap: %v", err)
	}
	if gaps, err := restarted.ListGaps(tenantCtx, agent, stream); err != nil || len(gaps) != 0 {
		t.Fatalf("filled gap still open: %+v, %v", gaps, err)
	}
	if gaps, err := restarted.QueryDeliveryGaps(tenantCtx, inside); err != nil || len(gaps) != 0 {
		t.Fatalf("resolved gap still affects hunt coverage: %+v, %v", gaps, err)
	}

	// Agent-origin spool loss is durable provenance, not an inferred delivery hole.
	// Persist it idempotently, query it through the same coverage reader used by hunts,
	// then advance the ACK ledger again and prove that reconciliation does not erase it.
	agentGap := ports.TelemetryAgentGap{
		GapID: shared.ID("agent-gap-" + suffix), AgentID: agent, AssetID: asset, StreamID: stream,
		Priority: fleetagent.PriorityP3, Epoch: 1, Count: 2, Reason: fleetagent.TelemetryGapQuotaEviction,
		FromAt: now.Add(-30 * time.Second), ToAt: now.Add(30 * time.Second),
		FirstReportedAt: now.Add(2 * time.Second), UpdatedAt: now.Add(2 * time.Second),
	}
	if err := restarted.RecordAgentGap(tenantCtx, agentGap); err != nil {
		t.Fatalf("record agent-origin gap: %v", err)
	}
	if err := restarted.RecordAgentGap(tenantCtx, agentGap); err != nil {
		t.Fatalf("idempotent agent-origin gap retry: %v", err)
	}
	combined := ports.CombinedTelemetryGapReader{Delivery: restarted, Agent: restarted}
	coverage, err = combined.QueryDeliveryGaps(tenantCtx, inside)
	if err != nil || len(coverage) != 1 || coverage[0].FromSequence != 0 || coverage[0].ToSequence != 0 {
		t.Fatalf("combined agent-origin coverage = %+v, %v; want one unknown-coordinate gap", coverage, err)
	}

	latest, err := restarted.StreamState(tenantCtx, agent, stream, 1)
	if err != nil {
		t.Fatal(err)
	}
	latest.UpdatedAt = now.Add(3 * time.Second)
	if err := restarted.SaveStreamState(tenantCtx, latest); err != nil {
		t.Fatalf("resave ACK state after agent gap: %v", err)
	}
	restartedAgain := mustNewTelemetryTransportRepository(t, pool)
	agentCoverage, err := restartedAgain.QueryAgentGaps(tenantCtx, inside)
	if err != nil || len(agentCoverage) != 1 || agentCoverage[0].FromSequence != 0 || agentCoverage[0].ToSequence != 0 {
		t.Fatalf("agent-origin gap after ACK reconciliation/restart = %+v, %v; want one", agentCoverage, err)
	}
	if crossTenant, err := restartedAgain.QueryAgentGaps(otherCtx, inside); err != nil || len(crossTenant) != 0 {
		t.Fatalf("cross-tenant agent-origin gap visibility = %+v, %v; want none", crossTenant, err)
	}

	var resolvedHistory int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM telemetry_transport_gaps
		WHERE tenant_id=$1 AND agent_id=$2 AND stream_id=$3 AND epoch=1 AND from_sequence=2 AND to_sequence=3 AND resolved_at IS NOT NULL`,
		tenant.String(), agent.String(), stream.String()).Scan(&resolvedHistory); err != nil {
		t.Fatalf("query resolved gap history: %v", err)
	}
	if resolvedHistory != 1 {
		t.Fatalf("resolved gap provenance rows = %d, want 1", resolvedHistory)
	}
}
