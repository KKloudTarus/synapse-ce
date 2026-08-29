package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
		for _, table := range []string{"telemetry_agent_gap_revisions", "telemetry_agent_gaps", "telemetry_transport_gaps", "telemetry_stream_positions", "telemetry_asset_bindings"} {
			_, _ = pool.Exec(bg, `DELETE FROM `+table+` WHERE tenant_id IN ($1,$2)`, tenant.String(), otherTenant.String())
		}
		_, _ = pool.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM fleet_agents WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ($1,$2)`, tenant.String(), otherTenant.String())
	})

	repo := mustNewTelemetryTransportRepository(t, pool)
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

	restarted := mustNewTelemetryTransportRepository(t, pool)
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

func TestTelemetryAgentGapSignedRevisionsSurviveRestart(t *testing.T) {
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
	tenant := shared.ID("agent-gap-revision-" + suffix)
	agent := shared.ID("agent-revision-" + suffix)
	asset := shared.ID("asset-revision-" + suffix)
	session := fleetagent.CanonicalSessionID(agent)
	stream, err := fleetagent.TelemetryDeliveryStreamID(agent, session, fleetagent.PriorityP3)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_agents(id,tenant_id,name,token_hash,state) VALUES($1,$2,$3,$4,'active')`,
		agent.String(), tenant.String(), "agent-gap-revision-test", "hash-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_assets(id,tenant_id,kind,"key",name,attributes,created_at,updated_at)
		VALUES($1,$2,'host',$3,$4,jsonb_build_object('reporting_agent_id',$5::text),$6,$6)`,
		asset.String(), tenant.String(), "machine/"+suffix, "host-"+suffix, agent.String(), now); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `SET session_replication_role = replica`)
		for _, table := range []string{"telemetry_agent_gap_revisions", "telemetry_agent_gaps", "telemetry_asset_bindings"} {
			_, _ = pool.Exec(bg, `DELETE FROM `+table+` WHERE tenant_id=$1`, tenant.String())
		}
		_, _ = pool.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM fleet_agents WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `SET session_replication_role = origin`)
	})

	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	makeRevision := func(report fleetagent.TelemetryGapReport, receivedAt time.Time) ports.TelemetryAgentGapRevision {
		t.Helper()
		digest := sha256.Sum256(fleetagent.TelemetryGapMessage(report))
		return ports.TelemetryAgentGapRevision{
			ProtocolVersion: report.ProtocolVersion, GapID: report.GapID,
			AuthenticatedAgentID: agent, AgentID: report.AgentID, HostID: report.HostID,
			AgentSessionID: report.AgentSessionID, AssetID: report.AssetID, StreamID: report.StreamID,
			Priority: report.Priority, Epoch: report.Epoch, KnownSequence: report.KnownSequence,
			FromSequence: report.FromSequence, ToSequence: report.ToSequence, Count: report.Count,
			Reason: report.Reason, FromAt: report.FromAt, ToAt: report.ToAt,
			KeyID: report.KeyID, Signature: report.Signature,
			SignedContentDigest: hex.EncodeToString(digest[:]), ReceivedAt: receivedAt,
		}
	}
	tenantCtx := shared.WithTenant(ctx, tenant)
	repo := mustNewTelemetryTransportRepository(t, pool)
	first := fleetagent.TelemetryGapReport{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion, GapID: shared.ID("gap-revision-" + suffix),
		AgentID: agent, HostID: agent, AgentSessionID: session, AssetID: asset, StreamID: stream,
		Priority: fleetagent.PriorityP3, Epoch: 1, Count: 2, Reason: fleetagent.TelemetryGapQuotaEviction,
		FromAt: now.Add(-time.Minute).Add(123 * time.Nanosecond), ToAt: now.Add(456 * time.Nanosecond),
		KeyID: "gap-key-" + suffix,
	}
	first.Signature = fleetagent.SignTelemetryGap(privateKey, first)
	firstRevision := makeRevision(first, now)
	if err := repo.AcceptAgentGapRevision(tenantCtx, firstRevision); err != nil {
		t.Fatalf("accept first signed revision: %v", err)
	}
	if err := repo.AcceptAgentGapRevision(tenantCtx, makeRevision(first, now.Add(time.Hour))); err != nil {
		t.Fatalf("accept exact retry: %v", err)
	}

	extended := first
	extended.Count = 3
	extended.ToAt = first.ToAt.Add(time.Minute)
	extended.Signature = fleetagent.SignTelemetryGap(privateKey, extended)
	extendedRevision := makeRevision(extended, now.Add(time.Second))
	if err := repo.AcceptAgentGapRevision(tenantCtx, extendedRevision); err != nil {
		t.Fatalf("accept signed extension: %v", err)
	}

	incompatible := extended
	incompatible.Count = 1
	incompatible.ToAt = incompatible.FromAt
	incompatible.Signature = fleetagent.SignTelemetryGap(privateKey, incompatible)
	if err := repo.AcceptAgentGapRevision(tenantCtx, makeRevision(incompatible, now.Add(2*time.Second))); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("incompatible gap reuse error = %v, want conflict", err)
	}

	reconnected, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	t.Cleanup(reconnected.Close)
	restarted := mustNewTelemetryTransportRepository(t, reconnected)
	revisions, err := restarted.AgentGapRevisions(tenantCtx, first.GapID)
	if err != nil || len(revisions) != 2 {
		t.Fatalf("signed revisions after restart = %+v, %v; want two", revisions, err)
	}
	if revisions[0].Revision != 1 || revisions[1].Revision != 2 ||
		revisions[0].SignedContentDigest != firstRevision.SignedContentDigest ||
		revisions[1].SignedContentDigest != extendedRevision.SignedContentDigest ||
		revisions[0].AuthenticatedAgentID != agent || revisions[1].AuthenticatedAgentID != agent ||
		revisions[0].Signature != first.Signature || revisions[1].Signature != extended.Signature ||
		!revisions[0].FromAt.Equal(first.FromAt) || !revisions[1].ToAt.Equal(extended.ToAt) {
		t.Fatalf("signed revision history changed across restart: %+v", revisions)
	}
}
