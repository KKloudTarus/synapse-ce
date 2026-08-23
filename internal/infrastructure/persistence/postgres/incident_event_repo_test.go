package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestIncidentEventRepository(t *testing.T) {
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

	id := randHex(t)
	tenant := shared.ID("iel-" + id)
	other := shared.ID("iel-other-" + id)
	asset := shared.ID("iel-asset-" + id)
	incID := shared.ID("iel-inc-" + id)
	for _, tn := range []shared.ID{tenant, other} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tn.String()); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		conn, err := pool.Acquire(bg)
		if err != nil {
			return
		}
		defer conn.Release()
		if _, err := conn.Exec(bg, `SET session_replication_role = replica`); err != nil {
			return
		}
		defer conn.Exec(bg, `SET session_replication_role = origin`)
		for _, tn := range []shared.ID{tenant, other} {
			_, _ = conn.Exec(bg, `DELETE FROM incident_events WHERE tenant_id=$1`, tn.String())
			_, _ = conn.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tn.String())
		}
	})

	repo := NewIncidentEventRepository(pool)
	tctx := shared.WithTenant(ctx, tenant)
	base := time.Unix(1_800_000_000, 0).UTC()

	created := incident.IncidentEvent{IncidentID: incID, Kind: incident.EventCreated, At: base, Actor: "correlator", AssetID: asset, Severity: shared.SeverityHigh, DetectionID: "d1"}
	if err := repo.AppendEvents(tctx, incID, 0, []incident.IncidentEvent{created}); err != nil {
		t.Fatalf("append created: %v", err)
	}
	// Optimistic concurrency: a second append at revision 0 conflicts.
	if err := repo.AppendEvents(tctx, incID, 0, []incident.IncidentEvent{created}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("double append at rev 0 must conflict, got %v", err)
	}
	// Append a risk reassessment (exercises the nested *RiskAssessment JSONB payload round-trip) then a
	// comment, at the correct revisions.
	risk := incident.IncidentEvent{IncidentID: incID, Kind: incident.EventRiskReassessed, At: base.Add(time.Second), Actor: "scorer",
		Risk: &riskassessment.RiskAssessment{AssessmentID: "ra-1", ScorerVersion: "v1", PolicyVersion: "p1", Risk: 88, Confidence: 61, Coverage: 43}}
	if err := repo.AppendEvents(tctx, incID, 1, []incident.IncidentEvent{risk}); err != nil {
		t.Fatalf("append risk: %v", err)
	}
	commented := incident.IncidentEvent{IncidentID: incID, Kind: incident.EventAnalystCommented, At: base.Add(2 * time.Second), Actor: "alice", Comment: "looks real"}
	if err := repo.AppendEvents(tctx, incID, 2, []incident.IncidentEvent{commented}); err != nil {
		t.Fatalf("append comment: %v", err)
	}

	events, err := repo.LoadEvents(tctx, incID)
	if err != nil || len(events) != 3 {
		t.Fatalf("load: %d err=%v", len(events), err)
	}
	inc, err := incident.Project(events)
	if err != nil {
		t.Fatalf("loaded log must project: %v", err)
	}
	if inc.Severity != shared.SeverityHigh || len(inc.Comments) != 1 || inc.Comments[0].Text != "looks real" {
		t.Fatalf("round-trip projection wrong: %+v", inc)
	}
	if inc.Risk == nil || inc.Risk.Risk != 88 || inc.Risk.Coverage != 43 {
		t.Fatalf("risk payload did not round-trip through JSONB: %+v", inc.Risk)
	}

	// List by asset.
	ids, err := repo.ListIncidentIDs(tctx, ports.IncidentQuery{AssetID: asset})
	if err != nil || len(ids) != 1 || ids[0] != incID {
		t.Fatalf("list by asset: %v err=%v", ids, err)
	}

	// Cross-tenant isolation: the other tenant sees nothing.
	octx := shared.WithTenant(ctx, other)
	if ev, err := repo.LoadEvents(octx, incID); err != nil || len(ev) != 0 {
		t.Fatalf("cross-tenant load must be empty, got %d err=%v", len(ev), err)
	}

	// Append-only: a direct UPDATE/DELETE is refused by the trigger.
	if _, err := pool.Exec(ctx, `UPDATE incident_events SET actor='x' WHERE tenant_id=$1`, tenant.String()); err == nil {
		t.Fatal("UPDATE on the append-only incident log must be rejected")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM incident_events WHERE tenant_id=$1`, tenant.String()); err == nil {
		t.Fatal("DELETE on the append-only incident log must be rejected")
	}
}
