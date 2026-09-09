package response

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	pgstore "github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/incidentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

func TestIncidentCoordinatorPreparesPostgresActionBeforeRequestProjection(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := pgstore.MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := pgstore.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	suffix := time.Now().UTC().Format("20060102150405.000000000")
	tenantID := shared.ID("incident-order-tenant-" + suffix)
	engagementID := shared.ID("incident-order-engagement-" + suffix)
	incidentID := shared.ID("incident-order-incident-" + suffix)
	actionID := shared.ID("incident-order-action-" + suffix)
	unpreparedID := shared.ID("incident-order-unprepared-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,$1)`, engagementID, tenantID); err != nil {
		t.Fatal(err)
	}
	cleanupIncidentCoordinatorPostgres(t, pool, tenantID)

	tenantCtx := shared.WithTenant(ctx, tenantID)
	clock := fixedClock{t: time.Unix(2_000_000, 0).UTC()}
	incidentRepo := pgstore.NewIncidentEventRepository(pool)
	incidentService, err := incidentuc.NewService(incidentRepo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := incidentService.Append(tenantCtx, incidentID, 0, []incident.IncidentEvent{{
		IncidentID:   incidentID,
		Kind:         incident.EventCreated,
		At:           clock.Now(),
		Actor:        "correlator",
		AssetID:      "host-1",
		EngagementID: "eng-1",
		Severity:     shared.SeverityHigh,
	}}); err != nil {
		t.Fatalf("seed incident: %v", err)
	}

	target := engagement.Target{Kind: engagement.TargetIP, Value: "host-1"}
	fingerprint := responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintHost, HostID: "host-1", NetpolGeneration: 1}
	unprepared := act(unpreparedID.String())
	if _, err := incidentService.Append(tenantCtx, incidentID, 1, []incident.IncidentEvent{{
		IncidentID:           incidentID,
		Kind:                 incident.EventResponseRequested,
		At:                   clock.Now(),
		Actor:                "alice",
		ResponseActionID:     unprepared.ID,
		ResponseEngagementID: engagementID,
		ResponseActionDigest: responseActionDigest(unprepared),
		ResponseTarget:       fingerprint,
	}}); err == nil {
		t.Fatal("response request projection accepted an action that was not prepared")
	}

	responseStore := pgstore.NewResponseRepository(pool)
	admitter := &fakeAdmitter{err: safety.ErrPendingApproval}
	executor := &fakeExec{}
	responseService, err := newService(admitter, executor, responseStore, &fakeAudit{}, clock)
	if err != nil {
		t.Fatal(err)
	}
	action := act(actionID.String())
	prepared, err := responseService.PrepareIncidentResponse(tenantCtx, engagementID, action, target, fingerprint, "alice")
	if err != nil {
		t.Fatalf("prepare response action: %v", err)
	}
	if prepared.State != StatePending || prepared.ApprovedBy != "" || !prepared.ApprovalEvidenceID.IsZero() || !prepared.AppliedAt.IsZero() {
		t.Fatalf("preparation advanced governed response state: %+v", prepared)
	}
	assertPreparedResponseHasNoSideEffectState(t, pool, tenantID, actionID)

	coordinator, err := NewIncidentCoordinator(responseService, incidentService, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Apply(tenantCtx, incidentID, action, target, fingerprint, "alice"); !errors.Is(err, safety.ErrPendingApproval) {
		t.Fatalf("unapproved incident response error=%v, want pending approval", err)
	}
	if executor.count() != 0 {
		t.Fatalf("incident response preparation executed %d side effects", executor.count())
	}
	current, err := incidentService.Get(tenantCtx, incidentID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != 2 || len(current.Responses) != 1 || current.Responses[0] != (incident.ResponseRef{
		ActionID: action.ID, EngagementID: engagementID, ActionDigest: responseActionDigest(action), Target: fingerprint,
	}) {
		t.Fatalf("prepared response request was not projected exactly once: %+v", current)
	}
	assertPreparedResponseHasNoSideEffectState(t, pool, tenantID, actionID)
}

func assertPreparedResponseHasNoSideEffectState(t *testing.T, pool *pgxpool.Pool, tenantID, actionID shared.ID) {
	t.Helper()
	var state, submittedBy, approvedBy string
	var approvalEvidenceID *string
	if err := pool.QueryRow(context.Background(), `SELECT state,submitted_by,approved_by,approval_evidence_id
		FROM response_actions WHERE tenant_id=$1 AND id=$2`, tenantID, actionID).
		Scan(&state, &submittedBy, &approvedBy, &approvalEvidenceID); err != nil {
		t.Fatalf("read prepared response action: %v", err)
	}
	if state != string(rdom.StatePending) || submittedBy != "alice" || approvedBy != "" || approvalEvidenceID != nil {
		t.Fatalf("prepared response action contains approval or execution state: state=%q submitter=%q approver=%q evidence=%v", state, submittedBy, approvedBy, approvalEvidenceID)
	}
	for name, query := range map[string]string{
		"execution attempt": `SELECT count(*) FROM response_attempts WHERE tenant_id=$1 AND action_id=$2`,
		"audit intent":      `SELECT count(*) FROM response_audit_intents WHERE tenant_id=$1 AND target=$2`,
	} {
		var count int
		if err := pool.QueryRow(context.Background(), query, tenantID, actionID).Scan(&count); err != nil {
			t.Fatalf("count prepared response %s: %v", name, err)
		}
		if count != 0 {
			t.Fatalf("preparation created %d %s rows", count, name)
		}
	}
}

func cleanupIncidentCoordinatorPostgres(t *testing.T, pool *pgxpool.Pool, tenantID shared.ID) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
		conn, err := pool.Acquire(ctx)
		if err != nil {
			t.Errorf("acquire incident ordering cleanup connection: %v", err)
			return
		}
		defer conn.Release()
		if _, err := conn.Exec(ctx, `SET session_replication_role = replica`); err != nil {
			t.Errorf("enable incident ordering cleanup: %v", err)
			return
		}
		defer func() {
			if _, err := conn.Exec(ctx, `SET session_replication_role = origin`); err != nil {
				t.Errorf("restore incident ordering cleanup: %v", err)
			}
		}()
		for _, table := range []string{
			"response_audit_intents", "response_attempts", "incident_response_links", "incident_events",
			"response_halt_dispatches", "response_halt_fences", "response_actions", "engagements",
		} {
			if _, err := conn.Exec(ctx, `DELETE FROM `+table+` WHERE tenant_id=$1`, tenantID); err != nil {
				t.Errorf("cleanup incident ordering table %s: %v", table, err)
			}
		}
		if _, err := conn.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID); err != nil {
			t.Errorf("cleanup incident ordering tenant: %v", err)
		}
	})
}
