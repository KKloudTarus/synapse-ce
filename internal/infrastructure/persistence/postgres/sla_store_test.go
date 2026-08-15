package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
)

// TestPostgresSLAStore exercises the real migration, JSON codecs, nullable provenance, RLS-scoped
// adapter calls, immutable history, and the no-human-clobber refresh invariant. It deliberately uses
// an assessment without source/previous IDs first so nullable column scanning is covered.
func TestPostgresSLAStore(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	base := context.Background()
	if err := Migrate(base, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(base, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	prefix := "sla-" + randHex(t)
	tenantID := shared.ID(prefix + "-tenant")
	engagementID := shared.ID(prefix + "-engagement")
	findingID := shared.ID(prefix + "-finding")
	if _, err := pool.Exec(base, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenantID.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := pool.Exec(base, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,$1)`, engagementID.String(), tenantID.String()); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
	if _, err := pool.Exec(base, `INSERT INTO findings(id,tenant_id,engagement_id,title,dedup_key) VALUES($1,$2,$3,'SLA integration finding',$1)`, findingID.String(), tenantID.String(), engagementID.String()); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(base, `ALTER TABLE sla_lifecycle_events DISABLE TRIGGER sla_lifecycle_events_append_only`)
		_, _ = pool.Exec(base, `ALTER TABLE sla_assessments DISABLE TRIGGER sla_assessments_append_only`)
		_, _ = pool.Exec(base, `ALTER TABLE sla_policies DISABLE TRIGGER sla_policies_append_only`)
		_, _ = pool.Exec(base, `DELETE FROM sla_lifecycle_events WHERE tenant_id=$1`, tenantID.String())
		_, _ = pool.Exec(base, `DELETE FROM sla_lifecycles WHERE tenant_id=$1`, tenantID.String())
		_, _ = pool.Exec(base, `DELETE FROM sla_current_assessments WHERE tenant_id=$1`, tenantID.String())
		_, _ = pool.Exec(base, `UPDATE sla_assessments SET previous_assessment_id=NULL WHERE tenant_id=$1`, tenantID.String())
		_, _ = pool.Exec(base, `DELETE FROM sla_assessments WHERE tenant_id=$1`, tenantID.String())
		_, _ = pool.Exec(base, `DELETE FROM sla_active_policies WHERE tenant_id=$1`, tenantID.String())
		_, _ = pool.Exec(base, `DELETE FROM sla_policies WHERE tenant_id=$1`, tenantID.String())
		_, _ = pool.Exec(base, `DELETE FROM findings WHERE tenant_id=$1`, tenantID.String())
		_, _ = pool.Exec(base, `DELETE FROM engagements WHERE tenant_id=$1`, tenantID.String())
		_, _ = pool.Exec(base, `DELETE FROM tenants WHERE id=$1`, tenantID.String())
		_, _ = pool.Exec(base, `ALTER TABLE sla_policies ENABLE TRIGGER sla_policies_append_only`)
		_, _ = pool.Exec(base, `ALTER TABLE sla_assessments ENABLE TRIGGER sla_assessments_append_only`)
		_, _ = pool.Exec(base, `ALTER TABLE sla_lifecycle_events ENABLE TRIGGER sla_lifecycle_events_append_only`)
	})

	ctx := shared.WithTenant(base, tenantID)
	store := NewSLAStore(pool)
	now := time.Date(2026, 8, 15, 13, 0, 0, 0, time.UTC)
	policy, err := sla.NewPolicy(tenantID, sla.DefaultConfig(), "integration-admin", now)
	if err != nil {
		t.Fatal(err)
	}
	if created, err := store.PutPolicy(ctx, policy, true); err != nil || !created {
		t.Fatalf("put policy created=%v err=%v", created, err)
	}
	active, err := store.ActivePolicy(ctx, tenantID)
	if err != nil || active.SHA256 != policy.SHA256 || active.Config.DueRanges.High != policy.Config.DueRanges.High {
		t.Fatalf("active policy=%+v err=%v", active, err)
	}

	first, err := sla.Evaluate(sla.AssessmentInput{
		TenantID: tenantID, EngagementID: engagementID, FindingID: findingID,
		Risk: sla.Inputs{Severity: shared.SeverityHigh, CVSSScore: 8.1, EPSS: 0.2, Feasibility: sla.FeasibilityPatchAvailable},
	}, policy.Config, now)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.UpsertAssessment(ctx, first)
	if err != nil || !stored.Created || !stored.Assessment.PreviousAssessmentID.IsZero() {
		t.Fatalf("first assessment=%+v err=%v", stored, err)
	}
	current, err := store.Current(ctx, tenantID, engagementID, findingID)
	if err != nil || current.Assessment.ID != first.ID || current.Lifecycle.Version != 1 {
		t.Fatalf("current=%+v err=%v", current, err)
	}

	expiry := now.Add(14 * 24 * time.Hour)
	next, event, err := sla.ApplyTransition(current.Lifecycle, shared.ID(prefix+"-event"), sla.TransitionCommand{
		To: sla.RemediationAcceptedRisk, Actor: "risk-owner", Reason: "vendor maintenance window",
		CompensatingControl: "network isolation", AcceptanceExpiresAt: &expiry, ExpectedVersion: 1,
	}, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTransition(ctx, next, event); err != nil {
		t.Fatal(err)
	}

	refreshed, err := sla.Evaluate(sla.AssessmentInput{
		TenantID: tenantID, EngagementID: engagementID, FindingID: findingID,
		Risk: sla.Inputs{Severity: shared.SeverityCritical, CVSSScore: 9.8, EPSS: 0.95, ActiveExploitation: true, Feasibility: sla.FeasibilityPatchAvailable},
	}, policy.Config, now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	stored, err = store.UpsertAssessment(ctx, refreshed)
	if err != nil || !stored.Created || stored.Assessment.PreviousAssessmentID != first.ID {
		t.Fatalf("refreshed assessment=%+v err=%v", stored, err)
	}
	if !stored.Assessment.DeadlineAnchorAt.Equal(first.AssessedAt) ||
		stored.Assessment.Result.RemediateBy.After(first.Result.RemediateBy) {
		t.Fatalf("refreshed assessment reset or extended SLA clock: first=%+v refreshed=%+v", first, stored.Assessment)
	}
	current, err = store.Current(ctx, tenantID, engagementID, findingID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Lifecycle.AssessmentID != refreshed.ID || current.Lifecycle.Status != sla.RemediationAcceptedRisk ||
		current.Lifecycle.Version != 2 || current.Lifecycle.AcceptedBy != "risk-owner" ||
		current.Lifecycle.AcceptanceExpiresAt == nil || !current.Lifecycle.AcceptanceExpiresAt.Equal(expiry) {
		t.Fatalf("machine refresh clobbered human lifecycle: %+v", current.Lifecycle)
	}
	history, err := store.AssessmentHistory(ctx, tenantID, engagementID, findingID)
	if err != nil || len(history) != 2 || history[0].ID != refreshed.ID || history[1].ID != first.ID {
		t.Fatalf("history=%+v err=%v", history, err)
	}
	events, err := store.LifecycleEvents(ctx, tenantID, engagementID, findingID)
	if err != nil || len(events) != 1 || events[0].ID != event.ID {
		t.Fatalf("events=%+v err=%v", events, err)
	}

	if err := store.SaveTransition(ctx, next, event); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale transition should conflict, got %v", err)
	}
	immutableMutations := []struct {
		name  string
		query string
		args  []any
	}{
		{name: "policy update", query: `UPDATE sla_policies SET created_by='tampered' WHERE tenant_id=$1`, args: []any{tenantID.String()}},
		{name: "assessment update", query: `UPDATE sla_assessments SET score=0 WHERE tenant_id=$1`, args: []any{tenantID.String()}},
		{name: "event delete", query: `DELETE FROM sla_lifecycle_events WHERE tenant_id=$1`, args: []any{tenantID.String()}},
	}
	for _, mutation := range immutableMutations {
		if _, err := pool.Exec(base, mutation.query, mutation.args...); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s must be rejected by append-only trigger, got %v", mutation.name, err)
		}
	}
	otherCtx := shared.WithTenant(base, "other-tenant")
	if _, err := store.Current(otherCtx, tenantID, engagementID, findingID); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cross-tenant read should fail closed, got %v", err)
	}
}

func TestSLAFindingAdvisoryLockKeyIsStableAndScoped(t *testing.T) {
	first := slaFindingAdvisoryLockKey("tenant-a", "eng-1", "finding-1")
	if first != slaFindingAdvisoryLockKey("tenant-a", "eng-1", "finding-1") {
		t.Fatal("same SLA finding identity produced an unstable advisory lock key")
	}
	if first == slaFindingAdvisoryLockKey("tenant-a", "eng-1", "finding-2") ||
		first == slaFindingAdvisoryLockKey("tenant-b", "eng-1", "finding-1") {
		t.Fatal("distinct SLA finding identities produced the same test lock key")
	}
}

func TestPostgresUniqueViolationClassification(t *testing.T) {
	if !postgresUniqueViolation(&pgconn.PgError{Code: "23505"}) {
		t.Fatal("unique_violation must be classified as a conflict")
	}
	if postgresUniqueViolation(&pgconn.PgError{Code: "23503"}) || postgresUniqueViolation(errors.New("23505")) {
		t.Fatal("non-unique PostgreSQL and untyped errors must not be classified as unique violations")
	}
}
