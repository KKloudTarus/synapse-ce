package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
	"github.com/jackc/pgx/v5"
)

func TestLifecycleRelevancePostgresCancellationAndTenantIsolation(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("relevance-current")
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,'Current'),('relevance-other','Other')`, tenant); err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT date_trunc('microseconds',now())`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	accepted, expiry := now.Add(-9*24*time.Hour), now.Add(time.Hour)
	seedLifecycleAcceptance(t, pool, ctx, tenant.String(), "relevance", accepted, expiry)
	repo := NewNotificationRepository(pool)
	deadline := accepted.Add(7 * 24 * time.Hour)
	checkRisk := func(version int, at time.Time, expiring, want bool) {
		t.Helper()
		got, err := repo.RiskAcceptanceCurrent(ctx, tenant, "eng-relevance", "finding-relevance", version, at, expiring)
		if err != nil || got != want {
			t.Fatalf("risk current(version=%d,expiring=%v)=%v,%v want %v", version, expiring, got, err, want)
		}
	}
	checkBreach := func(version int, want bool) {
		t.Helper()
		got, err := repo.SLABreachCurrent(ctx, tenant, "eng-relevance", "finding-relevance", deadline, version)
		if err != nil || got != want {
			t.Fatalf("breach current=%v,%v want %v", got, err, want)
		}
	}
	checkRisk(2, expiry, true, true)
	checkRisk(1, expiry, true, false)
	checkRisk(2, expiry.Add(time.Microsecond), true, false)
	checkRisk(2, expiry, false, false)
	checkBreach(1, false) // A live acceptance suppresses an overdue remediation page.
	other := shared.WithTenant(context.Background(), "relevance-other")
	if got, err := repo.RiskAcceptanceCurrent(other, "relevance-other", "eng-relevance", "finding-relevance", 2, expiry, true); err != nil || got {
		t.Fatalf("foreign risk current=%v,%v", got, err)
	}
	if got, err := repo.SLABreachCurrent(other, "relevance-other", "eng-relevance", "finding-relevance", deadline, 1); err != nil || got {
		t.Fatalf("foreign breach current=%v,%v", got, err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE sla_lifecycles SET acceptance_expires_at=now() WHERE tenant_id=$1 RETURNING acceptance_expires_at`, tenant).Scan(&expiry)
	}); err != nil {
		t.Fatal(err)
	}
	checkRisk(2, expiry, true, false)
	checkRisk(2, expiry, false, true)
	checkBreach(1, false)
	checkBreach(2, true)
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sla_lifecycles SET status='remediated',version=3,accepted_by='',accepted_at=NULL,acceptance_expires_at=NULL WHERE tenant_id=$1`, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	checkRisk(2, expiry, false, false)
	checkBreach(1, false)
}

func TestSLABreachClosedEpisodeCannotBecomeRelevantAfterRevocation(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("relevance-episode")
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT date_trunc('microseconds',now())`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(-time.Hour)
	seedOpenLifecycleWithDeadline(t, pool, ctx, tenant.String(), "episode", now.Add(-2*time.Hour), deadline)
	repo := NewNotificationRepository(pool)
	current := sla.Lifecycle{TenantID: tenant, EngagementID: "eng-episode", FindingID: "finding-episode", AssessmentID: "assessment-episode", Status: sla.RemediationOpen, Version: 1, UpdatedBy: "operator", UpdatedAt: now.Add(-2 * time.Hour)}
	check := func(version int, want bool) {
		t.Helper()
		got, err := repo.SLABreachCurrent(ctx, tenant, "eng-episode", "finding-episode", deadline, version)
		if err != nil || got != want {
			t.Fatalf("episode %d relevance=%v err=%v want %v", version, got, err, want)
		}
	}
	check(1, true)
	transition := func(to sla.RemediationStatus, id string, expiry *time.Time) {
		t.Helper()
		next, event, err := sla.ApplyTransition(current, shared.ID(id), sla.TransitionCommand{To: to, Reason: "approved", CompensatingControl: "control", AcceptanceExpiresAt: expiry, Actor: "operator", ExpectedVersion: current.Version}, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := NewSLAStore(pool).SaveTransition(ctx, next, event); err != nil {
			t.Fatal(err)
		}
		current = next
	}
	transition(sla.RemediationMitigating, "mitigating", nil)
	check(1, true) // A non-terminating transition retains the existing episode.
	expiry := now.Add(time.Hour)
	transition(sla.RemediationAcceptedRisk, "accepted", &expiry)
	check(1, false)
	transition(sla.RemediationOpen, "revoked", nil)
	check(1, false) // The original deadline cannot resurrect a closed episode.
	check(4, true)
}
