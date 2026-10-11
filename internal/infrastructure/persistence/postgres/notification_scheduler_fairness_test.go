package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/jackc/pgx/v5"
)

func TestNotificationSchedulerProgressUnderSnapshotAndLifecycleBacklog(t *testing.T) {
	pool := notificationTestPool(t)
	base := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, repo, time.Minute)
	ctx := context.Background()
	tenants := []shared.ID{"fairness-a", "fairness-m", "fairness-z"}
	for _, tenant := range tenants {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := source.Poll(ctx, base, 200); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range tenants {
		tenantCtx := shared.WithTenant(ctx, tenant)
		for i := range 5 {
			seedOpenLifecycleWithDeadline(t, pool, tenantCtx, tenant.String(), fmt.Sprintf("%s-breach-%d", tenant, i), base, base.Add(time.Hour))
		}
		seedLifecycleAcceptance(t, pool, tenantCtx, tenant.String(), tenant.String()+"-expired", base, base.Add(2*time.Hour))
		seedLifecycleAcceptance(t, pool, tenantCtx, tenant.String(), tenant.String()+"-warning", base, base.Add(4*time.Hour))
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			for _, legacy := range []struct {
				kind  string
				event notification.EventType
			}{{"scan_job", notification.EventScanCompleted}, {"project_analysis_gate", notification.EventQualityGateFailed}, {"incident", notification.EventIncidentCreated}} {
				data, _ := json.Marshal(map[string]any{"title": "Legacy notification", "summary": "Existing source remains recoverable.", "scan_kind": "sast", "total_count": 0, "failed_conditions": 1, "project_id": "legacy-project"})
				record := notification.SourceRecord{TenantID: tenant, SourceKind: legacy.kind, SourceID: "legacy", EventType: legacy.event, EngagementID: shared.ID("eng-" + tenant.String() + "-warning"), Severity: shared.SeverityHigh, OccurredAt: base.Add(time.Minute), Data: data}
				if err := NewNotificationOutbox(pool).Append(bindTenantTransaction(shared.WithTenant(ctx, tenant), tenant, tx), record); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		for i, lead := range []int64{3600, 7200} {
			insertLifecycleRule(t, pool, tenantCtx, tenant.String(), fmt.Sprintf("warning-%d", i), notification.EventRiskAcceptanceExpiring, lead)
		}
	}
	// All tenants remain saturated. Tiny batches must still advance breach,
	// expiry and every warning window, alongside snapshot projection.
	var tenantCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE id<>''`).Scan(&tenantCount); err != nil {
		t.Fatal(err)
	}
	// Eight due observations per tenant must progress within eight complete
	// tenant rotations. Include identities seeded by migrations in this bound.
	for tick := range 8 * tenantCount {
		for _, tenant := range tenants {
			if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
				for i := range 10 {
					id := fmt.Sprintf("finding-%d-%d", tick, i)
					data, _ := json.Marshal(map[string]any{"title": "Finding created", "summary": "A finding was created.", "finding_id": id, "engagement_id": "eng-" + tenant.String() + "-warning", "finding_kind": "manual", "status": "open", "finding_version": 1})
					if err := appendNotificationSnapshotTx(ctx, tx, notification.SourceRecord{TenantID: tenant, SourceKind: "finding_created", SourceID: id, EventType: notification.EventFindingCreated, EngagementID: shared.ID("eng-" + tenant.String() + "-warning"), OccurredAt: base.Add(time.Minute), Data: data, SubjectKind: "finding", SubjectID: id}, nil); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		if n, err := source.Poll(ctx, base.Add(3*time.Hour), 8); err != nil || n > 8 {
			t.Fatalf("poll count=%d err=%v", n, err)
		}
	}
	for _, tenant := range tenants {
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			var breaches, expired, warnings, projected, legacy int
			if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE event_type='sla.breached'),count(*) FILTER (WHERE event_type='risk_acceptance.expired'),count(*) FILTER (WHERE event_type='risk_acceptance.expiring') FROM notification_source_records WHERE tenant_id=$1`, tenant).Scan(&breaches, &expired, &warnings); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE tenant_id=$1 AND event_type='finding.created'`, tenant).Scan(&projected); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE tenant_id=$1 AND event_type IN ('scan.completed','quality_gate.failed','incident.created')`, tenant).Scan(&legacy); err != nil {
				return err
			}
			if legacy != 3 {
				t.Fatalf("tenant %s legacy projections=%d want 3", tenant, legacy)
			}
			if breaches != 5 || expired != 1 || warnings != 2 || projected == 0 {
				t.Fatalf("tenant %s progress breach=%d expired=%d warnings=%d snapshots=%d", tenant, breaches, expired, warnings, projected)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRiskAcceptanceCaptureFailureRollsBackLifecycleAndEpisode(t *testing.T) {
	pool := notificationTestPool(t)
	base := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	tenant := shared.ID("acceptance-rollback")
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	source := NewNotificationSource(pool, NewNotificationRepository(pool), time.Minute)
	if _, err := source.Poll(ctx, base, 100); err != nil {
		t.Fatal(err)
	}
	deadline := base.Add(time.Hour)
	seedOpenLifecycleWithDeadline(t, pool, ctx, tenant.String(), "rollback", base, deadline)
	key := "finding-rollback:" + strconv.FormatInt(deadline.UnixMicro(), 10)
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return upsertLifecycleState(ctx, tx, tenant, slaBreachStateKind, key, "0", true, deadline)
	}); err != nil {
		t.Fatal(err)
	}
	current := sla.Lifecycle{TenantID: tenant, EngagementID: "eng-rollback", FindingID: "finding-rollback", AssessmentID: "assessment-rollback", Status: sla.RemediationOpen, Version: 1, UpdatedBy: "operator", UpdatedAt: base}
	expiry := deadline.Add(time.Hour)
	next, event, err := sla.ApplyTransition(current, shared.ID(strings.Repeat("a", 513)), sla.TransitionCommand{To: sla.RemediationAcceptedRisk, Reason: "approved", CompensatingControl: "control", AcceptanceExpiresAt: &expiry, Actor: "operator", ExpectedVersion: 1}, deadline)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewSLAStore(pool).SaveTransition(ctx, next, event); err == nil {
		t.Fatal("oversized capture identity did not fail")
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		var version, events, sources int
		var status string
		var active bool
		if err := tx.QueryRow(ctx, `SELECT version,status FROM sla_lifecycles WHERE tenant_id=$1`, tenant).Scan(&version, &status); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM sla_lifecycle_events WHERE tenant_id=$1),(SELECT count(*) FROM notification_source_records WHERE tenant_id=$1)`, tenant).Scan(&events, &sources); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT active FROM notification_source_state WHERE tenant_id=$1 AND source_kind='sla_breach' AND source_id=$2`, tenant, key).Scan(&active); err != nil {
			return err
		}
		if version != 1 || status != "open" || events != 0 || sources != 0 || !active {
			t.Fatalf("rollback version=%d status=%s events=%d sources=%d active=%v", version, status, events, sources, active)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationActivationBaselineSerializesWithAcceptance(t *testing.T) {
	pool := notificationTestPool(t)
	base := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	tenant := shared.ID("activation-acceptance")
	ctx, cancel := context.WithTimeout(shared.WithTenant(context.Background(), tenant), 15*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	deadline := base.Add(-time.Hour)
	seedOpenLifecycleWithDeadline(t, pool, ctx, tenant.String(), "activation", base.Add(-2*time.Hour), deadline)
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, repo, time.Minute)
	key := "finding-activation:" + strconv.FormatInt(deadline.UnixMicro(), 10)
	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	if _, err := blocker.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	if err := upsertLifecycleState(ctx, blocker, tenant, slaBreachStateKind, key, "4", true, base); err != nil {
		t.Fatal(err)
	}
	var blockerPID int
	if err := blocker.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	baselinePID := make(chan int, 1)
	baselineDone := make(chan error, 1)
	go func() {
		baselineDone <- WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			var pid int
			if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				return err
			}
			baselinePID <- pid
			return source.baselineLifecycle(ctx, tx, tenant, base)
		})
	}()
	waitBlocked := func(pid, blockedBy int) {
		t.Helper()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			var blocked bool
			if err := pool.QueryRow(ctx, `SELECT $2=ANY(pg_blocking_pids($1))`, pid, blockedBy).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("expected database lock wait", ctx.Err())
			case <-ticker.C:
			}
		}
	}
	var pid int
	select {
	case pid = <-baselinePID:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	baselineProcess := pid
	waitBlocked(pid, blockerPID) // Baseline has locked the lifecycle before its state write.
	current := sla.Lifecycle{TenantID: tenant, EngagementID: "eng-activation", FindingID: "finding-activation", AssessmentID: "assessment-activation", Status: sla.RemediationOpen, Version: 1, UpdatedBy: "operator", UpdatedAt: base.Add(-2 * time.Hour)}
	expiry := base.Add(time.Hour)
	next, event, err := sla.ApplyTransition(current, "acceptance-activation", sla.TransitionCommand{To: sla.RemediationAcceptedRisk, Reason: "approved", CompensatingControl: "control", AcceptanceExpiresAt: &expiry, Actor: "operator", ExpectedVersion: 1}, base)
	if err != nil {
		t.Fatal(err)
	}
	acceptancePID := make(chan int, 1)
	acceptanceDone := make(chan error, 1)
	go func() {
		acceptanceDone <- NewTenantTransactionRunner(pool).Run(ctx, tenant, func(txCtx context.Context) error {
			tx, _, err := contextTenantTx(txCtx, tenant)
			if err != nil {
				return err
			}
			var pid int
			if err := tx.QueryRow(txCtx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				return err
			}
			acceptancePID <- pid
			return NewSLAStore(pool).SaveTransition(txCtx, next, event)
		})
	}()
	select {
	case pid = <-acceptancePID:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waitBlocked(pid, baselineProcess) // Acceptance cannot race past the baseline's lifecycle lock.
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, result := range []<-chan error{baselineDone, acceptanceDone} {
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, active, found, err := lifecycleState(ctx, tx, tenant, slaBreachStateKind, key)
		if err == nil && (!found || active) {
			t.Fatal("acceptance did not close the concurrently initialized baseline")
		}
		// Finish activation before observing the future expiry threshold.
		if err == nil {
			err = upsertLifecycleState(ctx, tx, tenant, "framework", "activation", "v1", true, base)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(ctx, expiry, 100); err != nil {
		t.Fatal(err)
	}
	assertSourceRecord(t, pool, ctx, tenant.String(), "sla_breach_episode", key+":2:0", expiry)
}
