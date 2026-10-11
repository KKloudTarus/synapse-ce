package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestRunTerminalProducersPostgresSnapshotsAndReplay(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("run-events")
	ctx := shared.WithTenant(context.Background(), tenant)
	at := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	eng, err := engagement.New("run-events-eng", "", "Captured run engagement", "", at)
	if err != nil {
		t.Fatal(err)
	}
	eng.TenantID = tenant
	if err := NewEngagementRepository(pool).Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	// The activation gate is deliberately enabled before the producer writes.
	eventRepo := NewNotificationRepository(pool)
	eventRepo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, eventRepo, time.Minute)
	if _, err := source.Poll(ctx, at, 100); err != nil {
		t.Fatal(err)
	}

	dastStore := NewDASTRunStore(pool)
	dast, err := dastrun.NewRun("run-dast", tenant, eng.ID, "action", "operator", at)
	if err != nil {
		t.Fatal(err)
	}
	if err := dastStore.SaveDASTRun(ctx, dast); err != nil {
		t.Fatal(err)
	}
	if err := dast.Start(); err != nil {
		t.Fatal(err)
	}
	if won, err := dastStore.StartRun(ctx, tenant, dast); err != nil || !won {
		t.Fatalf("start DAST won=%v err=%v", won, err)
	}
	dast.Fail("probe_timeout", at.Add(time.Minute))
	if won, err := dastStore.FinishRun(ctx, tenant, dast); err != nil || !won {
		t.Fatalf("finish stranded DAST won=%v err=%v", won, err)
	}
	if won, err := dastStore.FinishRun(ctx, tenant, dast); err != nil || won {
		t.Fatalf("DAST replay won=%v err=%v", won, err)
	}

	cspmStore := NewCloudRunStore(pool)
	cspm := cloudposture.Run{ID: "run-cspm", TenantID: tenant, EngagementID: eng.ID, Actor: "operator", Status: cloudposture.RunQueued, StartedAt: at}
	if err := cspmStore.EnqueueCloudRun(ctx, cspm, "cspm", []byte(`{"scopes":[{"provider":"aws"},{"provider":"aws"}]}`)); err != nil {
		t.Fatal(err)
	}
	finished := at.Add(2 * time.Minute)
	cspm.Status, cspm.ErrorCode, cspm.FinishedAt = cloudposture.RunCancelled, "dead_letter", &finished
	if err := cspmStore.SaveCloudRun(ctx, cspm); err != nil {
		t.Fatal(err)
	}
	if err := cspmStore.SaveCloudRun(ctx, cspm); err != nil {
		t.Fatal(err)
	}

	reconStore := NewReconRunStore(pool)
	reconRun := recon.Run{ID: "run-recon", EngagementID: eng.ID, Tool: "subfinder", Target: "https://user:secret@example.test/path?token=secret", Status: recon.StatusRunning, StartedAt: at}
	if err := reconStore.Save(ctx, reconRun); err != nil {
		t.Fatal(err)
	}
	reconFinished := at.Add(3 * time.Minute)
	reconRun.Status, reconRun.FinishedAt, reconRun.ResultCount = recon.StatusSucceeded, &reconFinished, 9
	if err := reconStore.Save(ctx, reconRun); err != nil {
		t.Fatal(err)
	}
	if err := reconStore.Save(ctx, reconRun); err != nil {
		t.Fatal(err)
	}

	scanStore := NewScanJobStore(pool)
	scan := ports.ScanJob{ID: "run-scan", EngagementID: eng.ID.String(), Target: "example.test?token=secret", Kind: "sast", Status: ports.ScanRunning, StartedAt: at}
	if err := scanStore.CreateRunning(ctx, scan); err != nil {
		t.Fatal(err)
	}
	scan.Status, scan.Stage, scan.Error = ports.ScanFailed, "timeout", "raw token=secret"
	scan.FinishedAt = ptrRunTime(at.Add(4 * time.Minute))
	if err := scanStore.Save(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if err := scanStore.Save(ctx, scan); err != nil {
		t.Fatal(err)
	}

	// Mutable presentation rows can change after the transaction without altering
	// a sealed source record or its terminal timestamp.
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE engagements SET name='Changed after terminal' WHERE tenant_id=$1 AND id=$2`, tenant, eng.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct {
		event notification.EventType
		id    string
	}{
		{notification.EventDASTRunFinished, dast.ID.String()},
		{notification.EventCSPMRunFinished, cspm.ID.String()},
		{notification.EventReconRunFinished, reconRun.ID.String()},
		{notification.EventScanFailed, scan.ID},
	} {
		var data, snapshot []byte
		var version int
		var occurred time.Time
		err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT data,context,capture_version,occurred_at FROM notification_source_records WHERE tenant_id=$1 AND source_id=$2`, tenant, want.id).Scan(&data, &snapshot, &version, &occurred)
		})
		if err != nil || version != 3 {
			t.Fatalf("%s source err=%v capture=%d", want.event, err, version)
		}
		var values map[string]any
		if err := json.Unmarshal(data, &values); err != nil || values["outcome"] == nil {
			t.Fatalf("%s data=%s err=%v", want.event, data, err)
		}
		facts, err := notification.DecodeTemplateContext(snapshot)
		if err != nil || facts.Vars["engagement_name"] != "Captured run engagement" {
			t.Fatalf("%s mutable context=%+v err=%v", want.event, facts, err)
		}
		if strings.Contains(string(data), "secret") || strings.Contains(string(snapshot), "secret") {
			t.Fatalf("%s exposed raw target or worker error", want.event)
		}
		if occurred.IsZero() {
			t.Fatalf("%s missing terminal timestamp", want.event)
		}
	}
	var count int
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND source_kind IN ('scan_job','dast_run','recon_run','cspm_run')`, tenant).Scan(&count)
	}); err != nil || count != 4 {
		t.Fatalf("run source replay count=%d err=%v", count, err)
	}
	if _, err := source.Poll(ctx, at.Add(10*time.Minute), 100); err != nil {
		t.Fatal(err)
	}
	for _, eventType := range []notification.EventType{notification.EventDASTRunFinished, notification.EventCSPMRunFinished, notification.EventReconRunFinished, notification.EventScanFailed} {
		events, err := eventRepo.ListRecentNotificationEvents(ctx, tenant, eventType, 2)
		if err != nil || len(events) != 1 {
			t.Fatalf("published %s events=%d err=%v", eventType, len(events), err)
		}
		assertPublishedEventSchema(t, events[0])
	}
}

func TestRunTerminalProducerRollbackAndTenantBoundary(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("run-rollback")
	ctx := shared.WithTenant(context.Background(), tenant)
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1),('run-foreign','foreign')`, tenant); err != nil {
		t.Fatal(err)
	}
	eng, err := engagement.New("run-rollback-eng", "", "Rollback", "", at)
	if err != nil {
		t.Fatal(err)
	}
	eng.TenantID = tenant
	if err := NewEngagementRepository(pool).Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	if _, err := NewNotificationSource(pool, NewNotificationRepository(pool), time.Minute).Poll(ctx, at, 100); err != nil {
		t.Fatal(err)
	}
	store := NewDASTRunStore(pool)
	longID := shared.ID(strings.Repeat("r", 513))
	run, err := dastrun.NewRun(longID, tenant, eng.ID, "action", "operator", at)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveDASTRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	if won, err := store.StartRun(ctx, tenant, run); err != nil || !won {
		t.Fatalf("start=%v err=%v", won, err)
	}
	run.Fail("timeout", at.Add(time.Minute))
	if _, err := store.FinishRun(ctx, tenant, run); err == nil {
		t.Fatal("invalid source key terminalized DAST run")
	}
	stored, err := store.GetDASTRun(ctx, tenant, longID)
	if err != nil || stored.Status != dastrun.RunRunning {
		t.Fatalf("terminal escaped rollback: %+v %v", stored, err)
	}
	foreign := run
	foreign.TenantID = "run-foreign"
	if _, err := store.FinishRun(ctx, tenant, foreign); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("foreign terminal accepted: %v", err)
	}
}

func TestRunTerminalProducerSupportedOutcomesAndFirstOutcomeWins(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("run-outcomes")
	ctx := shared.WithTenant(context.Background(), tenant)
	at := time.Date(2026, 10, 12, 13, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	eng, err := engagement.New("run-outcomes-eng", "", "Outcomes", "", at)
	if err != nil {
		t.Fatal(err)
	}
	eng.TenantID = tenant
	if err := NewEngagementRepository(pool).Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	eventRepo := NewNotificationRepository(pool)
	eventRepo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, eventRepo, time.Minute)
	if _, err := source.Poll(ctx, at, 100); err != nil {
		t.Fatal(err)
	}

	dastStore := NewDASTRunStore(pool)
	for _, outcome := range []dastrun.RunStatus{dastrun.RunSucceeded, dastrun.RunFailed} {
		run, err := dastrun.NewRun(shared.ID("outcome-dast-"+string(outcome)), tenant, eng.ID, shared.ID("action-"+string(outcome)), "operator", at)
		if err != nil {
			t.Fatal(err)
		}
		if err := dastStore.SaveDASTRun(ctx, run); err != nil {
			t.Fatal(err)
		}
		if err := run.Start(); err != nil {
			t.Fatal(err)
		}
		if won, err := dastStore.StartRun(ctx, tenant, run); err != nil || !won {
			t.Fatalf("start DAST %s won=%v err=%v", outcome, won, err)
		}
		finished := at.Add(time.Duration(len(outcome)) * time.Minute)
		if outcome == dastrun.RunSucceeded {
			if err := run.Succeed("confirmed", 200, shared.ID("evidence-"+string(outcome)), finished); err != nil {
				t.Fatal(err)
			}
		} else {
			run.Fail("timeout", finished)
		}
		if won, err := dastStore.FinishRun(ctx, tenant, run); err != nil || !won {
			t.Fatalf("finish DAST %s won=%v err=%v", outcome, won, err)
		}
	}

	reconStore := NewReconRunStore(pool)
	for _, outcome := range []recon.Status{recon.StatusSucceeded, recon.StatusFailed} {
		finished := at.Add(time.Duration(len(outcome)+10) * time.Minute)
		run := recon.Run{ID: shared.ID("outcome-recon-" + string(outcome)), EngagementID: eng.ID, Tool: "subfinder", Target: "example.test", Status: recon.StatusRunning, StartedAt: at}
		if err := reconStore.Save(ctx, run); err != nil {
			t.Fatal(err)
		}
		run.Status, run.FinishedAt = outcome, &finished
		if outcome == recon.StatusFailed {
			run.Stage, run.Error = "timeout", "raw tool failure"
		}
		if err := reconStore.Save(ctx, run); err != nil {
			t.Fatal(err)
		}
	}

	cspmStore := NewCloudRunStore(pool)
	for _, outcome := range []cloudposture.RunStatus{cloudposture.RunSucceeded, cloudposture.RunPartial, cloudposture.RunFailed, cloudposture.RunCancelled} {
		run := cloudposture.Run{ID: shared.ID("outcome-cspm-" + string(outcome)), TenantID: tenant, EngagementID: eng.ID, Actor: "operator", Status: cloudposture.RunQueued, StartedAt: at}
		if err := cspmStore.EnqueueCloudRun(ctx, run, "cspm", []byte(`{"scopes":[{"provider":"aws"},{"provider":"gcp"}]}`)); err != nil {
			t.Fatal(err)
		}
		finished := at.Add(time.Duration(len(outcome)+20) * time.Minute)
		run.Status, run.FinishedAt, run.Findings = outcome, &finished, 3
		if outcome == cloudposture.RunFailed || outcome == cloudposture.RunCancelled {
			run.ErrorCode = "terminal_" + string(outcome)
		}
		if err := cspmStore.SaveCloudRun(ctx, run); err != nil {
			t.Fatal(err)
		}
	}
	// A pre-migration run can lack both durable providers and a retained job.
	// It still terminalizes atomically with an explicit unknown provider token.
	legacyFinished := at.Add(80 * time.Minute)
	legacy := cloudposture.Run{ID: "outcome-cspm-legacy", TenantID: tenant, EngagementID: eng.ID, Actor: "operator", Status: cloudposture.RunFailed, ErrorCode: "legacy", StartedAt: at, FinishedAt: &legacyFinished}
	if err := cspmStore.SaveCloudRun(ctx, legacy); err != nil {
		t.Fatal(err)
	}

	// A later business correction may update the durable run, but its first
	// terminal notification source remains the immutable event-time outcome.
	corrected := cloudposture.Run{ID: "outcome-cspm-failed", TenantID: tenant, EngagementID: eng.ID, Actor: "operator", Status: cloudposture.RunSucceeded, Complete: true, Findings: 99, StartedAt: at, FinishedAt: ptrRunTime(at.Add(90 * time.Minute))}
	if err := cspmStore.SaveCloudRun(ctx, corrected); err != nil {
		t.Fatal(err)
	}

	for _, want := range []struct {
		sourceID string
		outcome  string
	}{
		{"outcome-dast-succeeded", "succeeded"}, {"outcome-dast-failed", "failed"},
		{"outcome-recon-succeeded", "succeeded"}, {"outcome-recon-failed", "failed"},
		{"outcome-cspm-succeeded", "succeeded"}, {"outcome-cspm-partial", "partial"},
		{"outcome-cspm-failed", "failed"}, {"outcome-cspm-cancelled", "cancelled"},
		{"outcome-cspm-legacy", "failed"},
	} {
		var raw []byte
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT data FROM notification_source_records WHERE tenant_id=$1 AND source_id=$2`, tenant, want.sourceID).Scan(&raw)
		}); err != nil {
			t.Fatalf("read source %s: %v", want.sourceID, err)
		}
		var data map[string]any
		if err := json.Unmarshal(raw, &data); err != nil || data["outcome"] != want.outcome {
			t.Fatalf("source %s outcome=%v data=%s err=%v", want.sourceID, data["outcome"], raw, err)
		}
		if want.sourceID == "outcome-cspm-legacy" && data["provider"] != "unknown" {
			t.Fatalf("legacy CSPM provider=%v data=%s", data["provider"], raw)
		}
	}
	if _, err := source.Poll(ctx, at.Add(2*time.Hour), 100); err != nil {
		t.Fatal(err)
	}
	for _, eventType := range []struct {
		type_ notification.EventType
		count int
	}{
		{notification.EventDASTRunFinished, 2}, {notification.EventReconRunFinished, 2}, {notification.EventCSPMRunFinished, 5},
	} {
		events, err := eventRepo.ListRecentNotificationEvents(ctx, tenant, eventType.type_, 10)
		if err != nil || len(events) != eventType.count {
			t.Fatalf("published %s events=%d err=%v", eventType.type_, len(events), err)
		}
		for _, event := range events {
			assertPublishedEventSchema(t, event)
		}
	}
}

func ptrRunTime(value time.Time) *time.Time { return &value }
