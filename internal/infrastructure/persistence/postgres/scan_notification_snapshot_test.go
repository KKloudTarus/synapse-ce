package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestScanJobTerminalSnapshotUsesEarlierCanonicalBaseline(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("scan-summary-" + randHex(t))
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,'Scan summary')", tenant); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO engagements(id,tenant_id,name) VALUES('scan-summary-eng',$1,'Scan summary')", tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", tenant) })

	makeSnapshot := func(keys ...string) notification.ScanSummary {
		items := make([]finding.Finding, 0, len(keys))
		for _, key := range keys {
			items = append(items, finding.Finding{ID: shared.ID(key), DedupKey: key, Kind: finding.KindSCA, Severity: shared.SeverityHigh})
		}
		return notification.NewScanSummary("https://git.example.test/repo", ports.TargetGit, true, items)
	}
	store := NewScanJobStore(pool)
	at := time.Now().UTC().Truncate(time.Microsecond)
	firstFinished := at.Add(time.Minute)
	first := ports.ScanJob{ID: "scan-summary-a", EngagementID: "scan-summary-eng", Target: "https://git.example.test/repo.git", Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &firstFinished, NotificationSnapshot: makeSnapshot("same", "fixed")}
	if err := store.Save(ctx, first); err != nil {
		t.Fatal(err)
	}
	secondFinished := at.Add(2 * time.Minute)
	second := ports.ScanJob{ID: "scan-summary-b", EngagementID: "scan-summary-eng", Target: "https://git.example.test/repo", Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &secondFinished, NotificationSnapshot: makeSnapshot("same", "new")}
	if err := store.Save(ctx, second); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetJob(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.NotificationSnapshot.DeltaAvailable || got.NotificationSnapshot.New != 1 || got.NotificationSnapshot.Fixed != 1 || got.NotificationSnapshot.BaselineJobID != first.ID {
		t.Fatalf("terminal snapshot = %+v", got.NotificationSnapshot)
	}
	// A status correction changes delivery relevance without replacing the
	// captured completion evidence.
	second.NotificationSnapshot = makeSnapshot()
	later := secondFinished.Add(time.Hour)
	second.FinishedAt = &later
	second.Status = ports.ScanFailed
	if err := store.Save(ctx, second); err != nil {
		t.Fatal(err)
	}
	got, err = store.GetJob(ctx, second.ID)
	if err != nil || got.Status != ports.ScanFailed || got.FinishedAt == nil || !got.FinishedAt.Equal(secondFinished) || got.NotificationSnapshot.BaselineJobID != first.ID || got.NotificationSnapshot.Total != 2 {
		t.Fatalf("frozen terminal snapshot = %+v, err=%v", got.NotificationSnapshot, err)
	}
	if err := store.Save(ctx, second); err != nil {
		t.Fatal(err)
	}
	second.Status = ports.ScanSucceeded
	successRetry := later.Add(time.Hour)
	second.FinishedAt = &successRetry
	second.NotificationSnapshot = makeSnapshot("untrusted-retry")
	if err := store.Save(ctx, second); err != nil {
		t.Fatal(err)
	}
	got, err = store.GetJob(ctx, second.ID)
	if err != nil || got.Status != ports.ScanSucceeded || got.FinishedAt == nil || !got.FinishedAt.Equal(secondFinished) || got.NotificationSnapshot.BaselineJobID != first.ID || got.NotificationSnapshot.Total != 2 {
		t.Fatalf("terminal retry replaced captured evidence: %+v, err=%v", got.NotificationSnapshot, err)
	}
}

func TestScanJobTerminalSnapshotDoesNotSkipLegacyPredecessor(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("scan-summary-legacy-" + randHex(t))
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,'Scan summary')", tenant); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO engagements(id,tenant_id,name) VALUES('scan-summary-legacy-eng',$1,'Scan summary')", tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", tenant) })

	rawTarget := "https://git.example.test/repo.git"
	targetKey := notification.CanonicalScanTarget(rawTarget, ports.TargetGit)
	makeSnapshot := func(keys ...string) notification.ScanSummary {
		items := make([]finding.Finding, 0, len(keys))
		for _, key := range keys {
			items = append(items, finding.Finding{ID: shared.ID(key), DedupKey: key, Kind: finding.KindSCA, Severity: shared.SeverityHigh})
		}
		return notification.NewScanSummary(targetKey, ports.TargetGit, true, items)
	}
	store := NewScanJobStore(pool)
	at := time.Now().UTC().Truncate(time.Microsecond)
	firstFinished := at.Add(time.Minute)
	if err := store.Save(ctx, ports.ScanJob{ID: "scan-summary-known", EngagementID: "scan-summary-legacy-eng", Target: rawTarget, Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &firstFinished, NotificationSnapshot: makeSnapshot("fixed")}); err != nil {
		t.Fatal(err)
	}
	legacyFinished := at.Add(2 * time.Minute)
	if err := store.Save(ctx, ports.ScanJob{ID: "scan-summary-legacy", EngagementID: "scan-summary-legacy-eng", Target: "https://git.example.test/repo", Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &legacyFinished}); err != nil {
		t.Fatal(err)
	}
	currentFinished := at.Add(3 * time.Minute)
	if err := store.Save(ctx, ports.ScanJob{ID: "scan-summary-current", EngagementID: "scan-summary-legacy-eng", Target: rawTarget, Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &currentFinished, NotificationSnapshot: makeSnapshot("new")}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetJob(ctx, "scan-summary-current")
	if err != nil {
		t.Fatal(err)
	}
	if got.NotificationSnapshot.DeltaAvailable || got.NotificationSnapshot.BaselineJobID != "" {
		t.Fatalf("legacy predecessor was skipped: %+v", got.NotificationSnapshot)
	}
}

func TestScanJobTerminalSnapshotRequiresTenantOwnedEngagement(t *testing.T) {
	pool := notificationTestPool(t)
	owner := shared.ID("scan-summary-owner-" + randHex(t))
	other := shared.ID("scan-summary-other-" + randHex(t))
	ownerCtx := shared.WithTenant(context.Background(), owner)
	otherCtx := shared.WithTenant(context.Background(), other)
	for _, tenant := range []shared.ID{owner, other} {
		if _, err := pool.Exec(context.Background(), "INSERT INTO tenants(id,name) VALUES($1,'Scan summary')", tenant); err != nil {
			t.Fatal(err)
		}
	}
	if err := WithTenant(ownerCtx, pool, owner.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ownerCtx, "INSERT INTO engagements(id,tenant_id,name) VALUES('scan-summary-foreign-eng',$1,'Scan summary')", owner)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=ANY($1)", []string{owner.String(), other.String()})
	})
	finished := time.Now().UTC()
	summary := notification.NewScanSummary("repo", ports.TargetGit, true, nil)
	err := NewScanJobStore(pool).Save(otherCtx, ports.ScanJob{ID: "scan-summary-foreign", EngagementID: "scan-summary-foreign-eng", Target: "repo", Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: finished, FinishedAt: &finished, NotificationSnapshot: summary})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign engagement save error = %v, want ErrNotFound", err)
	}
}

func TestEncodeScanJobNotificationSnapshotUsesEmptyObjectWithoutSnapshot(t *testing.T) {
	encoded, err := encodeScanJobNotificationSnapshot(ports.ScanJob{})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "{}" {
		t.Fatalf("empty notification snapshot = %s, want {}", encoded)
	}
}

func TestScanCompletedCaptureBoundsLargePersistedSnapshotContext(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("scan-summary-context-" + randHex(t))
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,'Scan summary')", tenant); err != nil {
		t.Fatal(err)
	}
	engagementName := "Engagement Key -----BEGIN RSA PRIVATE KEY-----\n" + strings.Repeat("MIIEow", 300) + "\n-----END RSA PRIVATE KEY-----"
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO engagements(id,tenant_id,name) VALUES('scan-summary-context-eng',$1,$2)", tenant, engagementName)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", tenant) })

	const count = 10000
	title := strings.Repeat("🧨", 1000)
	findings := make([]finding.Finding, 0, count)
	for i := 0; i < count; i++ {
		key := fmt.Sprintf("finding-%05d", i)
		findings = append(findings, finding.Finding{ID: shared.ID(key), DedupKey: key, Kind: finding.KindSCA, Severity: shared.SeverityInfo, Title: title, Status: finding.StatusOpen})
	}
	finished := time.Now().UTC().Truncate(time.Microsecond)
	summary := notification.NewScanSummary("repo", ports.TargetGit, true, findings)
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, repo, time.Minute)
	if _, err := source.Poll(ctx, finished, 10); err != nil {
		t.Fatal(err)
	}
	if err := NewScanJobStore(pool).Save(ctx, ports.ScanJob{ID: "scan-summary-context", EngagementID: "scan-summary-context-eng", Target: "https://user:pass@git.example.test/repo?opaque=secret#fragment", Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: finished, FinishedAt: &finished, NotificationSnapshot: summary}); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(ctx, finished.Add(time.Second), 10); err != nil {
		t.Fatal(err)
	}
	var encoded string
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT context::text FROM notification_events WHERE tenant_id=$1 AND source_kind='scan_job' AND source_id='scan-summary-context'", tenant).Scan(&encoded)
	}); err != nil {
		t.Fatal(err)
	}
	if len([]byte(encoded)) > 16*1024 {
		t.Fatalf("scan context is %d bytes, want <= 16384", len([]byte(encoded)))
	}
	context, err := notification.DecodeTemplateContext([]byte(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if context.Vars["total_count"] != "10000" || len(context.Lists["findings"]) == 0 || len(context.Lists["findings"]) > 50 {
		t.Fatalf("bounded scan context lost signal: %+v", context)
	}
	if got := context.Vars["engagement_name"]; got != "Engagement Key [redacted]" {
		t.Fatalf("source scalar was bounded before secret redaction: %q", got)
	}
	if context.Vars["target"] != "https://git.example.test/repo" {
		t.Fatalf("scan target context = %q", context.Vars["target"])
	}
	if strings.Contains(encoded, "\"keys\"") || strings.Contains(encoded, "\"identity\"") {
		t.Fatalf("internal scan comparison data reached context: %s", encoded)
	}
}

func TestTerminalScanSnapshotDoesNotWaitForLockedLegacyPredecessor(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("scan-summary-legacy-lock-" + randHex(t))
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,'Scan summary')", tenant); err != nil {
		t.Fatal(err)
	}
	const engagementID = "scan-summary-legacy-lock-eng"
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Scan summary')", engagementID, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", tenant) })

	store := NewScanJobStore(pool)
	at := time.Now().UTC().Truncate(time.Microsecond)
	legacyFinished := at.Add(time.Minute)
	legacy := ports.ScanJob{ID: "scan-summary-legacy-lock", EngagementID: engagementID, Target: "https://git.example.test/repo.git", Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &legacyFinished}
	if err := store.Save(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	holder, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback(context.Background())
	if _, err := holder.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(ctx, "SELECT id FROM scan_jobs WHERE id=$1 FOR UPDATE", legacy.ID); err != nil {
		t.Fatal(err)
	}

	finished := at.Add(2 * time.Minute)
	current := ports.ScanJob{ID: "scan-summary-current-lock", EngagementID: engagementID, Target: "https://git.example.test/repo", Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &finished,
		NotificationSnapshot: notification.NewScanSummary("https://git.example.test/repo", ports.TargetGit, true, []finding.Finding{{ID: "current", DedupKey: "current", Kind: finding.KindSCA, Severity: shared.SeverityHigh}})}
	deadlineCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := store.Save(deadlineCtx, current); err != nil {
		t.Fatalf("terminal snapshot waited for legacy predecessor lock: %v", err)
	}
}

func TestTerminalScanSnapshotConcurrentRetriesDoNotLockPredecessors(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("scan-summary-retry-" + randHex(t))
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,'Scan summary')", tenant); err != nil {
		t.Fatal(err)
	}
	const engagementID = "scan-summary-retry-eng"
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Scan summary')", engagementID, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", tenant) })

	makeSummary := func(target, key string) notification.ScanSummary {
		return notification.NewScanSummary(target, ports.TargetLocal, true, []finding.Finding{{ID: shared.ID(key), DedupKey: key, Kind: finding.KindSCA, Severity: shared.SeverityHigh}})
	}
	store := NewScanJobStore(pool)
	at := time.Now().UTC().Truncate(time.Microsecond)
	firstFinished := at.Add(time.Minute)
	first := ports.ScanJob{ID: "scan-summary-retry-a", EngagementID: engagementID, Target: "repo-a", Kind: ports.TargetLocal, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &firstFinished, NotificationSnapshot: makeSummary("repo-a", "a")}
	secondFinished := at.Add(2 * time.Minute)
	second := ports.ScanJob{ID: "scan-summary-retry-b", EngagementID: engagementID, Target: "repo-b", Kind: ports.TargetLocal, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &secondFinished, NotificationSnapshot: makeSummary("repo-b", "b")}
	for _, job := range []ports.ScanJob{first, second} {
		if err := store.Save(ctx, job); err != nil {
			t.Fatal(err)
		}
	}

	lockRow := func(id string) pgx.Tx {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "SELECT id FROM scan_jobs WHERE id=$1 FOR UPDATE", id); err != nil {
			t.Fatal(err)
		}
		return tx
	}
	firstLock := lockRow(first.ID)
	defer firstLock.Rollback(context.Background())
	secondLock := lockRow(second.ID)
	defer secondLock.Rollback(context.Background())
	var firstLockPID, secondLockPID uint32
	if err := firstLock.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&firstLockPID); err != nil {
		t.Fatal(err)
	}
	if err := secondLock.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&secondLockPID); err != nil {
		t.Fatal(err)
	}

	deadlineCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	errs := make(chan error, 2)
	for _, job := range []ports.ScanJob{first, second} {
		job := job
		finished := at.Add(3 * time.Minute)
		job.FinishedAt = &finished
		go func() { errs <- store.Save(deadlineCtx, job) }()
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE wait_event_type='Lock' AND ($1=ANY(pg_blocking_pids(pid)) OR $2=ANY(pg_blocking_pids(pid)))`, firstLockPID, secondLockPID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("terminal retry saves did not reach their row locks")
		}
		time.Sleep(10 * time.Millisecond)
	}
	startRelease := make(chan struct{})
	released := make(chan error, 2)
	for _, tx := range []pgx.Tx{firstLock, secondLock} {
		tx := tx
		go func() {
			<-startRelease
			released <- tx.Commit(ctx)
		}()
	}
	close(startRelease)
	for range 2 {
		if err := <-released; err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("terminal retry failed: %v", err)
		}
	}
	for _, job := range []ports.ScanJob{first, second} {
		got, err := store.GetJob(ctx, job.ID)
		if err != nil || got.FinishedAt == nil || !got.FinishedAt.Equal(job.FinishedAt.UTC()) {
			t.Fatalf("frozen terminal retry %s = %+v, err=%v", job.ID, got, err)
		}
	}
}

func TestTerminalScanSnapshotsSerializeConcurrentCanonicalTarget(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("scan-summary-concurrent-" + randHex(t))
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,'Scan summary')", tenant); err != nil {
		t.Fatal(err)
	}
	const engagementID = "scan-summary-concurrent-eng"
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Scan summary')", engagementID, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", tenant) })

	finished := time.Now().UTC().Truncate(time.Microsecond)
	makeJob := func(id, target, key string) ports.ScanJob {
		return ports.ScanJob{ID: id, EngagementID: engagementID, Target: target, Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: finished, FinishedAt: &finished,
			NotificationSnapshot: notification.NewScanSummary(notification.CanonicalScanTarget(target, ports.TargetGit), ports.TargetGit, true, []finding.Finding{{ID: shared.ID(key), DedupKey: key, Kind: finding.KindSCA, Severity: shared.SeverityHigh}})}
	}
	jobs := []ports.ScanJob{makeJob("scan-summary-concurrent-a", "https://git.example.test/repo.git", "a"), makeJob("scan-summary-concurrent-b", "https://git.example.test/repo", "b")}
	store := NewScanJobStore(pool)
	lock, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(context.Background())
	var lockPID int
	if err := lock.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&lockPID); err != nil {
		t.Fatal(err)
	}
	target := notification.CanonicalScanTarget(jobs[0].Target, jobs[0].Kind)
	lockKey := fmt.Sprintf("%d:%s%d:%s%d:%s", len(engagementID), engagementID, len(ports.TargetGit), ports.TargetGit, len(target), target)
	if _, err := lock.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", lockKey); err != nil {
		t.Fatal(err)
	}
	saveCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	start := make(chan struct{})
	errs := make(chan error, len(jobs))
	var ready sync.WaitGroup
	ready.Add(len(jobs))
	for _, job := range jobs {
		job := job
		go func() {
			ready.Done()
			<-start
			errs <- store.Save(saveCtx, job)
		}()
	}
	ready.Wait()
	close(start)
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE $1 = ANY(pg_blocking_pids(pid))`, lockPID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting == len(jobs) {
			break
		}
		select {
		case err := <-errs:
			t.Fatalf("terminal save returned before the canonical target lock was released: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("canonical target saves did not wait on the held advisory lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := lock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for range jobs {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent terminal save: %v", err)
		}
	}
	for _, job := range jobs {
		got, err := store.GetJob(ctx, job.ID)
		if err != nil || got.NotificationSnapshot.TargetKey != "https://git.example.test/repo" || got.NotificationSnapshot.Total != 1 {
			t.Fatalf("terminal snapshot %s = %+v, err=%v", job.ID, got.NotificationSnapshot, err)
		}
	}
}

func TestTerminalScanSnapshotPredecessorPlanUsesSucceededIndex(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("scan-summary-plan-" + randHex(t))
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,'Scan summary')", tenant); err != nil {
		t.Fatal(err)
	}
	const engagementID = "scan-summary-plan-eng"
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Scan summary')", engagementID, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", tenant) })
	if _, err := pool.Exec(ctx, `INSERT INTO scan_jobs(id,engagement_id,target,kind,status,stage,progress,started_at,finished_at)
		SELECT 'scan-summary-plan-' || n, $1, 'repo-' || n, 'git', 'succeeded', 'done', 100, now() - n * interval '1 second', now() - n * interval '1 second'
		FROM generate_series(1,12000) AS n`, engagementID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "ANALYZE scan_jobs"); err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Query(ctx, `EXPLAIN (COSTS OFF) SELECT id, target, notification_snapshot FROM scan_jobs
		WHERE engagement_id=$1 AND kind=$2 AND status='succeeded' AND id<>$3
		AND (finished_at < $4 OR (finished_at = $4 AND id < $5))
		ORDER BY finished_at DESC NULLS LAST, id DESC LIMIT 128`, engagementID, ports.TargetGit, "scan-summary-plan-current", time.Now().UTC().Add(time.Hour), "scan-summary-plan-current")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(plan, "\n"), "idx_scan_jobs_succeeded_predecessor") {
		t.Fatalf("predecessor query did not use succeeded index:\n%s", strings.Join(plan, "\n"))
	}
}
