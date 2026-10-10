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
	// A retry may carry stale, malformed, or oversized worker output. Once the
	// successful snapshot is frozen it must retain its stored evidence and time.
	replacement := second
	replacementFinished := successRetry.Add(time.Hour)
	replacement.FinishedAt = &replacementFinished
	replacement.NotificationSnapshot = notification.ScanSummary{
		TargetKey: "untrusted-target", Kind: "untrusted-kind",
		Keys: []string{strings.Repeat("x", 4*1024*1024)},
	}
	if err := store.Save(ctx, replacement); err != nil {
		t.Fatalf("frozen retry rejected replacement payload: %v", err)
	}
	got, err = store.GetJob(ctx, second.ID)
	if err != nil || got.FinishedAt == nil || !got.FinishedAt.Equal(secondFinished) || got.NotificationSnapshot.BaselineJobID != first.ID || got.NotificationSnapshot.Total != 2 {
		t.Fatalf("frozen retry replaced stored snapshot: %+v, err=%v", got.NotificationSnapshot, err)
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
	const target = "https://user:pass@git.example.test/repo?opaque=secret#fragment"
	findings := make([]finding.Finding, 0, count)
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("finding-%05d", i)
		key := fmt.Sprintf("%05d-%s", i, strings.Repeat("k", 414))
		findings = append(findings, finding.Finding{ID: shared.ID(id), DedupKey: key, Kind: finding.KindSCA, Severity: shared.SeverityInfo, Title: "scan finding", Status: finding.StatusOpen})
	}
	finished := time.Now().UTC().Truncate(time.Microsecond)
	summary := notification.NewScanSummary(notification.CanonicalScanTarget(target, ports.TargetGit), ports.TargetGit, true, findings)
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, repo, time.Minute)
	if _, err := source.Poll(ctx, finished, 10); err != nil {
		t.Fatal(err)
	}
	store := NewScanJobStore(pool)
	if err := store.Save(ctx, ports.ScanJob{ID: "scan-summary-context", EngagementID: "scan-summary-context-eng", Target: target, Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: finished, FinishedAt: &finished, NotificationSnapshot: summary}); err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetJob(ctx, "scan-summary-context")
	if err != nil {
		t.Fatal(err)
	}
	if stored.NotificationSnapshot.Total != count || !stored.NotificationSnapshot.Truncated || stored.NotificationSnapshot.DeltaAvailable {
		t.Fatalf("large snapshot did not round-trip its bounded comparison state: %+v", stored.NotificationSnapshot)
	}
	var snapshotSize int
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT pg_column_size(notification_snapshot) FROM scan_jobs WHERE id=$1", "scan-summary-context").Scan(&snapshotSize)
	}); err != nil {
		t.Fatal(err)
	}
	if snapshotSize >= 4*1024*1024 {
		t.Fatalf("stored notification snapshot = %d bytes, want < 4MiB", snapshotSize)
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
	longTarget := incompressibleScanTarget()
	if _, err := pool.Exec(ctx, `INSERT INTO scan_jobs(id,engagement_id,target,kind,status,stage,progress,started_at,finished_at,notification_snapshot)
		SELECT 'scan-summary-plan-' || n, $1, $2 || n, 'git', 'succeeded', 'done', 100,
			now() - n * interval '1 second', now() - n * interval '1 second',
			jsonb_build_object('target_key',$2 || n,'kind','git')
		FROM generate_series(1,12000) AS n`, engagementID, longTarget); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "ANALYZE scan_jobs"); err != nil {
		t.Fatal(err)
	}
	targetKey := longTarget + "1"
	rows, err := pool.Query(ctx, `EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, SUMMARY OFF) SELECT id, notification_snapshot, finished_at FROM scan_jobs
		WHERE engagement_id COLLATE "C"=$1 COLLATE "C" AND kind COLLATE "C"=$2 COLLATE "C" AND status='succeeded' AND id COLLATE "C"<>$3 COLLATE "C"
		AND (finished_at,id COLLATE "C") < ($4,$5 COLLATE "C")
		AND notification_snapshot ? 'target_key' AND jsonb_typeof(notification_snapshot->'target_key')='string' AND notification_snapshot->>'target_key'<>''
		AND md5(notification_snapshot->>'target_key')=md5($6) AND notification_snapshot->>'target_key' COLLATE "C"=$6 COLLATE "C"
		ORDER BY finished_at DESC NULLS LAST, id COLLATE "C" DESC LIMIT 1`, engagementID, ports.TargetGit, "scan-summary-plan-current", time.Now().UTC().Add(time.Hour), "scan-summary-plan-current", targetKey)
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
	if !strings.Contains(strings.Join(plan, "\n"), "idx_scan_jobs_succeeded_notification_modern_predecessor") {
		t.Fatalf("modern predecessor query did not use hash index:\n%s", strings.Join(plan, "\n"))
	}
}

func TestTerminalScanSnapshotLegacyCursorSeeksPastEarlierRows(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("scan-legacy-plan-" + randHex(t))
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,'Legacy scan plan')", tenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", tenant) })
	const engagementID = "scan-legacy-plan-eng"
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Legacy scan plan')", engagementID, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO scan_jobs(id,engagement_id,target,kind,status,stage,progress,started_at,finished_at)
		SELECT 'legacy-plan-' || lpad(n::text,6,'0'),$1,'https://git.example.test/repo/' || n,'git','succeeded','done',100,
			$2::timestamptz - n * interval '1 second',$2::timestamptz - n * interval '1 second'
		FROM generate_series(1,100000) AS n`, engagementID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "ANALYZE scan_jobs"); err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Query(ctx, "EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF) "+scanLegacyPredecessorQuery,
		engagementID, ports.TargetGit, "legacy-plan-current", at.Add(-50048*time.Second), "legacy-plan-050048", scanPredecessorPageSize)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	var cursorSeek bool
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, line)
		cursorSeek = cursorSeek || (strings.Contains(line, "Index Cond:") && strings.Contains(line, "ROW(finished_at"))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !cursorSeek || !strings.Contains(strings.Join(plan, "\n"), "idx_scan_jobs_succeeded_notification_legacy_predecessor") {
		t.Fatalf("legacy cursor must seek past prior pages without filtering their prefix:\n%s", strings.Join(plan, "\n"))
	}
	t.Logf("legacy predecessor plan:\n%s", strings.Join(plan, "\n"))
}

func TestTerminalScanSnapshotFindsModernBaselineBeyondLegacyPages(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("scan-summary-pages-" + randHex(t))
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,'Scan summary')", tenant); err != nil {
		t.Fatal(err)
	}
	const engagementID = "scan-summary-pages-eng"
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Scan summary')", engagementID, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", tenant) })

	store := NewScanJobStore(pool)
	at := time.Now().UTC().Truncate(time.Microsecond)
	target := "https://git.example.test/repo.git"
	targetKey := notification.CanonicalScanTarget(target, ports.TargetGit)
	summary := func(key string) notification.ScanSummary {
		return notification.NewScanSummary(targetKey, ports.TargetGit, true, []finding.Finding{{ID: shared.ID(key), DedupKey: key, Kind: finding.KindSCA, Severity: shared.SeverityHigh}})
	}
	knownFinished := at.Add(time.Second)
	known := ports.ScanJob{ID: "scan-summary-pages-known", EngagementID: engagementID, Target: target, Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &knownFinished, NotificationSnapshot: summary("fixed")}
	if err := store.Save(ctx, known); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		for n := 2; n <= 131; n++ {
			finished := at.Add(time.Duration(n) * time.Second)
			if _, err := tx.Exec(ctx, `INSERT INTO scan_jobs(id,engagement_id,target,kind,status,stage,progress,started_at,finished_at)
				VALUES($1,$2,$3,'git','succeeded','done',100,$4,$4)`, fmt.Sprintf("scan-summary-pages-legacy-%03d", n), engagementID, fmt.Sprintf("unrelated-%03d", n), finished); err != nil {
				return err
			}
		}
		// A malformed target key on an unrelated target is not decoded and
		// cannot prevent reaching the canonical predecessor.
		if _, err := tx.Exec(ctx, `UPDATE scan_jobs SET notification_snapshot='{"target_key":7}'::jsonb WHERE id=$1`, "scan-summary-pages-legacy-131"); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	currentFinished := at.Add(200 * time.Second)
	current := ports.ScanJob{ID: "scan-summary-pages-current", EngagementID: engagementID, Target: target, Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &currentFinished, NotificationSnapshot: summary("new")}
	if err := store.Save(ctx, current); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetJob(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.NotificationSnapshot.DeltaAvailable || got.NotificationSnapshot.BaselineJobID != known.ID || got.NotificationSnapshot.New != 1 || got.NotificationSnapshot.Fixed != 1 {
		t.Fatalf("baseline after legacy pages = %+v", got.NotificationSnapshot)
	}
}

func TestTerminalScanSnapshotDoesNotSkipMatchingLegacyOnLaterPage(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("scan-summary-pages-legacy-" + randHex(t))
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,'Scan summary')", tenant); err != nil {
		t.Fatal(err)
	}
	const engagementID = "scan-summary-pages-legacy-eng"
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Scan summary')", engagementID, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", tenant) })

	store := NewScanJobStore(pool)
	at := time.Now().UTC().Truncate(time.Microsecond)
	target := "https://git.example.test/repo.git"
	targetKey := notification.CanonicalScanTarget(target, ports.TargetGit)
	summary := notification.NewScanSummary(targetKey, ports.TargetGit, true, []finding.Finding{{ID: "fixed", DedupKey: "fixed", Kind: finding.KindSCA, Severity: shared.SeverityHigh}})
	knownFinished := at.Add(time.Second)
	known := ports.ScanJob{ID: "scan-summary-pages-legacy-known", EngagementID: engagementID, Target: target, Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &knownFinished, NotificationSnapshot: summary}
	if err := store.Save(ctx, known); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		for n := 3; n <= 132; n++ {
			finished := at.Add(time.Duration(n) * time.Second)
			if _, err := tx.Exec(ctx, `INSERT INTO scan_jobs(id,engagement_id,target,kind,status,stage,progress,started_at,finished_at)
				VALUES($1,$2,$3,'git','succeeded','done',100,$4,$4)`, fmt.Sprintf("scan-summary-pages-legacy-unrelated-%03d", n), engagementID, fmt.Sprintf("unrelated-%03d", n), finished); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO scan_jobs(id,engagement_id,target,kind,status,stage,progress,started_at,finished_at)
			VALUES('scan-summary-pages-legacy-matching',$1,$2,'git','succeeded','done',100,$3,$3)`, engagementID, target, at.Add(2*time.Second))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	currentFinished := at.Add(200 * time.Second)
	current := ports.ScanJob{ID: "scan-summary-pages-legacy-current", EngagementID: engagementID, Target: target, Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &currentFinished, NotificationSnapshot: notification.NewScanSummary(targetKey, ports.TargetGit, true, []finding.Finding{{ID: "new", DedupKey: "new", Kind: finding.KindSCA, Severity: shared.SeverityHigh}})}
	if err := store.Save(ctx, current); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetJob(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.NotificationSnapshot.DeltaAvailable || got.NotificationSnapshot.BaselineJobID != "" {
		t.Fatalf("matching legacy predecessor was skipped: %+v", got.NotificationSnapshot)
	}
}

func TestTerminalScanSnapshotRejectsStoredIdentityMutationAndFailedSeed(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("scan-summary-admission-" + randHex(t))
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,'Scan summary')", tenant); err != nil {
		t.Fatal(err)
	}
	const engagementID = "scan-summary-admission-eng"
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Scan summary')", engagementID, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", tenant) })

	store := NewScanJobStore(pool)
	at := time.Now().UTC().Truncate(time.Microsecond)
	stored := ports.ScanJob{ID: "scan-summary-admission-stored", EngagementID: engagementID, Target: "repo-a", Kind: ports.TargetLocal, Status: ports.ScanRunning, Stage: "queued", StartedAt: at}
	if err := store.CreateRunning(ctx, stored); err != nil {
		t.Fatal(err)
	}
	finished := at.Add(time.Minute)
	mutated := stored
	mutated.Target, mutated.Status, mutated.Stage, mutated.FinishedAt = "repo-b", ports.ScanSucceeded, "done", &finished
	mutated.NotificationSnapshot = notification.NewScanSummary("repo-b", ports.TargetLocal, true, nil)
	if err := store.Save(ctx, mutated); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("stored identity mutation error = %v, want validation", err)
	}
	failed := ports.ScanJob{ID: "scan-summary-admission-failed", EngagementID: engagementID, Target: "repo-c", Kind: ports.TargetLocal, Status: ports.ScanFailed, Stage: "failed", StartedAt: at, FinishedAt: &finished, NotificationSnapshot: notification.NewScanSummary("repo-c", ports.TargetLocal, true, nil)}
	if err := store.Save(ctx, failed); err != nil {
		t.Fatal(err)
	}
	var snapshot string
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT notification_snapshot::text FROM scan_jobs WHERE id=$1", failed.ID).Scan(&snapshot)
	}); err != nil {
		t.Fatal(err)
	}
	if snapshot != "{}" {
		t.Fatalf("failed first write persisted notification snapshot: %s", snapshot)
	}
}

func TestTerminalScanSnapshotUsesStoredKindForPredecessor(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("scan-summary-stored-kind-" + randHex(t))
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,'Scan summary')", tenant); err != nil {
		t.Fatal(err)
	}
	const engagementID = "scan-summary-stored-kind-eng"
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Scan summary')", engagementID, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", tenant) })

	store := NewScanJobStore(pool)
	at := time.Now().UTC().Truncate(time.Microsecond)
	target := "https://git.example.test/repo.git"
	key := notification.CanonicalScanTarget(target, ports.TargetGit)
	previousFinished := at.Add(time.Minute)
	previous := ports.ScanJob{ID: "scan-summary-stored-kind-previous", EngagementID: engagementID, Target: target, Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &previousFinished,
		NotificationSnapshot: notification.NewScanSummary(key, ports.TargetGit, true, []finding.Finding{{ID: "fixed", DedupKey: "fixed", Kind: finding.KindSCA, Severity: shared.SeverityHigh}})}
	if err := store.Save(ctx, previous); err != nil {
		t.Fatal(err)
	}
	current := ports.ScanJob{ID: "scan-summary-stored-kind-current", EngagementID: engagementID, Target: target, Kind: ports.TargetGit, Status: ports.ScanRunning, Stage: "queued", StartedAt: at}
	if err := store.CreateRunning(ctx, current); err != nil {
		t.Fatal(err)
	}
	finished := at.Add(2 * time.Minute)
	current.Target = "caller-replacement-target"
	current.Kind = ports.TargetLocal
	current.Status, current.Stage, current.FinishedAt = ports.ScanSucceeded, "done", &finished
	current.NotificationSnapshot = notification.NewScanSummary(key, ports.TargetGit, true, []finding.Finding{{ID: "new", DedupKey: "new", Kind: finding.KindSCA, Severity: shared.SeverityHigh}})
	if err := store.Save(ctx, current); err != nil {
		t.Fatalf("save terminal job with stale caller target/kind: %v", err)
	}
	got, err := store.GetJob(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.NotificationSnapshot.DeltaAvailable || got.NotificationSnapshot.BaselineJobID != previous.ID || got.NotificationSnapshot.New != 1 || got.NotificationSnapshot.Fixed != 1 {
		t.Fatalf("stored-kind predecessor was missed: %+v", got.NotificationSnapshot)
	}
}

func TestTerminalScanSnapshotMatchingMalformedLegacyPersistsUnknownDelta(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("scan-summary-malformed-" + randHex(t))
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,'Scan summary')", tenant); err != nil {
		t.Fatal(err)
	}
	const engagementID = "scan-summary-malformed-eng"
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Scan summary')", engagementID, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", tenant) })

	at := time.Now().UTC().Truncate(time.Microsecond)
	target := "https://git.example.test/repo.git"
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO scan_jobs(id,engagement_id,target,kind,status,stage,progress,started_at,finished_at,notification_snapshot)
			VALUES('scan-summary-malformed-legacy',$1,$2,'git','succeeded','done',100,$3,$3,'{"target_key":7}'::jsonb)`, engagementID, target, at)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	finished := at.Add(time.Minute)
	current := ports.ScanJob{ID: "scan-summary-malformed-current", EngagementID: engagementID, Target: target, Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &finished,
		NotificationSnapshot: notification.NewScanSummary(notification.CanonicalScanTarget(target, ports.TargetGit), ports.TargetGit, true, []finding.Finding{{ID: "present", DedupKey: "present", Kind: finding.KindSCA, Severity: shared.SeverityHigh}})}
	if err := NewScanJobStore(pool).Save(ctx, current); err != nil {
		t.Fatalf("save current scan with malformed predecessor: %v", err)
	}
	got, err := NewScanJobStore(pool).GetJob(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.NotificationSnapshot.DeltaAvailable || got.NotificationSnapshot.BaselineJobID != "" || got.NotificationSnapshot.Total != 1 {
		t.Fatalf("malformed matching predecessor did not persist unknown delta: %+v", got.NotificationSnapshot)
	}
}

func TestTerminalScanSnapshotEqualTimeLegacyBlocksOlderModernBaseline(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("scan-summary-equal-time-" + randHex(t))
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,'Scan summary')", tenant); err != nil {
		t.Fatal(err)
	}
	const engagementID = "scan-summary-equal-time-eng"
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Scan summary')", engagementID, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", tenant) })

	store := NewScanJobStore(pool)
	at := time.Now().UTC().Truncate(time.Microsecond)
	target := "https://git.example.test/repo.git"
	key := notification.CanonicalScanTarget(target, ports.TargetGit)
	known := ports.ScanJob{ID: "scan-summary-equal-time-a", EngagementID: engagementID, Target: target, Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &at,
		NotificationSnapshot: notification.NewScanSummary(key, ports.TargetGit, true, []finding.Finding{{ID: "fixed", DedupKey: "fixed", Kind: finding.KindSCA, Severity: shared.SeverityHigh}})}
	if err := store.Save(ctx, known); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO scan_jobs(id,engagement_id,target,kind,status,stage,progress,started_at,finished_at)
			VALUES('scan-summary-equal-time-z',$1,$2,'git','succeeded','done',100,$3,$3)`, engagementID, target, at)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	finished := at.Add(time.Minute)
	current := ports.ScanJob{ID: "scan-summary-equal-time-current", EngagementID: engagementID, Target: target, Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &finished,
		NotificationSnapshot: notification.NewScanSummary(key, ports.TargetGit, true, []finding.Finding{{ID: "new", DedupKey: "new", Kind: finding.KindSCA, Severity: shared.SeverityHigh}})}
	if err := store.Save(ctx, current); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetJob(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.NotificationSnapshot.DeltaAvailable || got.NotificationSnapshot.BaselineJobID != "" {
		t.Fatalf("equal-time legacy predecessor was skipped: %+v", got.NotificationSnapshot)
	}
}

func TestTerminalScanSnapshotPrefersNewerModernOverOlderMatchingLegacy(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("scan-summary-modern-wins-" + randHex(t))
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,'Scan summary')", tenant); err != nil {
		t.Fatal(err)
	}
	const engagementID = "scan-summary-modern-wins-eng"
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Scan summary')", engagementID, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", tenant) })

	store := NewScanJobStore(pool)
	at := time.Now().UTC().Truncate(time.Microsecond)
	target := "https://git.example.test/repo.git"
	key := notification.CanonicalScanTarget(target, ports.TargetGit)
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO scan_jobs(id,engagement_id,target,kind,status,stage,progress,started_at,finished_at)
			VALUES('scan-summary-modern-wins-legacy',$1,$2,'git','succeeded','done',100,$3,$3)`, engagementID, target, at)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	modernFinished := at.Add(time.Minute)
	modern := ports.ScanJob{ID: "scan-summary-modern-wins-modern", EngagementID: engagementID, Target: target, Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &modernFinished,
		NotificationSnapshot: notification.NewScanSummary(key, ports.TargetGit, true, []finding.Finding{{ID: "fixed", DedupKey: "fixed", Kind: finding.KindSCA, Severity: shared.SeverityHigh}})}
	if err := store.Save(ctx, modern); err != nil {
		t.Fatal(err)
	}
	currentFinished := modernFinished.Add(time.Minute)
	current := ports.ScanJob{ID: "scan-summary-modern-wins-current", EngagementID: engagementID, Target: target, Kind: ports.TargetGit, Status: ports.ScanSucceeded, Stage: "done", StartedAt: at, FinishedAt: &currentFinished,
		NotificationSnapshot: notification.NewScanSummary(key, ports.TargetGit, true, []finding.Finding{{ID: "new", DedupKey: "new", Kind: finding.KindSCA, Severity: shared.SeverityHigh}})}
	if err := store.Save(ctx, current); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetJob(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.NotificationSnapshot.DeltaAvailable || got.NotificationSnapshot.BaselineJobID != modern.ID || got.NotificationSnapshot.New != 1 || got.NotificationSnapshot.Fixed != 1 {
		t.Fatalf("older legacy hid newer modern baseline: %+v", got.NotificationSnapshot)
	}
}

func incompressibleScanTarget() string {
	var b strings.Builder
	b.Grow(len("https://git.example.test/") + 8192)
	b.WriteString("https://git.example.test/")
	state := uint64(0x9e3779b97f4a7c15)
	const digits = "0123456789abcdef"
	for range 8192 {
		state = state*6364136223846793005 + 1442695040888963407
		b.WriteByte(digits[(state>>60)&0xf])
	}
	return b.String()
}
