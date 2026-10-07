package postgres

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
)

func TestMigration0219EngineOutcomesRollsBackOnlyWhenNoEvidenceExists(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 219, 218)
	db := isolated.db
	if err := goose.UpTo(db, ".", 219); err != nil {
		t.Fatalf("apply engine outcomes migration: %v", err)
	}
	for _, table := range []string{"scan_run_lanes", "scan_jobs"} {
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name='engine_outcomes')`, table).Scan(&exists); err != nil || !exists {
			t.Fatalf("%s.engine_outcomes exists=%t err=%v", table, exists, err)
		}
	}

	// Empty defaults are reversible, and reapplying starts with the same empty evidence state.
	if err := goose.DownTo(db, ".", 218); err != nil {
		t.Fatalf("roll back empty engine outcomes migration: %v", err)
	}
	if err := goose.UpTo(db, ".", 219); err != nil {
		t.Fatalf("reapply engine outcomes migration: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO scan_jobs (id, engagement_id, target, kind, status, stage, progress, started_at, engine_outcomes) VALUES ('engine-outcomes-migration-job', 'migration-engagement', 'repo', 'git', 'succeeded', 'done', 100, now(), '[{"engine":"sast","execution":"completed","coverage":"complete","required":true}]'::jsonb)`); err != nil {
		t.Fatalf("insert recorded engine outcome: %v", err)
	}
	if err := goose.DownTo(db, ".", 218); err == nil {
		t.Fatal("rollback removed recorded engine outcomes instead of refusing the destructive operation")
	}
}

func TestMigration0219RollbackWaitsForConcurrentEvidenceBeforeRefusing(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 219, 218)
	db := isolate.db
	if err := goose.UpTo(db, ".", 219); err != nil {
		t.Fatalf("apply engine outcomes migration: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	writer, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("reserve evidence writer connection: %v", err)
	}
	defer writer.Close()
	writerTx, err := writer.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin evidence writer transaction: %v", err)
	}
	defer writerTx.Rollback()
	const jobID = "engine-outcomes-concurrent-migration-job"
	if _, err := writerTx.ExecContext(ctx, `INSERT INTO scan_jobs (id, engagement_id, target, kind, status, stage, progress, started_at, engine_outcomes) VALUES ($1, 'migration-engagement', 'repo', 'git', 'succeeded', 'done', 100, now(), '[{"engine":"sast","execution":"completed","coverage":"complete","required":true}]'::jsonb)`, jobID); err != nil {
		t.Fatalf("record uncommitted engine outcome: %v", err)
	}

	downResult := make(chan error, 1)
	go func() {
		downResult <- goose.DownTo(db, ".", 218)
	}()
	waitForMigration0219ExclusiveLock(t, ctx, db)

	if err := writerTx.Commit(); err != nil {
		t.Fatalf("commit recorded engine outcome: %v", err)
	}
	select {
	case err := <-downResult:
		if err == nil || !strings.Contains(err.Error(), "cannot remove recorded scan engine outcomes") {
			t.Fatalf("rollback error = %v, want recorded engine outcome refusal", err)
		}
	case <-ctx.Done():
		t.Fatalf("rollback did not finish after the concurrent evidence commit: %v", ctx.Err())
	}

	for _, table := range []string{"scan_run_lanes", "scan_jobs"} {
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name='engine_outcomes')`, table).Scan(&exists); err != nil || !exists {
			t.Fatalf("%s.engine_outcomes exists=%t err=%v after rejected rollback", table, exists, err)
		}
	}
	var outcomes string
	if err := db.QueryRow(`SELECT engine_outcomes::text FROM scan_jobs WHERE id=$1`, jobID).Scan(&outcomes); err != nil {
		t.Fatalf("load committed engine outcome after rejected rollback: %v", err)
	}
	if outcomes == "[]" {
		t.Fatal("rejected rollback erased the committed engine outcome")
	}
}

func waitForMigration0219ExclusiveLock(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	const query = `SELECT EXISTS (
		SELECT 1
		FROM pg_locks
		WHERE relation = 'scan_jobs'::regclass
		  AND mode = 'AccessExclusiveLock'
		  AND NOT granted
	)`
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := db.QueryRowContext(ctx, query).Scan(&waiting); err != nil {
			t.Fatalf("inspect migration lock request: %v", err)
		}
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("rollback never requested an exclusive scan_jobs lock: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}
