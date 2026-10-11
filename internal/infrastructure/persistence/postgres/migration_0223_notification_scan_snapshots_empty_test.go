package postgres

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0223RollbackAllowsOnlyEmptySnapshots(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 223, 222)
	db := isolate.db
	if err := goose.UpTo(db, ".", 223); err != nil {
		t.Fatalf("apply notification snapshot migration: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO scan_jobs (id,engagement_id,target,kind,status,stage,progress,started_at)
		VALUES ('notification-snapshot-running-job','migration-engagement','repo','git','running','queued',0,now())`); err != nil {
		t.Fatalf("record empty notification snapshot: %v", err)
	}
	if err := goose.DownTo(db, ".", 222); err != nil {
		t.Fatalf("rollback empty notification snapshots: %v", err)
	}
	var predecessorIndex sql.NullString
	if err := db.QueryRow(`SELECT to_regclass('idx_scan_jobs_succeeded_predecessor')::text`).Scan(&predecessorIndex); err != nil {
		t.Fatalf("read predecessor index after rollback: %v", err)
	}
	if predecessorIndex.Valid {
		t.Fatalf("predecessor index remains after rollback: %q", predecessorIndex.String)
	}
}
