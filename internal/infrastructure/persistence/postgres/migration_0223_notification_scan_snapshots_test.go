package postgres

import (
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0223RollbackRefusesRecordedNotificationSnapshots(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 223, 222)
	db := isolate.db
	if err := goose.UpTo(db, ".", 223); err != nil {
		t.Fatalf("apply notification snapshot migration: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO scan_jobs (id,engagement_id,target,kind,status,stage,progress,started_at,notification_snapshot)
		VALUES ('notification-snapshot-migration-job','migration-engagement','repo','git','succeeded','done',100,now(),'{"target_key":"repo"}'::jsonb)`); err != nil {
		t.Fatalf("record notification snapshot: %v", err)
	}
	if err := goose.DownTo(db, ".", 222); err == nil || !strings.Contains(err.Error(), "cannot remove recorded scan notification snapshots") {
		t.Fatalf("rollback error = %v, want recorded notification snapshot refusal", err)
	}
	var snapshot string
	if err := db.QueryRow(`SELECT notification_snapshot::text FROM scan_jobs WHERE id='notification-snapshot-migration-job'`).Scan(&snapshot); err != nil {
		t.Fatalf("load recorded notification snapshot after rejected rollback: %v", err)
	}
	if snapshot == "{}" {
		t.Fatal("rejected rollback erased the recorded notification snapshot")
	}
}
