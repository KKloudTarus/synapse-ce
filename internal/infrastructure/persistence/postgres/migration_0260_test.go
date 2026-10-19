package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0260(t *testing.T) {
	testMigrationRoundTrip(t, 260, func(t *testing.T, db *sql.DB) {
		requireMigrationColumn(t, db, "scan_jobs", "purpose")
		requireMigrationConstraint(t, db, "scan_jobs", "scan_jobs_purpose_known")
		requireMigrationTrigger(t, db, "scan_jobs", "scan_jobs_immutable_purpose")
		requireMigrationIndexes(t, db, "idx_scan_jobs_project_analysis_latest")
	})
}
