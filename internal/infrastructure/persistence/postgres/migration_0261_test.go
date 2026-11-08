package postgres

import (
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0261DocumentRestrictionMonitorUpgradeRollbackAndReapply(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 261, 260)
	if err := goose.UpTo(isolate.db, ".", 261); err != nil {
		t.Fatal(err)
	}
	requireMigrationRLS(t, isolate.db, "document_links")
	requireMigrationIndexes(t, isolate.db, "document_links_restriction_due_idx")
	if err := goose.DownTo(isolate.db, ".", 260); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpTo(isolate.db, ".", 261); err != nil {
		t.Fatal(err)
	}
	requireMigrationIndexes(t, isolate.db, "document_links_restriction_due_idx")
}
