package postgres

import (
	"context"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0261DocumentRestrictionMonitorUpgradeRollbackAndReapply(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 261, 260)
	if err := Migrate(context.Background(), isolate.dsn); err != nil {
		t.Fatal(err)
	}
	requireMigrationRLS(t, isolate.db, "document_links")
	requireMigrationIndexes(t, isolate.db, "document_links_restriction_due_idx")
	if err := goose.DownTo(isolate.db, ".", 260); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(context.Background(), isolate.dsn); err != nil {
		t.Fatal(err)
	}
	requireMigrationIndexes(t, isolate.db, "document_links_restriction_due_idx")
}
