package postgres

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func deleteV2AuditRowsForMigrationRollback(t *testing.T, db *sql.DB) {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'audit_log' AND column_name = 'hash_version'
	)`).Scan(&exists); err != nil {
		t.Fatalf("check audit migration state: %v", err)
	}
	if !exists {
		return
	}
	if _, err := db.Exec(`SET session_replication_role = replica`); err != nil {
		t.Fatalf("disable audit append-only trigger for intentional historical rollback: %v", err)
	}
	defer func() {
		if _, err := db.Exec(`SET session_replication_role = origin`); err != nil {
			t.Errorf("restore audit append-only trigger: %v", err)
		}
	}()
	if _, err := db.Exec(`DELETE FROM audit_log WHERE hash_version = 2`); err != nil {
		t.Fatalf("clear v2 audit rows before intentional historical rollback: %v", err)
	}
}

func TestMigration0088ProposalAndPromotionAuditStatusAreImmutable(t *testing.T) {
	migration, err := migrations.FS.ReadFile("0088_judgment_proposal_audit_and_promotion_hardening.sql")
	if err != nil {
		t.Fatalf("read migration 0088: %v", err)
	}
	text := string(migration)
	for _, required := range []string{
		"judgment_proposal_audit_status", "finding_promotion_audit_status", "FOR SELECT", "FOR INSERT", "FOR UPDATE", "BEFORE UPDATE OR DELETE", "BEFORE TRUNCATE",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("migration 0088 lacks %q", required)
		}
	}
	if strings.Contains(text, "FOR ALL") || strings.Contains(text, "FOR DELETE") {
		t.Fatal("migration 0088 permits broad or delete RLS policy")
	}
}
