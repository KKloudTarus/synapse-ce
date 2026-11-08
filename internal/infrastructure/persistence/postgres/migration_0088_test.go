package postgres

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

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
