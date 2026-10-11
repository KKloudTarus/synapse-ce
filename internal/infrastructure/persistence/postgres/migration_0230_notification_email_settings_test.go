package postgres

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0230NotificationEmailSettingsUsesTenantRLSAndSealedRelay(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0230_notification_email_settings.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, table := range []string{"notification_email_settings", "notification_email_domains"} {
		if !strings.Contains(sql, "CREATE TABLE "+table) || !strings.Contains(sql, "CALL synapse_enable_tenant_rls('"+table+"')") {
			t.Fatalf("missing tenant RLS table %s", table)
		}
	}
	for _, invariant := range []string{"sealed TEXT NOT NULL", "port IN (465,587)", "PRIMARY KEY (tenant_id,domain)"} {
		if !strings.Contains(sql, invariant) {
			t.Fatalf("migration missing %q", invariant)
		}
	}
}
