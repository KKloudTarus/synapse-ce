package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
)

func TestMigration0191TenantSettingsSchema(t *testing.T) {
	_, db := ownershipTestDatabase(t, 186, nil)
	requireMigrationTable(t, db, "tenant_settings", true)
	requireMigrationRLS(t, db, "tenant_settings")
	if _, err := db.Exec(`INSERT INTO tenants(id, name) VALUES ('t-schema', 'Schema') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct{ name, locale, zone string }{
		{"free-text locale", "fr", "UTC"},
		{"empty zone", "en", ""},
		{"server-local zone", "en", "Local"},
		{"zone with a path traversal", "en", "../etc/passwd"},
	} {
		if _, err := db.Exec(`INSERT INTO tenant_settings(tenant_id, default_locale, time_zone, revision, updated_at, updated_by)
			VALUES ('t-schema', $1, $2, 1, now(), 'admin')`, bad.locale, bad.zone); err == nil {
			t.Errorf("%s: the CHECK accepted locale %q zone %q", bad.name, bad.locale, bad.zone)
		}
	}
	if err := goose.DownTo(db, ".", 186); err != nil {
		t.Fatalf("migrate down: %v", err)
	}
	requireMigrationTable(t, db, "tenant_settings", false)
}

// TestTenantSettingsStoreIsTenantIsolated is the hostile case: under the runtime role, which does
// not bypass RLS, a tenant can neither read nor overwrite another tenant's settings.
func TestTenantSettingsStoreIsTenantIsolated(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 186, nil)
	for _, id := range []string{"t-a", "t-b"} {
		if _, err := db.Exec(`INSERT INTO tenants(id, name) VALUES ($1, $1) ON CONFLICT DO NOTHING`, id); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	store := NewTenantSettingsStore(pool)
	at := time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC)

	if _, found, err := store.GetTenantSettings(ctx, "t-a"); err != nil || found {
		t.Fatalf("a tenant that never saved: found=%v err=%v", found, err)
	}
	saved, err := store.SaveTenantSettings(ctx, tenancy.Settings{TenantID: "t-a", DefaultLocale: "vi", TimeZone: "Asia/Ho_Chi_Minh", UpdatedAt: at, UpdatedBy: "admin"}, 0)
	if err != nil || saved.Revision != 1 {
		t.Fatalf("first save = %+v, %v", saved, err)
	}
	got, found, err := store.GetTenantSettings(ctx, "t-a")
	if err != nil || !found || got.DefaultLocale != "vi" || got.TimeZone != "Asia/Ho_Chi_Minh" || got.Revision != 1 || got.UpdatedBy != "admin" {
		t.Fatalf("read back = %+v found=%v err=%v", got, found, err)
	}
	if _, found, err := store.GetTenantSettings(ctx, "t-b"); err != nil || found {
		t.Fatalf("tenant t-b read tenant t-a's row: found=%v err=%v", found, err)
	}

	// Stale revisions are refused on both the insert and the update path.
	if _, err := store.SaveTenantSettings(ctx, tenancy.Settings{TenantID: "t-a", DefaultLocale: "en", TimeZone: "UTC", UpdatedAt: at, UpdatedBy: "other"}, 0); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("second first-save: want ErrConflict, got %v", err)
	}
	if _, err := store.SaveTenantSettings(ctx, tenancy.Settings{TenantID: "t-a", DefaultLocale: "en", TimeZone: "UTC", UpdatedAt: at, UpdatedBy: "other"}, 7); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale update: want ErrConflict, got %v", err)
	}
	updated, err := store.SaveTenantSettings(ctx, tenancy.Settings{TenantID: "t-a", DefaultLocale: "en", TimeZone: "Europe/Berlin", UpdatedAt: at, UpdatedBy: "other"}, 1)
	if err != nil || updated.Revision != 2 {
		t.Fatalf("update = %+v, %v", updated, err)
	}

	// Under tenant t-b's session a direct write naming t-a is refused by the policy's WITH CHECK,
	// and an update of t-a's row matches nothing.
	err = WithTenant(ctx, pool, "t-b", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO tenant_settings(tenant_id, default_locale, time_zone, revision, updated_at, updated_by)
			VALUES ('t-a', 'en', 'UTC', 9, now(), 'intruder')`)
		return err
	})
	if err == nil {
		t.Fatal("tenant t-b inserted a row for tenant t-a")
	}
	err = WithTenant(ctx, pool, "t-b", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE tenant_settings SET time_zone='UTC', updated_by='intruder' WHERE tenant_id='t-a'`)
		if err == nil && tag.RowsAffected() != 0 {
			t.Errorf("tenant t-b updated %d of tenant t-a's rows", tag.RowsAffected())
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _, err = store.GetTenantSettings(ctx, "t-a")
	if err != nil || got.TimeZone != "Europe/Berlin" || got.UpdatedBy != "other" {
		t.Fatalf("tenant t-a's row changed under another tenant: %+v, %v", got, err)
	}
}
