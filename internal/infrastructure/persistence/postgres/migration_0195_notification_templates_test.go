package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/testutil/notificationtemplatetest"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const templateChecksum = "0000000000000000000000000000000000000000000000000000000000000000"

func TestMigration0195NotificationTemplatesSchema(t *testing.T) {
	_, db := ownershipTestDatabase(t, 194, nil)
	for _, table := range []string{"notification_templates", "notification_template_versions"} {
		requireMigrationTable(t, db, table, true)
		requireMigrationRLS(t, db, table)
	}
	requireMigrationIndexes(t, db, "notification_templates_one_active")
	if _, err := db.Exec(`INSERT INTO tenants(id, name) VALUES ('t-schema', 'Schema') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	// The owner connection bypasses nothing here: RLS is forced, so writes run under the tenant.
	exec := func(query string, args ...any) error {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SELECT set_config('app.current_tenant', 't-schema', true)`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(query, args...); err != nil {
			return err
		}
		return tx.Commit()
	}
	insertHead := func(id, event, family, locale string) error {
		return exec(`INSERT INTO notification_templates(tenant_id, id, name, event_type, family, locale, latest_version, revision, created_at, created_by, updated_at, updated_by)
			VALUES ('t-schema', $1, 'Name', $2, $3, $4, 1, 1, now(), 'admin', now(), 'admin')`, id, event, family, locale)
	}
	insertVersion := func(id string, version int, fields string) error {
		return exec(`INSERT INTO notification_template_versions(tenant_id, template_id, version, fields, checksum, created_at, created_by)
			VALUES ('t-schema', $1, $2, $3::jsonb, $4, now(), 'admin')`, id, version, fields, templateChecksum)
	}

	for _, bad := range []struct{ name, event, family, locale string }{
		{"malformed event type", "Scan Completed", "chat", "en"},
		{"event type without a dot", "scan", "chat", "en"},
		{"free-text family", "scan.completed", "sms", "en"},
		{"unsupported locale", "scan.completed", "chat", "fr"},
		{"region-tagged locale", "scan.completed", "chat", "en-US"},
	} {
		if err := insertHead("tpl-bad", bad.event, bad.family, bad.locale); err == nil {
			t.Errorf("%s: the CHECK accepted it", bad.name)
		}
	}
	// A well-formed event type outside today's catalog is the application's call, not the schema's.
	for i, event := range []string{"scan.completed", "*", "future_event.created"} {
		if err := insertHead(fmt.Sprintf("tpl-%d", i), event, "chat", "*"); err != nil {
			t.Fatalf("event type %q: %v", event, err)
		}
	}
	for _, bad := range []struct{ name, fields string }{
		{"array", `["title"]`},
		{"empty object", `{}`},
		{"non-string value", `{"title": 1}`},
		{"nested value", `{"title": {"x": "y"}}`},
		{"malformed key", `{"Title": "x"}`},
	} {
		if err := insertVersion("tpl-0", 1, bad.fields); err == nil {
			t.Errorf("fields %s: the CHECK accepted %s", bad.name, bad.fields)
		}
	}
	if err := insertVersion("tpl-0", 1, `{"title": "v1", "body": "b"}`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`UPDATE notification_templates SET status='active', revision=2 WHERE id='tpl-0'`); err == nil {
		t.Error("an active template without an active version was accepted")
	}
	if err := exec(`UPDATE notification_templates SET status='active', active_version=2, revision=2 WHERE id='tpl-0'`); err == nil {
		t.Error("an active version past the latest version was accepted")
	}

	// Versions are append-only, even for the table owner.
	for _, q := range []string{
		`UPDATE notification_template_versions SET fields='{"title":"rewritten"}' WHERE template_id='tpl-0'`,
		`UPDATE notification_template_versions SET created_by='someone' WHERE template_id='tpl-0'`,
		`DELETE FROM notification_template_versions WHERE template_id='tpl-0'`,
	} {
		if err := exec(q); err == nil {
			t.Errorf("append-only guard allowed %s", q)
		}
	}
	// The key is immutable and a template with versions cannot be deleted.
	for _, q := range []string{
		`UPDATE notification_templates SET event_type='incident.created', revision=2 WHERE id='tpl-0'`,
		`UPDATE notification_templates SET locale='vi', revision=2 WHERE id='tpl-0'`,
		`UPDATE notification_templates SET name='x', revision=1 WHERE id='tpl-0'`,
		`DELETE FROM notification_templates WHERE id='tpl-0'`,
	} {
		if err := exec(q); err == nil {
			t.Errorf("template guard allowed %s", q)
		}
	}

	// Acceptance: two active templates for one key are refused by the database itself.
	if err := insertVersion("tpl-1", 1, `{"title": "star"}`); err != nil {
		t.Fatal(err)
	}
	if err := insertVersion("tpl-2", 1, `{"title": "future"}`); err != nil {
		t.Fatal(err)
	}
	if err := insertHead("tpl-dup", "*", "chat", "*"); err != nil {
		t.Fatal(err)
	}
	if err := insertVersion("tpl-dup", 1, `{"title": "dup"}`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`UPDATE notification_templates SET status='active', active_version=1, revision=2 WHERE id='tpl-1'`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`UPDATE notification_templates SET status='active', active_version=1, revision=2 WHERE id='tpl-dup'`); err == nil {
		t.Fatal("a second active template for (t-schema, *, chat, *) was accepted")
	}
	if err := exec(`UPDATE notification_templates SET status='active', active_version=1, revision=2 WHERE id='tpl-2'`); err != nil {
		t.Fatalf("another key may have its own active template: %v", err)
	}

	if err := goose.DownTo(db, ".", 194); err != nil {
		t.Fatalf("migrate down: %v", err)
	}
	requireMigrationTable(t, db, "notification_templates", false)
	requireMigrationTable(t, db, "notification_template_versions", false)
	var functions int
	if err := db.QueryRow(`SELECT count(*) FROM pg_proc WHERE proname IN ('notification_template_version_immutable', 'notification_template_head_guard')`).Scan(&functions); err != nil || functions != 0 {
		t.Fatalf("down left %d functions: %v", functions, err)
	}
}

func TestNotificationTemplateStoreConformancePostgres(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 194, nil)
	for _, id := range []shared.ID{notificationtemplatetest.TenantA, notificationtemplatetest.TenantB} {
		if _, err := db.Exec(`INSERT INTO tenants(id, name) VALUES ($1, $1) ON CONFLICT DO NOTHING`, id); err != nil {
			t.Fatal(err)
		}
	}
	notificationtemplatetest.Run(t, func(t *testing.T) ports.NotificationTemplateStore {
		// TRUNCATE fires no row triggers, so the owner can reset the append-only table between cases.
		// CASCADE also empties notification_channels, whose template binding (0200) references
		// notification_templates; the conformance cases create no channel.
		if _, err := db.Exec(`TRUNCATE notification_template_versions, notification_templates CASCADE`); err != nil {
			t.Fatal(err)
		}
		return NewNotificationTemplateStore(pool)
	})
}

// TestNotificationTemplateStoreIsTenantIsolated is the hostile case: under the runtime role, which
// does not bypass RLS, tenant t-b can neither read, write nor activate tenant t-a's templates, even
// with raw SQL that names t-a.
func TestNotificationTemplateStoreIsTenantIsolated(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 194, nil)
	for _, id := range []string{"t-a", "t-b"} {
		if _, err := db.Exec(`INSERT INTO tenants(id, name) VALUES ($1, $1) ON CONFLICT DO NOTHING`, id); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	store := NewNotificationTemplateStore(pool)
	at := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	key := notification.TemplateKey{EventType: notification.EventScanCompleted, Family: notification.FamilyChat, Locale: "en"}
	if _, _, err := store.CreateNotificationTemplate(ctx, notification.Template{TenantID: "t-a", ID: "tpl-a", Name: "A", TemplateKey: key, CreatedAt: at, CreatedBy: "admin"},
		map[string]string{"title": "secret wording of tenant a"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ActivateNotificationTemplate(ctx, ports.NotificationTemplateChange{TenantID: "t-a", ID: "tpl-a", ExpectedRevision: 1, Actor: "admin", At: at}); err != nil {
		t.Fatal(err)
	}

	// Acceptance: a cross-tenant read fails through the store.
	if _, err := store.GetNotificationTemplate(ctx, "t-b", "tpl-a"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("tenant t-b read tenant t-a's template: %v", err)
	}
	if _, err := store.GetNotificationTemplateVersion(ctx, "t-b", "tpl-a", 1); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("tenant t-b read tenant t-a's version: %v", err)
	}

	// Raw SQL under t-b's session sees nothing and changes nothing.
	err := WithTenant(ctx, pool, "t-b", func(tx pgx.Tx) error {
		var visible int
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM notification_templates) + (SELECT count(*) FROM notification_template_versions)`).Scan(&visible); err != nil {
			return err
		}
		if visible != 0 {
			t.Errorf("tenant t-b sees %d of tenant t-a's rows", visible)
		}
		tag, err := tx.Exec(ctx, `UPDATE notification_templates SET status='archived', revision=revision+1 WHERE tenant_id='t-a'`)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 0 {
			t.Errorf("tenant t-b archived %d of tenant t-a's templates", tag.RowsAffected())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, q := range map[string]string{
		"template": `INSERT INTO notification_templates(tenant_id, id, name, event_type, family, locale, latest_version, revision, created_at, created_by, updated_at, updated_by)
			VALUES ('t-a', 'tpl-evil', 'Evil', 'scan.completed', 'chat', 'en', 1, 1, now(), 'intruder', now(), 'intruder')`,
		"version": `INSERT INTO notification_template_versions(tenant_id, template_id, version, fields, checksum, created_at, created_by)
			VALUES ('t-a', 'tpl-a', 2, '{"title":"injected"}', '` + templateChecksum + `', now(), 'intruder')`,
	} {
		err := WithTenant(ctx, pool, "t-b", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, q)
			return err
		})
		if err == nil {
			t.Errorf("tenant t-b inserted a %s row for tenant t-a", name)
		}
	}
	head, v, found, err := store.ActiveNotificationTemplate(ctx, "t-a", key)
	if err != nil || !found || head.Status != notification.TemplateActive || head.Revision != 2 || head.LatestVersion != 1 || v.Fields["title"] != "secret wording of tenant a" {
		t.Fatalf("tenant t-a's template changed under tenant t-b: %+v %+v found=%v err=%v", head, v, found, err)
	}
}

// TestNotificationTemplateConcurrentActivationKeepsOneActive races activations of different
// templates for one key. Each either wins, archiving the one before it, or is refused with
// ErrConflict when the unique index catches it; the key never ends with two active templates.
func TestNotificationTemplateConcurrentActivationKeepsOneActive(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 194, nil)
	if _, err := db.Exec(`INSERT INTO tenants(id, name) VALUES ('t-race', 'Race') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store := NewNotificationTemplateStore(pool)
	at := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	key := notification.TemplateKey{EventType: notification.EventIncidentCreated, Family: notification.FamilyPager, Locale: "vi"}
	const racers = 6
	for i := 0; i < racers; i++ {
		if _, _, err := store.CreateNotificationTemplate(ctx, notification.Template{TenantID: "t-race", ID: shared.ID(fmt.Sprintf("tpl-%d", i)), Name: "Race", TemplateKey: key, CreatedAt: at, CreatedBy: "admin"},
			map[string]string{"summary": "incident"}); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make([]error, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, errs[i] = store.ActivateNotificationTemplate(ctx, ports.NotificationTemplateChange{TenantID: "t-race", ID: shared.ID(fmt.Sprintf("tpl-%d", i)), ExpectedRevision: 1, Actor: "admin", At: at})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil && !errors.Is(err, shared.ErrConflict) {
			t.Errorf("racer %d: want success or ErrConflict, got %v", i, err)
		}
	}
	active, err := store.ListNotificationTemplates(ctx, "t-race", ports.NotificationTemplateQuery{Status: notification.TemplateActive})
	if err != nil || len(active) != 1 {
		t.Fatalf("after the race %d templates are active (err=%v), want exactly 1", len(active), err)
	}
}
