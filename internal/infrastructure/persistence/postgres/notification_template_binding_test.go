package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
)

// Channel template binding (#1371, migration 0200) over PostgreSQL: the binding and locale persist
// through create, update, get, list and LoadWork; the database refuses a template of another
// family or another tenant; RLS hides a bound channel from another tenant; and resolution reads the
// tenant default locale from the settings store.
func TestNotificationTemplateBindingPostgres(t *testing.T) {
	pool := notificationTestPool(t)
	ctxA := shared.WithTenant(context.Background(), "bind-a")
	ctxB := shared.WithTenant(context.Background(), "bind-b")
	if _, err := pool.Exec(ctxA, "INSERT INTO tenants(id,name) VALUES('bind-a','A'),('bind-b','B')"); err != nil {
		t.Fatal(err)
	}
	var forced bool
	if err := pool.QueryRow(ctxA, `SELECT relforcerowsecurity FROM pg_class WHERE oid='notification_channels'::regclass`).Scan(&forced); err != nil || !forced {
		t.Fatalf("notification_channels forced RLS = %v err=%v", forced, err)
	}
	cipher, _ := vault.NewCipher([]byte(strings.Repeat("k", 32)))
	repo := NewNotificationRepository(pool)
	svc, err := notificationuc.NewService(repo, cipher, nil, NewAuditLog(pool), &notificationTestClock{time.Now().UTC().Truncate(time.Microsecond)}, &notificationTestIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTransactionRunner(NewTenantTransactionRunner(pool))
	svc.SetTemplateStore(NewNotificationTemplateStore(pool))
	settings := NewTenantSettingsStore(pool)
	svc.SetTenantSettings(settings)

	activate := func(ctx context.Context, in notificationuc.TemplateInput) notification.Template {
		t.Helper()
		created, err := svc.CreateTemplate(ctx, "ada", in)
		if err != nil {
			t.Fatal(err)
		}
		active, err := svc.ActivateTemplate(ctx, "ada", created.ID, notificationuc.TemplateChangeInput{Revision: created.Revision})
		if err != nil {
			t.Fatal(err)
		}
		return active.Template
	}
	chatAny := activate(ctxA, notificationuc.TemplateInput{Name: "Chat", EventType: notification.AnyEventType, Family: notification.FamilyChat, Locale: "*",
		Fields: map[string]string{"title": "Synapse", "body": "Open Synapse."}})
	emailAny := activate(ctxA, notificationuc.TemplateInput{Name: "Mail", EventType: notification.AnyEventType, Family: notification.FamilyEmail, Locale: "*",
		Fields: map[string]string{"subject": "Synapse", "body": "Open Synapse."}})
	chatB := activate(ctxB, notificationuc.TemplateInput{Name: "Chat B", EventType: notification.AnyEventType, Family: notification.FamilyChat, Locale: "*",
		Fields: map[string]string{"title": "B", "body": "B"}})

	id := chatAny.ID
	locale := tenancy.Locale("vi")
	channel, err := svc.CreateChannel(ctxA, "ada", notificationuc.ChannelInput{Name: "ops", Type: notification.ChannelSlack, Enabled: true,
		URL: "https://hooks.slack.com/services/T/B/X", TemplateID: &id, Locale: &locale})
	if err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetChannel(ctxA, "bind-a", channel.ID)
	if err != nil || got.TemplateID != chatAny.ID || got.Locale != "vi" {
		t.Fatalf("get = %+v err=%v", got.TemplateBinding, err)
	}
	listed, err := repo.ListChannels(ctxA, "bind-a")
	if err != nil || len(listed) != 1 || listed[0].TemplateBinding != got.TemplateBinding {
		t.Fatalf("list = %+v err=%v", listed, err)
	}
	resolution, err := svc.ResolveTemplate(context.Background(), "bind-a", channel.ID, notification.EventScanCompleted)
	if err != nil || resolution.Tier != notificationuc.TierChannel || resolution.Locale != "vi" || resolution.Template.ID != chatAny.ID || resolution.Version == nil {
		t.Fatalf("resolution = %+v err=%v", resolution, err)
	}

	// LoadWork carries the binding to the worker, for the send-time renderer (#1365).
	delivery, err := svc.TestChannel(ctxA, "ada", channel.ID)
	if err != nil {
		t.Fatal(err)
	}
	work, err := repo.LoadWork(ctxA, "bind-a", delivery)
	if err != nil || work.Channel.TemplateID != chatAny.ID || work.Channel.Locale != "vi" {
		t.Fatalf("work channel = %+v err=%v", work.Channel.TemplateBinding, err)
	}

	// Unbinding clears both columns; the tenant default locale then applies.
	empty, emptyLocale := shared.ID(""), tenancy.Locale("")
	updated, err := svc.UpdateChannel(ctxA, "ada", channel.ID, notificationuc.ChannelInput{Name: "ops", Enabled: true, Revision: got.Revision, TemplateID: &empty, Locale: &emptyLocale})
	if err != nil || updated.TemplateID != "" || updated.Locale != "" {
		t.Fatalf("unbind = %+v err=%v", updated.TemplateBinding, err)
	}
	if _, err := settings.SaveTenantSettings(ctxA, tenancy.Settings{TenantID: "bind-a", DefaultLocale: "vi", TimeZone: "UTC", UpdatedAt: time.Now().UTC(), UpdatedBy: "ada"}, 0); err != nil {
		t.Fatal(err)
	}
	resolution, err = svc.ResolveTemplate(context.Background(), "bind-a", channel.ID, notification.EventScanCompleted)
	if err != nil || resolution.Tier != notificationuc.TierTenantWildcard || resolution.Locale != "vi" || resolution.LocaleSource != notificationuc.LocaleFromTenant {
		t.Fatalf("unbound resolution = %+v err=%v", resolution, err)
	}

	// The database refuses a template of another family and a template of another tenant, even
	// when the API is bypassed.
	for name, template := range map[string]shared.ID{"other family": emailAny.ID, "other tenant": chatB.ID, "unknown": "missing"} {
		err := WithTenant(ctxA, pool, "bind-a", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctxA, `UPDATE notification_channels SET template_id=$3 WHERE tenant_id=$1 AND id=$2`, "bind-a", channel.ID, template)
			return err
		})
		if err == nil {
			t.Errorf("%s: direct bind was accepted", name)
		}
	}
	err = WithTenant(ctxA, pool, "bind-a", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctxA, `UPDATE notification_channels SET locale='fr' WHERE tenant_id=$1 AND id=$2`, "bind-a", channel.ID)
		return err
	})
	if err == nil {
		t.Error("an unknown locale was stored")
	}

	// Another tenant neither reads the channel nor resolves through it.
	if _, err := repo.GetChannel(ctxB, "bind-b", channel.ID); err == nil {
		t.Fatal("tenant B read tenant A's channel")
	}
	var visible int
	if err := WithTenant(ctxB, pool, "bind-b", func(tx pgx.Tx) error {
		return tx.QueryRow(ctxB, `SELECT count(*) FROM notification_channels WHERE template_id IS NOT NULL OR id=$1`, channel.ID).Scan(&visible)
	}); err != nil || visible != 0 {
		t.Fatalf("tenant B sees %d bound channels, err=%v", visible, err)
	}
	if _, err := svc.ResolveTemplate(context.Background(), "bind-b", channel.ID, notification.EventScanCompleted); err == nil {
		t.Fatal("tenant B resolved tenant A's channel")
	}
}

// The custom body opt-in (#1376, migration 0201) persists on webhook channels only and always with
// a bound template, even when the API is bypassed.
func TestNotificationCustomBodyPostgres(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := shared.WithTenant(context.Background(), "body-a")
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES('body-a','A')"); err != nil {
		t.Fatal(err)
	}
	cipher, _ := vault.NewCipher([]byte(strings.Repeat("k", 32)))
	repo := NewNotificationRepository(pool)
	svc, err := notificationuc.NewService(repo, cipher, nil, NewAuditLog(pool), &notificationTestClock{time.Now().UTC().Truncate(time.Microsecond)}, &notificationTestIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTransactionRunner(NewTenantTransactionRunner(pool))
	svc.SetTemplateStore(NewNotificationTemplateStore(pool))
	created, err := svc.CreateTemplate(ctx, "ada", notificationuc.TemplateInput{Name: "Hook", EventType: notification.AnyEventType, Family: notification.FamilyWebhook, Locale: "*",
		Fields: map[string]string{"body": `{"source":"synapse","n":1}`}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ActivateTemplate(ctx, "ada", created.ID, notificationuc.TemplateChangeInput{Revision: created.Revision}); err != nil {
		t.Fatal(err)
	}
	id, on := created.ID, true
	hook, err := svc.CreateChannel(ctx, "ada", notificationuc.ChannelInput{Name: "hook", Type: notification.ChannelWebhook, Enabled: true,
		URL: "https://hooks.example.com/in", Secret: "0123456789abcdef", TemplateID: &id, CustomBody: &on})
	if err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetChannel(ctx, "body-a", hook.ID)
	if err != nil || !got.CustomBody || got.TemplateID != created.ID {
		t.Fatalf("get = %+v err=%v", got.TemplateBinding, err)
	}
	delivery, err := svc.TestChannel(ctx, "ada", hook.ID)
	if err != nil {
		t.Fatal(err)
	}
	if work, err := repo.LoadWork(ctx, "body-a", delivery); err != nil || !work.Channel.CustomBody {
		t.Fatalf("work = %+v err=%v", work.Channel.TemplateBinding, err)
	}
	slack, err := svc.CreateChannel(ctx, "ada", notificationuc.ChannelInput{Name: "ops", Type: notification.ChannelSlack, Enabled: true, URL: "https://hooks.slack.com/services/T/B/X"})
	if err != nil {
		t.Fatal(err)
	}
	for name, statement := range map[string]string{
		"slack channel":    `UPDATE notification_channels SET custom_body=true WHERE tenant_id=$1 AND id='` + slack.ID.String() + `'`,
		"without template": `UPDATE notification_channels SET template_id=NULL WHERE tenant_id=$1 AND id='` + hook.ID.String() + `'`,
	} {
		err := WithTenant(ctx, pool, "body-a", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, statement, "body-a")
			return err
		})
		if err == nil {
			t.Errorf("%s: custom body stored", name)
		}
	}
}
