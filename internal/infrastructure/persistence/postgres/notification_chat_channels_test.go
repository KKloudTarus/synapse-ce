package postgres

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// The WS3 chat channels (#1378 to #1381, migration 0220) over PostgreSQL: each type is stored
// with only its masked destination in clear, the sealed configuration opens to the per-type struct
// in the worker, a chat template binds to it, and the family guard still refuses a template of
// another family.
func TestNotificationChatChannelsPostgres(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := shared.WithTenant(context.Background(), "chat-a")
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES('chat-a','A')"); err != nil {
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
	svc.SetTenantSettings(NewTenantSettingsStore(pool))

	activate := func(in notificationuc.TemplateInput) notification.Template {
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
	chat := activate(notificationuc.TemplateInput{Name: "Chat", EventType: notification.AnyEventType, Family: notification.FamilyChat, Locale: "*",
		Fields: map[string]string{"title": "Synapse", "body": "Open Synapse."}})
	email := activate(notificationuc.TemplateInput{Name: "Mail", EventType: notification.AnyEventType, Family: notification.FamilyEmail, Locale: "*",
		Fields: map[string]string{"subject": "Synapse", "body": "Open Synapse."}})

	cases := []struct {
		in     notificationuc.ChannelInput
		want   ports.NotificationChannelConfig
		secret string
	}{
		{notificationuc.ChannelInput{Type: notification.ChannelTeams, URL: "https://prod-1.westus.logic.azure.com/workflows/a/triggers/manual/paths/invoke?sig=teams-sig-secret"},
			ports.TeamsChannelConfig{URL: "https://prod-1.westus.logic.azure.com/workflows/a/triggers/manual/paths/invoke?sig=teams-sig-secret"}, "teams-sig-secret"},
		{notificationuc.ChannelInput{Type: notification.ChannelTelegram, Secret: "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", ChatID: "-100123", ThreadID: 4},
			ports.TelegramChannelConfig{BotToken: "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", ChatID: "-100123", MessageThreadID: 4}, "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"},
		{notificationuc.ChannelInput{Type: notification.ChannelGoogleChat, URL: "https://chat.googleapis.com/v1/spaces/A/messages?key=k&token=gchat-token-secret"},
			ports.GoogleChatChannelConfig{URL: "https://chat.googleapis.com/v1/spaces/A/messages?key=k&token=gchat-token-secret"}, "gchat-token-secret"},
		{notificationuc.ChannelInput{Type: notification.ChannelDiscord, URL: "https://discord.com/api/webhooks/1/discord-token-secret"},
			ports.DiscordChannelConfig{URL: "https://discord.com/api/webhooks/1/discord-token-secret"}, "discord-token-secret"},
	}
	for _, tc := range cases {
		t.Run(string(tc.in.Type), func(t *testing.T) {
			id := chat.ID
			tc.in.Name, tc.in.Enabled, tc.in.TemplateID = "ops "+string(tc.in.Type), true, &id
			channel, err := svc.CreateChannel(ctx, "ada", tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if channel.TemplateID != chat.ID || !strings.HasPrefix(channel.Destination, "https://") {
				t.Fatalf("channel = %+v", channel)
			}

			// Nothing readable in the row holds the credential; only the sealed column does.
			var row string
			if err := WithTenant(ctx, pool, "chat-a", func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT row_to_json(c)::text FROM (SELECT id,name,channel_type,destination,recipients FROM notification_channels WHERE id=$1) c`, channel.ID).Scan(&row)
			}); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(row, tc.secret) {
				t.Fatalf("clear columns hold the credential: %s", row)
			}

			// The worker opens the sealed configuration as the type's own struct.
			delivery, err := svc.TestChannel(ctx, "ada", channel.ID)
			if err != nil {
				t.Fatal(err)
			}
			work, err := repo.LoadWork(ctx, "chat-a", delivery)
			if err != nil {
				t.Fatal(err)
			}
			aad := []byte("synapse:notification:chat-a:" + channel.ID.String() + ":" + strconv.Itoa(work.Channel.SecretVersion))
			raw, err := cipher.Open(work.Sealed, aad)
			if err != nil {
				t.Fatal(err)
			}
			opened := reflect.New(reflect.TypeOf(tc.want))
			if err := json.Unmarshal(raw, opened.Interface()); err != nil || opened.Elem().Interface() != tc.want {
				t.Fatalf("sealed config = %s err=%v", raw, err)
			}

			// The family guard (0220) refuses an email template on a chat channel, even directly.
			err = WithTenant(ctx, pool, "chat-a", func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE notification_channels SET template_id=$3 WHERE tenant_id=$1 AND id=$2`, "chat-a", channel.ID, email.ID)
				return err
			})
			if err == nil {
				t.Fatal("an email template was bound to a chat channel")
			}
		})
	}
}
