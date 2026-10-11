package postgres

import (
	"context"
	"encoding/json"
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

const pgSlackToken = "xoxb" + "-1111111111-2222222222-postgresSECRETtoken"

type pgSlackWorkspace struct{}

func (pgSlackWorkspace) Identify(context.Context, string) (ports.SlackIdentity, error) {
	return ports.SlackIdentity{TeamID: "T0PG", TeamName: "Acme"}, nil
}

func (pgSlackWorkspace) Conversation(_ context.Context, _, id string) (ports.SlackConversation, error) {
	return ports.SlackConversation{ID: id, Name: "security", Member: true}, nil
}

func (pgSlackWorkspace) Conversations(context.Context, string) ([]ports.SlackConversation, bool, error) {
	return nil, false, nil
}

// Slack bot channels (#1383, migration 0228) over PostgreSQL: the row holds only the masked
// destination, GetChannelSealedConfig returns the current version's sealed configuration for the
// tenant that owns the channel and nobody else, and the family guard binds a chat template to it.
func TestNotificationSlackBotChannelPostgres(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := shared.WithTenant(context.Background(), "slack-a")
	for _, tenant := range []string{"slack-a", "slack-b"} {
		if _, err := pool.Exec(context.Background(), "INSERT INTO tenants(id,name) VALUES($1,$1)", tenant); err != nil {
			t.Fatal(err)
		}
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
	svc.SetSlackWorkspace(pgSlackWorkspace{})

	created, err := svc.CreateTemplate(ctx, "ada", notificationuc.TemplateInput{Name: "Chat", EventType: notification.AnyEventType, Family: notification.FamilyChat, Locale: "*",
		Fields: map[string]string{"title": "Synapse", "body": "Open Synapse."}})
	if err != nil {
		t.Fatal(err)
	}
	chat, err := svc.ActivateTemplate(ctx, "ada", created.ID, notificationuc.TemplateChangeInput{Revision: created.Revision})
	if err != nil {
		t.Fatal(err)
	}
	templateID := chat.ID
	channel, err := svc.CreateChannel(ctx, "ada", notificationuc.ChannelInput{Name: "Security", Type: notification.ChannelSlackBot, Enabled: true,
		Secret: pgSlackToken, ConversationID: "C0123456789", TemplateID: &templateID})
	if err != nil {
		t.Fatal(err)
	}
	if channel.TemplateID != chat.ID || channel.Destination != "https://slack.com/…" || channel.Class() != notification.DataClassSignal {
		t.Fatalf("channel = %+v", channel)
	}

	var row string
	if err := WithTenant(ctx, pool, "slack-a", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT row_to_json(c)::text FROM (SELECT * FROM notification_channels WHERE id=$1) c`, channel.ID).Scan(&row)
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(row, "postgresSECRET") || strings.Contains(row, "C0123456789") {
		t.Fatalf("clear columns hold the destination: %s", row)
	}

	got, sealed, err := repo.GetChannelSealedConfig(ctx, "slack-a", channel.ID)
	if err != nil || got.ID != channel.ID || got.Type != notification.ChannelSlackBot || sealed == "" {
		t.Fatalf("sealed read = %+v %q %v", got, sealed, err)
	}
	raw, err := cipher.Open(sealed, []byte("synapse:notification:slack-a:"+channel.ID.String()+":1"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg ports.SlackBotChannelConfig
	if err := json.Unmarshal(raw, &cfg); err != nil || cfg != (ports.SlackBotChannelConfig{BotToken: pgSlackToken, ChannelID: "C0123456789", TeamID: "T0PG"}) {
		t.Fatalf("sealed config = %s %v", raw, err)
	}
	if _, _, err := repo.GetChannelSealedConfig(shared.WithTenant(context.Background(), "slack-b"), "slack-b", channel.ID); err == nil {
		t.Fatal("another tenant read the sealed configuration")
	}

	// The conversation picker opens the stored token for an existing channel.
	if _, err := svc.ListSlackConversations(ctx, notificationuc.SlackConversationsInput{ChannelID: channel.ID}); err != nil {
		t.Fatalf("list for channel: %v", err)
	}

	// After a re-point the reader returns the new version.
	moved, err := svc.UpdateChannel(ctx, "ada", channel.ID, notificationuc.ChannelInput{Name: "Security", Type: notification.ChannelSlackBot, Enabled: true, Revision: channel.Revision,
		Secret: pgSlackToken, ConversationID: "C0123456780", AllowDestinationChange: true})
	if err != nil {
		t.Fatal(err)
	}
	_, sealed, err = repo.GetChannelSealedConfig(ctx, "slack-a", channel.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = cipher.Open(sealed, []byte("synapse:notification:slack-a:"+channel.ID.String()+":2"))
	if err != nil || moved.SecretVersion != 2 || !strings.Contains(string(raw), "C0123456780") {
		t.Fatalf("after re-point: version %d %s %v", moved.SecretVersion, raw, err)
	}
}
