package notification

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	teamsURL      = "https://prod-12.westus.logic.azure.com:443/workflows/0a1b2c/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=teams-signature-secret"
	teamsPPURL    = "https://default0a1b.2c.environment.api.powerplatform.com/powerautomate/automations/direct/workflows/abc/triggers/manual/paths/invoke?api-version=1&sig=pp-signature-secret"
	googleChatURL = "https://chat.googleapis.com/v1/spaces/AAAA1234/messages?key=gchat-key-secret&token=gchat-token-secret"
	discordURL    = "https://discord.com/api/webhooks/123456789012345678/discord-token-secret_ABC"
	tgToken       = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"
)

func TestChatChannelsAcceptTheVendorEndpoints(t *testing.T) {
	cases := []struct {
		in          ChannelInput
		destination string
		want        ports.NotificationChannelConfig
	}{
		{ChannelInput{Type: domain.ChannelTeams, URL: teamsURL}, "https://prod-12.westus.logic.azure.com/…", ports.TeamsChannelConfig{URL: teamsURL}},
		{ChannelInput{Type: domain.ChannelTeams, URL: teamsPPURL}, "https://default0a1b.2c.environment.api.powerplatform.com/…", ports.TeamsChannelConfig{URL: teamsPPURL}},
		{ChannelInput{Type: domain.ChannelGoogleChat, URL: googleChatURL}, "https://chat.googleapis.com/…", ports.GoogleChatChannelConfig{URL: googleChatURL}},
		{ChannelInput{Type: domain.ChannelDiscord, URL: discordURL}, "https://discord.com/…", ports.DiscordChannelConfig{URL: discordURL}},
		{ChannelInput{Type: domain.ChannelDiscord, URL: "https://discordapp.com/api/v10/webhooks/1/tok?thread_id=42"}, "https://discordapp.com/…", ports.DiscordChannelConfig{URL: "https://discordapp.com/api/v10/webhooks/1/tok?thread_id=42"}},
		{ChannelInput{Type: domain.ChannelTelegram, Secret: tgToken, ChatID: "-1001234567890", ThreadID: 7}, "https://api.telegram.org/…", ports.TelegramChannelConfig{BotToken: tgToken, ChatID: "-1001234567890", MessageThreadID: 7}},
		{ChannelInput{Type: domain.ChannelTelegram, Secret: " " + tgToken + " ", ChatID: "@synapse_alerts"}, "https://api.telegram.org/…", ports.TelegramChannelConfig{BotToken: tgToken, ChatID: "@synapse_alerts"}},
	}
	for _, tc := range cases {
		tc.in.Name = "ops"
		config, destination, recipients, err := validateChannel(tc.in, true)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.in.Type, tc.in.URL, err)
		}
		if destination != tc.destination || recipients != nil || !reflect.DeepEqual(config, tc.want) {
			t.Errorf("%s: got %#v %q %v", tc.in.Type, config, destination, recipients)
		}
		// The masked destination never holds any part of the credential.
		for _, secret := range []string{"secret", "tok", tgToken, "sig="} {
			if strings.Contains(destination, secret) {
				t.Errorf("%s destination %q leaks %q", tc.in.Type, destination, secret)
			}
		}
		// The sealed config round-trips through the type's decoder.
		raw, _ := json.Marshal(config)
		decoded, code := decodeChannelConfig(tc.in.Type, raw)
		if code != "" || !reflect.DeepEqual(decoded, tc.want) {
			t.Errorf("%s decode: %#v %q", tc.in.Type, decoded, code)
		}
	}
}

func TestChatChannelsRefuseOtherEndpoints(t *testing.T) {
	cases := map[domain.ChannelType][]string{
		domain.ChannelTeams: {
			"http://prod-12.westus.logic.azure.com/workflows/x?sig=s",            // not https
			"https://prod-12.westus.logic.azure.com/workflows/x",                 // no signature
			"https://logic.azure.com/workflows/x?sig=s",                          // bare suffix
			"https://evil.example/workflows/x?sig=s",                             // foreign host
			"https://evil.logic.azure.com.attacker.example/workflows/x?sig=s",    // suffix in the middle
			"https://contoso.webhook.office.com/webhookb2/x/IncomingWebhook/y/z", // retired O365 connector
			"https://prod-12.westus.logic.azure.com:8443/workflows/x?sig=s",      // other port
			"https://user:pw@prod-12.westus.logic.azure.com/workflows/x?sig=s",   // userinfo
			"https://prod-12.westus.logic.azure.com/admin/x?sig=s",               // other path
			"https://prod-12.westus.logic.azure.com/workflows/x?sig=s#frag",      // fragment
		},
		domain.ChannelGoogleChat: {
			"https://chat.googleapis.com/v1/spaces/AAA/messages?key=k",                     // no token
			"https://chat.googleapis.com/v1/spaces/AAA/messages?token=t",                   // no key
			"https://chat.googleapis.com/v1/spaces/AAA/members?key=k&token=t",              // other method
			"https://chat.googleapis.com/v1/spaces/AAA/messages?key=k&token=t&threadKey=x", // extra option
			"https://chat.googleapis.com/v1/spaces/AAA/messages?key=k&key=k2&token=t",      // repeated key
			"https://evil.example/v1/spaces/AAA/messages?key=k&token=t",                    // foreign host
			"https://chat.googleapis.com/v1/spaces/../messages?key=k&token=t",              // traversal
		},
		domain.ChannelDiscord: {
			"https://discord.com/api/webhooks/123/",                 // no token
			"https://discord.com/api/webhooks/abc/token",            // non-numeric id
			"https://discord.com/api/webhooks/1/token/slack",        // Slack-compatible mode
			"https://discord.com/api/webhooks/1/token?wait=false",   // driver-owned option
			"https://discord.com/api/webhooks/1/token?thread_id=x",  // bad thread
			"https://discord.gg/api/webhooks/1/token",               // foreign host
			"https://discord.com.evil.example/api/webhooks/1/token", // lookalike host
			"https://discord.com/api/channels/1/messages",           // bot API, not a webhook
		},
	}
	for kind, urls := range cases {
		for _, raw := range urls {
			if _, _, _, err := validateChannel(ChannelInput{Name: "ops", Type: kind, URL: raw}, true); !errors.Is(err, shared.ErrValidation) {
				t.Errorf("%s accepted %q (err %v)", kind, raw, err)
			}
		}
	}
}

func TestTelegramChannelValidation(t *testing.T) {
	cases := []ChannelInput{
		{ChatID: "-100123"},                                     // no token
		{Secret: "not-a-token", ChatID: "-100123"},              // malformed token
		{Secret: tgToken + "/../../getMe", ChatID: "-100123"},   // path injection
		{Secret: tgToken},                                       // no chat
		{Secret: tgToken, ChatID: "@ab"},                        // username too short
		{Secret: tgToken, ChatID: "12 34"},                      // malformed chat
		{Secret: tgToken, ChatID: "-100123", ThreadID: -1},      // negative topic
		{Secret: tgToken, ChatID: "-100123", ThreadID: 1 << 31}, // topic beyond int32
	}
	for _, in := range cases {
		in.Name, in.Type = "ops", domain.ChannelTelegram
		_, _, _, err := validateChannel(in, true)
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("accepted %+v", in)
			continue
		}
		if strings.Contains(err.Error(), tgToken) || strings.Contains(err.Error(), "not-a-token") {
			t.Errorf("validation error echoes the token: %v", err)
		}
	}
}

func TestChatValidationErrorsNeverEchoTheURL(t *testing.T) {
	for kind, raw := range map[domain.ChannelType]string{
		domain.ChannelTeams:      "https://prod-12.westus.logic.azure.com/admin?sig=teams-signature-secret",
		domain.ChannelGoogleChat: "https://chat.googleapis.com/v1/spaces/AAA/members?key=gchat-key-secret&token=gchat-token-secret",
		domain.ChannelDiscord:    "https://discord.com/api/webhooks/1/discord-token-secret/slack",
	} {
		_, _, _, err := validateChannel(ChannelInput{Name: "ops", Type: kind, URL: raw}, true)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: %v", kind, err)
		}
	}
}

func TestEveryChatChannelTypeHasASchemaAndAChatFamily(t *testing.T) {
	for _, kind := range []domain.ChannelType{domain.ChannelTeams, domain.ChannelTelegram, domain.ChannelGoogleChat, domain.ChannelDiscord} {
		if _, ok := channelSchemas[kind]; !ok || !kind.Valid() || !kind.HTTPEndpoint() {
			t.Errorf("%s has no schema", kind)
		}
		if family, ok := domain.FamilyForChannelType(kind); !ok || family != domain.FamilyChat {
			t.Errorf("%s family = %q", kind, family)
		}
	}
}

// The service keeps the credential out of everything it returns and audits, and treats a new URL,
// token or chat as a destination change that only an administrator may make.
func TestChatChannelLifecycleKeepsTheCredentialSealed(t *testing.T) {
	inputs := map[domain.ChannelType]ChannelInput{
		domain.ChannelTeams:      {URL: teamsURL},
		domain.ChannelGoogleChat: {URL: googleChatURL},
		domain.ChannelDiscord:    {URL: discordURL},
		domain.ChannelTelegram:   {Secret: tgToken, ChatID: "-1001234567890"},
	}
	secrets := []string{"teams-signature-secret", "gchat-key-secret", "gchat-token-secret", "discord-token-secret", tgToken, "-1001234567890"}
	for kind, in := range inputs {
		t.Run(string(kind), func(t *testing.T) {
			f := newBindingFixture(t)
			in.Name, in.Type, in.Enabled = "ops", kind, true
			created, err := f.svc.CreateChannel(f.ctx, "ada", in)
			if err != nil {
				t.Fatal(err)
			}
			// Rename without the credential keeps it; no re-entry is asked for.
			renamed, err := f.svc.UpdateChannel(f.ctx, "ada", created.ID, ChannelInput{Name: "renamed", Enabled: true, Revision: created.Revision})
			if err != nil || renamed.SecretVersion != created.SecretVersion || renamed.Destination != created.Destination {
				t.Fatalf("rename: %+v %v", renamed, err)
			}
			// An integration admin cannot re-point it.
			repoint := in
			repoint.Name, repoint.Revision = "renamed", renamed.Revision
			if _, err := f.svc.UpdateChannel(f.ctx, "ada", created.ID, repoint); !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("destination change without administer: %v", err)
			}
			// An administrator can; the repository seals the new version (the fake keeps the number).
			repoint.AllowDestinationChange = true
			replaced, err := f.svc.UpdateChannel(f.ctx, "ada", created.ID, repoint)
			if err != nil || f.audit.last(t, "notification.channel.updated").Metadata["destination_changed"] != "true" {
				t.Fatalf("destination change: %+v %v", replaced, err)
			}
			raw, _ := json.Marshal([]any{created, renamed, replaced, f.audit.entries})
			for _, secret := range secrets {
				if strings.Contains(string(raw), secret) {
					t.Errorf("channel or audit leaks %q: %s", secret, raw)
				}
			}
			if got := f.audit.last(t, "notification.channel.created").Metadata["destination"]; !strings.HasPrefix(got, "https://") || strings.Contains(got, "/…") {
				t.Errorf("audited destination = %q, want scheme://host", got)
			}
		})
	}
}

func TestTelegramReplacementNeedsTheTokenAgain(t *testing.T) {
	f := newBindingFixture(t)
	created, err := f.svc.CreateChannel(f.ctx, "ada", ChannelInput{Name: "ops", Type: domain.ChannelTelegram, Enabled: true, Secret: tgToken, ChatID: "-100123"})
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []ChannelInput{
		{ChatID: "-100999"}, // a new chat alone
		{ThreadID: 9},       // a new topic alone
	} {
		in.Name, in.Enabled, in.Revision, in.AllowDestinationChange = "ops", true, created.Revision, true
		if _, err := f.svc.UpdateChannel(f.ctx, "ada", created.ID, in); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%+v: err = %v, want a validation error asking for the token", in, err)
		}
	}
	got, err := f.svc.GetChannel(f.ctx, created.ID)
	if err != nil || got.SecretVersion != created.SecretVersion {
		t.Fatalf("refused updates changed the channel: %+v %v", got, err)
	}
}

func TestChatChannelTypeIsImmutable(t *testing.T) {
	f := newBindingFixture(t)
	created, err := f.svc.CreateChannel(f.ctx, "ada", ChannelInput{Name: "ops", Type: domain.ChannelDiscord, Enabled: true, URL: discordURL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.UpdateChannel(f.ctx, "ada", created.ID, ChannelInput{Name: "ops", Type: domain.ChannelTeams, URL: teamsURL, Revision: created.Revision, AllowDestinationChange: true})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("type change: %v", err)
	}
	_ = fmt.Sprint(created)
}
