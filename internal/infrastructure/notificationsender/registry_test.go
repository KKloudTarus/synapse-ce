package notificationsender

import (
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
)

func TestChannelTypesListTheRegistryInRegistrationOrder(t *testing.T) {
	s := New(SMTPConfig{}, time.Second)
	if err := s.Register(&recordingDriver{kind: "recording"}); err != nil {
		t.Fatal(err)
	}
	got := s.ChannelTypes()
	want := []notification.ChannelType{notification.ChannelWebhook, notification.ChannelSlack, notification.ChannelEmail, notification.ChannelTeams, notification.ChannelTelegram, notification.ChannelGoogleChat, notification.ChannelDiscord, "recording"}
	if len(got) != len(want) {
		t.Fatalf("channel types = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("channel types = %v, want %v", got, want)
		}
	}
	got[0] = "mutated"
	if s.ChannelTypes()[0] != notification.ChannelWebhook {
		t.Fatal("ChannelTypes exposed the registry's slice")
	}
}

func TestResolveDisabledAcceptsOnlyRegisteredTypes(t *testing.T) {
	s := New(SMTPConfig{}, time.Second)
	disabled, err := s.ResolveDisabled([]string{"slack", "email"})
	if err != nil || len(disabled) != 2 || disabled[0] != notification.ChannelSlack || disabled[1] != notification.ChannelEmail {
		t.Fatalf("disabled=%v err=%v", disabled, err)
	}
	if disabled, err = s.ResolveDisabled(nil); err != nil || len(disabled) != 0 {
		t.Fatalf("empty setting: disabled=%v err=%v", disabled, err)
	}
	_, err = s.ResolveDisabled([]string{"slack", "slak"})
	if err == nil {
		t.Fatal("a typo was accepted")
	}
	for _, want := range []string{"SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED", `"slak"`, "webhook, slack, email"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}
