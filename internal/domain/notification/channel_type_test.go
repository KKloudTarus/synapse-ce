package notification

import (
	"regexp"
	"testing"
	"time"
)

func TestChatChannelTypesAreValidHTTPEndpoints(t *testing.T) {
	// The shape the channel_type CHECK has enforced since #1341, so a new type needs no migration.
	shape := regexp.MustCompile(`^[a-z_]+$`)
	for _, kind := range []ChannelType{ChannelWebhook, ChannelSlack, ChannelTeams, ChannelTelegram, ChannelGoogleChat, ChannelDiscord} {
		if !kind.Valid() || !kind.HTTPEndpoint() || !shape.MatchString(string(kind)) {
			t.Errorf("%s: valid=%v http=%v", kind, kind.Valid(), kind.HTTPEndpoint())
		}
	}
	if ChannelEmail.HTTPEndpoint() || !ChannelEmail.Valid() {
		t.Error("email delivers to recipients, not an HTTP endpoint")
	}
	if ChannelType("carrier_pigeon").Valid() || ChannelType("carrier_pigeon").HTTPEndpoint() {
		t.Error("an unknown type is not valid")
	}
}

// A chat channel created or re-pointed by an administrator raises the same in-app destination
// notice as a webhook (#1422), naming only the scheme and host.
func TestChatChannelsRaiseDestinationNotices(t *testing.T) {
	for _, kind := range []ChannelType{ChannelTeams, ChannelTelegram, ChannelGoogleChat, ChannelDiscord} {
		event, err := NewDestinationEvent("tenant", "c1", kind, "https://api.telegram.org/…", "host_changed", "ada", time.Unix(1700000000, 0))
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if event.Type != EventDestinationChanged {
			t.Errorf("%s: event type %s", kind, event.Type)
		}
	}
	if _, err := NewDestinationEvent("tenant", "c1", ChannelEmail, "https://example.com/…", "created", "ada", time.Unix(1700000000, 0)); err == nil {
		t.Error("an email channel has no HTTP host to announce")
	}
}
