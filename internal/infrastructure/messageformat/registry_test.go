package messageformat

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
)

func TestFormattersCoverChatAndEmail(t *testing.T) {
	formatters := Formatters()
	for _, kind := range []notification.ChannelType{notification.ChannelSlack, notification.ChannelEmail, notification.ChannelTeams, notification.ChannelTelegram, notification.ChannelGoogleChat, notification.ChannelDiscord} {
		if f, ok := formatters[kind]; !ok || f.ChannelType() != kind {
			t.Errorf("no formatter for %s", kind)
		}
	}
	if _, ok := formatters[notification.ChannelWebhook]; ok {
		t.Error("the generic webhook body is a contract, not formatted content")
	}
}
