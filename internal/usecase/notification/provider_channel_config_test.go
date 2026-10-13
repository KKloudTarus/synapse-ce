package notification

import (
	"errors"
	"reflect"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestProviderChannelConfigsAreSealedWithOnlyCredentialsNeededAtSendTime(t *testing.T) {
	cases := []struct {
		in   ChannelInput
		want ports.NotificationChannelConfig
	}{
		{ChannelInput{Type: domain.ChannelMattermost, URL: "https://chat.example.test/hooks/a"}, ports.MattermostChannelConfig{URL: "https://chat.example.test/hooks/a"}},
		{ChannelInput{Type: domain.ChannelRocketChat, URL: "https://chat.example.test/hooks/a"}, ports.RocketChatChannelConfig{URL: "https://chat.example.test/hooks/a"}},
		{ChannelInput{Type: domain.ChannelPagerDuty, URL: "https://events.eu.pagerduty.com/v2/enqueue", Secret: "0123456789abcdef"}, ports.PagerDutyChannelConfig{Region: pagerDutyEUHost, RoutingKey: "0123456789abcdef"}},
		{ChannelInput{Type: domain.ChannelJSM, Secret: "0123456789abcdef"}, ports.JSMChannelConfig{APIKey: "0123456789abcdef"}},
	}
	for _, tc := range cases {
		got, _, _, err := validateChannel(ChannelInput{Name: "ops", Type: tc.in.Type, URL: tc.in.URL, Secret: tc.in.Secret}, true)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %#v err=%v", tc.in.Type, got, err)
		}
	}
}

func TestProviderChannelConfigsRejectUnpinnedOrUnsafeEndpoints(t *testing.T) {
	cases := []ChannelInput{
		{Type: domain.ChannelMattermost, URL: "http://chat.example.test/hooks/a"},
		{Type: domain.ChannelRocketChat, URL: "https://u:p@chat.example.test/hooks/a"},
		{Type: domain.ChannelMattermost, URL: "https://chat.example.test:444/hooks/a"},
		{Type: domain.ChannelPagerDuty, URL: "https://evil.example/v2/enqueue", Secret: "0123456789abcdef"},
		{Type: domain.ChannelPagerDuty, URL: "https://events.pagerduty.com/v1/enqueue", Secret: "0123456789abcdef"},
		{Type: domain.ChannelJSM, URL: "https://evil.example/jsm/ops/integration/v2/alerts", Secret: "0123456789abcdef"},
		{Type: domain.ChannelJSM, Secret: "short"},
	}
	for _, in := range cases {
		_, _, _, err := validateChannel(ChannelInput{Name: "ops", Type: in.Type, URL: in.URL, Secret: in.Secret}, true)
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%+v accepted: %v", in, err)
		}
	}
}
