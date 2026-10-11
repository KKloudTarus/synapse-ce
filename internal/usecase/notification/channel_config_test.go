package notification

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Configurations sealed before the per-type structs used one shared struct with omitempty tags.
// The new structs must produce the same JSON, so channels saved by either release decode the same.
func TestPerTypeConfigsSealTheLegacyJSON(t *testing.T) {
	cases := []struct {
		in   ChannelInput
		want string
	}{
		{ChannelInput{Name: "hook", Type: domain.ChannelWebhook, URL: "https://hooks.example/in", Secret: "0123456789abcdef"}, `{"url":"https://hooks.example/in","secret":"0123456789abcdef"}`},
		{ChannelInput{Name: "slack", Type: domain.ChannelSlack, URL: "https://hooks.slack.com/services/T/B/x"}, `{"url":"https://hooks.slack.com/services/T/B/x"}`},
		{ChannelInput{Name: "mail", Type: domain.ChannelEmail, Recipients: []string{"Sec@Example.com"}}, `{"recipients":["sec@example.com"]}`},
	}
	for _, tc := range cases {
		config, _, _, err := validateChannel(tc.in, true)
		if err != nil {
			t.Fatalf("%s: %v", tc.in.Type, err)
		}
		raw, err := json.Marshal(config)
		if err != nil || string(raw) != tc.want {
			t.Errorf("%s sealed %s, want %s (err %v)", tc.in.Type, raw, tc.want, err)
		}
	}
}

func TestDecodeChannelConfigReadsLegacyBlobs(t *testing.T) {
	cases := []struct {
		kind domain.ChannelType
		raw  string
		want ports.NotificationChannelConfig
	}{
		{domain.ChannelWebhook, `{"url":"https://hooks.example/in","secret":"0123456789abcdef"}`, ports.WebhookChannelConfig{URL: "https://hooks.example/in", Secret: "0123456789abcdef"}},
		{domain.ChannelSlack, `{"url":"https://hooks.slack.com/services/T/B/x"}`, ports.SlackChannelConfig{URL: "https://hooks.slack.com/services/T/B/x"}},
		{domain.ChannelEmail, `{"recipients":["sec@example.com"]}`, ports.EmailChannelConfig{Recipients: []string{"sec@example.com"}}},
	}
	for _, tc := range cases {
		got, code := decodeChannelConfig(tc.kind, []byte(tc.raw))
		if code != "" || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %#v code %q", tc.kind, got, code)
		}
	}
}

func TestDecodeChannelConfigFailuresAreStableCodes(t *testing.T) {
	if _, code := decodeChannelConfig("carrier_pigeon", []byte(`{}`)); code != codeUnsupportedChannel {
		t.Errorf("unknown type code = %q", code)
	}
	if _, code := decodeChannelConfig(domain.ChannelWebhook, []byte(`not json`)); code != codeChannelConfigInvalid {
		t.Errorf("corrupt config code = %q", code)
	}
}

func TestEveryValidChannelTypeHasASchema(t *testing.T) {
	for _, kind := range []domain.ChannelType{domain.ChannelWebhook, domain.ChannelSlack, domain.ChannelEmail} {
		if _, ok := channelSchemas[kind]; !ok || !kind.Valid() {
			t.Errorf("channel type %s has no schema", kind)
		}
	}
	if _, _, _, err := validateChannel(ChannelInput{Name: "x", Type: "carrier_pigeon", URL: "https://example.com"}, true); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("unknown channel type accepted: %v", err)
	}
}
