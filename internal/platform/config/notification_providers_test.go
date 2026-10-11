package config

import (
	"strings"
	"testing"
)

func TestLoadNotificationProvidersDisabled(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"", ""},
		{" , ,", ""},
		{"slack", "slack"},
		{" Slack , EMAIL,,slack , email", "slack,email"},
		{"webhook,Webhook", "webhook"},
	}
	for _, tc := range cases {
		t.Setenv("SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED", tc.raw)
		got := Load().NotificationProvidersDisabled
		if strings.Join(got, ",") != tc.want {
			t.Errorf("SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED=%q parsed to %q, want %q", tc.raw, got, tc.want)
		}
		if tc.want == "" && got != nil {
			t.Errorf("SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED=%q parsed to %#v, want nil", tc.raw, got)
		}
	}
}

func TestValidateNotificationProvidersDisabled(t *testing.T) {
	for _, ok := range [][]string{nil, {"webhook"}, {"slack", "email"}, {"ms-teams", "google_chat", "a1"}} {
		if err := (Config{NotificationProvidersDisabled: ok}).ValidateNotificationProvidersDisabled(); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range [][]string{{"-slack"}, {"_slack"}, {"sl ack"}, {"slack!"}, {"Slack"}, {strings.Repeat("a", 65)}, {""}} {
		err := (Config{NotificationProvidersDisabled: bad}).ValidateNotificationProvidersDisabled()
		if err == nil {
			t.Errorf("%q accepted", bad)
			continue
		}
		if !strings.Contains(err.Error(), "SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED") {
			t.Errorf("error %q does not name the variable", err)
		}
	}
}
