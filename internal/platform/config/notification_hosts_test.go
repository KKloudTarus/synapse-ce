package config

import "testing"

func TestNotificationHostsRequireExactDNSNames(t *testing.T) {
	for _, host := range []string{"*.example.com", "https://relay.example.com", "relay.example.com:587", "127.0.0.1", "bad..example", "relay.example.com/token"} {
		if (Config{NotificationSMTPAllowedHosts: []string{host}}).ValidateNotificationHosts() == nil {
			t.Errorf("accepted %q", host)
		}
	}
	if err := (Config{NotificationChatAllowedHosts: []string{"chat.example.com"}}).ValidateNotificationHosts(); err != nil {
		t.Fatal(err)
	}
}
