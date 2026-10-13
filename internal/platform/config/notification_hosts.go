package config

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var notificationDNSLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidateNotificationHosts refuses patterns and URL fragments in exact host lists.
func (c Config) ValidateNotificationHosts() error {
	for _, list := range [][]string{c.NotificationSMTPAllowedHosts, c.NotificationChatAllowedHosts} {
		for _, host := range list {
			valid := host != "" && len(host) <= 253 && net.ParseIP(host) == nil
			for _, label := range strings.Split(host, ".") {
				valid = valid && notificationDNSLabel.MatchString(label)
			}
			if !valid {
				return fmt.Errorf("notification allowed hosts must be exact DNS names")
			}
		}
	}
	return nil
}
