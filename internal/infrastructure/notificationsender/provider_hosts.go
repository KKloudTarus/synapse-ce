package notificationsender

import (
	"crypto/sha256"
	"strings"
)

// SetSelfHostedChannelHosts installs the operator host policy at the send boundary.
func (s *Sender) SetSelfHostedChannelHosts(hosts []string) {
	s.selfHostedHosts = make(map[string]bool, len(hosts))
	for _, host := range hosts {
		s.selfHostedHosts[strings.ToLower(strings.TrimSpace(host))] = true
	}
}

// SetPagerKey derives a separate root for tenant-scoped pager identities.
func (s *Sender) SetPagerKey(vaultKey string) {
	if vaultKey == "" {
		s.pagerKey = nil
		return
	}
	key := sha256.Sum256([]byte("synapse-notification-pager\x00" + vaultKey))
	s.pagerKey = key[:]
}
