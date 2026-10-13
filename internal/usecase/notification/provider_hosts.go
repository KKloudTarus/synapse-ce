package notification

import (
	"fmt"
	"net/url"
	"strings"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// SetSelfHostedChannelHosts installs exact operator-approved webhook hosts.
func (s *Service) SetSelfHostedChannelHosts(hosts []string) {
	s.selfHostedHosts = make(map[string]bool, len(hosts))
	for _, host := range hosts {
		s.selfHostedHosts[strings.ToLower(strings.TrimSpace(host))] = true
	}
}

func (s *Service) validateChannelInput(in ChannelInput, requireSecret bool) (ports.NotificationChannelConfig, string, []string, error) {
	if in.Type == domain.ChannelMattermost || in.Type == domain.ChannelRocketChat {
		u, err := url.Parse(in.URL)
		if err != nil || !s.selfHostedHosts[strings.ToLower(u.Hostname())] {
			return nil, "", nil, fmt.Errorf("%w: channel host is not approved by the operator", shared.ErrValidation)
		}
	}
	return validateChannel(in, requireSecret)
}
