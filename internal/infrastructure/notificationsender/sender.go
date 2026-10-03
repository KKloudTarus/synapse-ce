// Package notificationsender delivers one durable notification attempt. Retry
// scheduling belongs to synapse-worker; this adapter never sleeps or retries.
//
// Each channel type is a Driver registered on the Sender. Adding a channel means
// adding a driver file and registering it in New; Send never switches on the type.
package notificationsender

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Driver delivers one attempt for one channel type. It receives the configuration the usecase
// decoded for that type and returns a transport-level result; it never retries.
type Driver interface {
	ChannelType() notification.ChannelType
	Send(context.Context, ports.NotificationWork, ports.NotificationChannelConfig) ports.NotificationSendResult
}

type SMTPConfig struct {
	Host       string
	Port       int
	From       string
	Username   string
	Password   string
	RequireTLS bool
}

// Sender holds the shared transports and the driver registry. Drivers keep a pointer to it, so
// the HTTP client, clock and SMTP dialer are configured in one place.
type Sender struct {
	http    *http.Client
	smtp    SMTPConfig
	dial    func(ctx context.Context, network, address string) (net.Conn, error)
	now     func() time.Time
	timeout time.Duration
	// telegramAPI is the Bot API origin; only tests change it.
	telegramAPI string
	drivers     map[notification.ChannelType]Driver
	// order is the registration order, so the types a deployment offers are listed stably.
	order []notification.ChannelType
}

var _ ports.NotificationSender = (*Sender)(nil)

func New(smtpConfig SMTPConfig, timeout time.Duration) *Sender {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if smtpConfig.Port == 0 {
		smtpConfig.Port = 587
	}
	// The relay comes from operator configuration, not from a tenant, and is often a local MTA, so
	// it may be private or loopback; metadata and other special-purpose ranges stay refused.
	relay := safehttp.NewDialer(safehttp.OperatorPolicy(), timeout)
	s := &Sender{http: safehttp.New(timeout, false), smtp: smtpConfig, dial: relay.DialContext, now: time.Now, timeout: timeout, telegramAPI: telegramAPIBase}
	s.drivers = map[notification.ChannelType]Driver{}
	for _, driver := range builtinDrivers(s) {
		s.drivers[driver.ChannelType()] = driver
		s.order = append(s.order, driver.ChannelType())
	}
	return s
}

// builtinDrivers are the channel types every deployment has. Their types are distinct constants,
// which TestBuiltinDriversCoverEveryChannelType checks, so New needs no duplicate handling.
func builtinDrivers(s *Sender) []Driver {
	return []Driver{webhookDriver{s}, slackDriver{s}, emailDriver{s}, teamsDriver{s}, telegramDriver{s}, googleChatDriver{s}, discordDriver{s}}
}

// Register adds a driver. Registering a second driver for a channel type is an error rather than
// a silent replacement.
func (s *Sender) Register(driver Driver) error {
	channelType := driver.ChannelType()
	if _, exists := s.drivers[channelType]; exists {
		return fmt.Errorf("notification driver for %q is already registered", channelType)
	}
	s.drivers[channelType] = driver
	s.order = append(s.order, channelType)
	return nil
}

// ChannelTypes lists every registered channel type in registration order. It is the source of the
// channel types a deployment advertises, before the operator kill switch removes any.
func (s *Sender) ChannelTypes() []notification.ChannelType {
	out := make([]notification.ChannelType, len(s.order))
	copy(out, s.order)
	return out
}

// ResolveDisabled checks the operator kill switch (SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED) against
// the registry. Every name must be a registered type, so a typo stops startup instead of leaving
// the type the operator meant to disable switched on.
func (s *Sender) ResolveDisabled(names []string) ([]notification.ChannelType, error) {
	out := make([]notification.ChannelType, 0, len(names))
	for _, name := range names {
		channelType := notification.ChannelType(name)
		if _, ok := s.drivers[channelType]; !ok {
			known := make([]string, len(s.order))
			for i, registered := range s.order {
				known[i] = string(registered)
			}
			return nil, fmt.Errorf("SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED names unknown type %q (known: %s)", name, strings.Join(known, ", "))
		}
		out = append(out, channelType)
	}
	return out, nil
}

// Send delivers one attempt through the driver registered for the channel's type.
func (s *Sender) Send(ctx context.Context, work ports.NotificationWork, config ports.NotificationChannelConfig) ports.NotificationSendResult {
	driver, ok := s.drivers[work.Channel.Type]
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "unsupported_channel"}
	}
	if config == nil || config.NotificationChannelType() != work.Channel.Type {
		return ports.NotificationSendResult{ErrorCode: "channel_config_invalid"}
	}
	return driver.Send(ctx, work, config)
}
