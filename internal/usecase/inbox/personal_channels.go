package inbox

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Personal channels beyond email (#1418, #1419, #1420): the jobs that send a personal message as a
// Slack direct message or a Teams personal chat, and the tenant defaults every person inherits.

const (
	// SlackJobKind sends one personal Slack direct message (#1419).
	SlackJobKind = "personal.slack"
	// TeamsJobKind sends one personal Microsoft Teams message (#1420).
	TeamsJobKind = "personal.teams"
)

// JobKinds lists every personal job kind this service runs.
func JobKinds() []string { return []string{JobKind, SlackJobKind, TeamsJobKind} }

var jobChannels = map[string]string{
	JobKind:      notification.PersonalEmail,
	SlackJobKind: notification.PersonalSlack,
	TeamsJobKind: notification.PersonalTeams,
}

// SetPersonalDelivery wires the send-time reload of queued personal messages.
func (s *Service) SetPersonalDelivery(store ports.PersonalDeliveryStore) { s.delivery = store }

// SetPersonalDefaults wires the tenant defaults store (#1418).
func (s *Service) SetPersonalDefaults(store ports.PersonalDefaultsStore) { s.defaults = store }

// SetPersonalSender wires the sender of one provider channel (slack or teams).
func (s *Service) SetPersonalSender(channel string, sender ports.PersonalChannelSender) {
	if s.senders == nil {
		s.senders = map[string]ports.PersonalChannelSender{}
	}
	s.senders[channel] = sender
}

// SetTeamsAvailable records whether the operator configured the Microsoft Teams bot (#1420).
// Without it Teams preferences are shown as unavailable and cannot be switched on.
func (s *Service) SetTeamsAvailable(available bool) { s.teamsAvailable = available }

// channelAvailable reports whether this deployment can deliver on a personal channel at all.
func (s *Service) channelAvailable(channel string) (bool, string) {
	if channel == notification.PersonalTeams && !s.teamsAvailable {
		return false, "Microsoft Teams personal delivery is not set up on this deployment."
	}
	return true, ""
}

func (s *Service) handleChannelJob(ctx context.Context, job ports.QueuedJob, channel string) error {
	var payload mailJob
	if len(job.Payload) > 512 || json.Unmarshal(job.Payload, &payload) != nil || payload.EventID.IsZero() || payload.UserID.IsZero() || payload.ContactID.IsZero() || payload.ContactVersion < 1 {
		return &mailError{code: "invalid personal " + channel + " payload", terminal: true}
	}
	if s.delivery == nil {
		return &mailError{code: channel + "_not_configured", terminal: true}
	}
	message, ok, err := s.delivery.LoadPersonalDelivery(ctx, job.TenantID, payload.UserID, payload.EventID, payload.ContactID, payload.ContactVersion, channel)
	if err != nil || !ok {
		return err
	}
	sender := s.senders[channel]
	if sender == nil {
		return &mailError{code: channel + "_not_configured", terminal: true}
	}
	result := sender.SendPersonal(ctx, message)
	if result.ErrorCode != "" {
		return &mailError{code: result.ErrorCode, terminal: !result.Retryable, after: result.RetryAfter}
	}
	return nil
}

// PersonalDefaults returns the tenant default of every external personal channel for every event a
// person can configure (#1418): the stored value, or the built-in one marked builtin.
func (s *Service) PersonalDefaults(ctx context.Context, tenant shared.ID) ([]notification.PersonalDefault, error) {
	if s.defaults == nil {
		return nil, fmt.Errorf("personal defaults: %w", shared.ErrNotFound)
	}
	stored, err := s.defaults.ListPersonalDefaults(ctx, shared.TenantOrDefault(tenant))
	if err != nil {
		return nil, err
	}
	byKey := map[notification.PersonalDefaultKey]notification.PersonalDefault{}
	for _, item := range stored {
		byKey[notification.PersonalDefaultKey{Event: item.EventType, Channel: item.Channel}] = item
	}
	events := append(notification.ConfigurableEvents(), notification.EventDestinationChanged, notification.EventChannelPaused)
	out := make([]notification.PersonalDefault, 0, len(events)*len(notification.ExternalPersonalChannels()))
	for _, event := range events {
		for _, channel := range notification.ExternalPersonalChannels() {
			item, ok := byKey[notification.PersonalDefaultKey{Event: event, Channel: channel}]
			if !ok {
				item = notification.PersonalDefault{EventType: event, Channel: channel, Enabled: notification.BuiltinPersonalDefault(channel), Builtin: true}
			}
			out = append(out, item)
		}
	}
	return out, nil
}

// PersonalDefaultInput changes one tenant default.
type PersonalDefaultInput struct {
	EventType notification.EventType `json:"event_type"`
	Channel   string                 `json:"channel"`
	Enabled   bool                   `json:"enabled"`
	// Revision is the revision the caller read; 0 for a built-in default.
	Revision int `json:"revision"`
}

// SavePersonalDefault changes one tenant default (#1418). It is audited by the store in the same
// transaction.
func (s *Service) SavePersonalDefault(ctx context.Context, tenant shared.ID, actor string, in PersonalDefaultInput) (notification.PersonalDefault, error) {
	if s.defaults == nil {
		return notification.PersonalDefault{}, fmt.Errorf("personal defaults: %w", shared.ErrNotFound)
	}
	if err := notification.ValidatePersonalDefault(in.EventType, in.Channel, in.Enabled); err != nil {
		return notification.PersonalDefault{}, err
	}
	if in.Revision < 0 {
		return notification.PersonalDefault{}, fmt.Errorf("%w: invalid revision", shared.ErrValidation)
	}
	actor = strings.TrimSpace(actor)
	if actor == "" || len(actor) > 200 {
		return notification.PersonalDefault{}, fmt.Errorf("%w: invalid actor", shared.ErrValidation)
	}
	return s.defaults.SavePersonalDefault(ctx, shared.TenantOrDefault(tenant), actor, in.EventType, in.Channel, in.Enabled, in.Revision, s.clock.Now().UTC())
}
