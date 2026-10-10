// Package inbox serves one person's notification feed and delivery choices.
package inbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const JobKind = "personal.email"

type Service struct {
	store  ports.InboxStore
	mailer ports.PersonalNoticeMailer
	clock  ports.Clock
	// delivery reloads queued Slack and Teams messages; senders send them (#1419, #1420).
	delivery ports.PersonalDeliveryStore
	senders  map[string]ports.PersonalChannelSender
	// defaults stores the tenant defaults (#1418).
	defaults       ports.PersonalDefaultsStore
	teamsAvailable bool
}

func NewService(store ports.InboxStore, clock ports.Clock) (*Service, error) {
	if store == nil || clock == nil {
		return nil, fmt.Errorf("%w: inbox dependencies are required", shared.ErrValidation)
	}
	return &Service{store: store, clock: clock}, nil
}

func (s *Service) SetMailer(mailer ports.PersonalNoticeMailer) { s.mailer = mailer }

func (s *Service) List(ctx context.Context, tenant, user shared.ID, cursor string, unreadOnly bool, limit int) (ports.InboxPage, error) {
	if limit < 1 || limit > 50 {
		limit = 25
	}
	before, beforeID, err := decodeCursor(cursor, unreadOnly)
	if err != nil {
		return ports.InboxPage{}, err
	}
	items, err := s.store.ListInbox(ctx, shared.TenantOrDefault(tenant), user, before, beforeID, unreadOnly, limit)
	if err != nil {
		return ports.InboxPage{}, err
	}
	page := ports.InboxPage{Items: items}
	if len(items) == limit {
		last := items[len(items)-1]
		page.Next = encodeCursor(unreadOnly, last.CreatedAt, last.ID)
	}
	return page, nil
}

func (s *Service) Unread(ctx context.Context, tenant, user shared.ID) (int, error) {
	return s.store.UnreadInbox(ctx, shared.TenantOrDefault(tenant), user)
}

func (s *Service) MarkRead(ctx context.Context, tenant, user, id shared.ID) error {
	return s.store.MarkInboxRead(ctx, shared.TenantOrDefault(tenant), user, id, s.clock.Now().UTC())
}

func (s *Service) MarkAllRead(ctx context.Context, tenant, user shared.ID) error {
	return s.store.MarkInboxAllRead(ctx, shared.TenantOrDefault(tenant), user, s.clock.Now().UTC())
}

func (s *Service) Preferences(ctx context.Context, tenant, user shared.ID) ([]ports.InboxPreference, error) {
	items, err := s.store.ListInboxPreferences(ctx, shared.TenantOrDefault(tenant), user)
	if err != nil {
		return nil, err
	}
	for i := range items {
		if ok, reason := s.channelAvailable(items[i].Channel); !ok {
			items[i].Available, items[i].Reason = false, reason
		}
	}
	return items, nil
}

func (s *Service) SavePreference(ctx context.Context, tenant, user shared.ID, event notification.EventType, channel string, state notification.Preference, revision int) (ports.InboxPreference, error) {
	if !state.Valid() || !notification.PersonalChannelValid(channel) {
		return ports.InboxPreference{}, fmt.Errorf("%w: preference channel or state is invalid", shared.ErrValidation)
	}
	if notification.InAppMandatory(event) && channel == notification.PersonalInApp && state == notification.PreferenceDisabled {
		return ports.InboxPreference{}, fmt.Errorf("%w: in-app administrator notices are mandatory", shared.ErrValidation)
	}
	if ok, reason := s.channelAvailable(channel); !ok && state == notification.PreferenceEnabled {
		return ports.InboxPreference{}, fmt.Errorf("%w: %s", shared.ErrValidation, reason)
	}
	if !notification.PersonalEventConfigurable(event) || !event.Valid() || event == notification.EventTest {
		return ports.InboxPreference{}, fmt.Errorf("%w: unsupported notification preference", shared.ErrValidation)
	}
	if !notification.PersonalDeliveryAvailable(event) {
		return ports.InboxPreference{}, fmt.Errorf("%w: personal delivery is unavailable for this event", shared.ErrValidation)
	}
	saved, err := s.store.SaveInboxPreference(ctx, shared.TenantOrDefault(tenant), user, event, channel, state, revision, s.clock.Now().UTC())
	if err != nil {
		return ports.InboxPreference{}, err
	}
	// The response is the row as the preference list shows it, with the effective default and the
	// availability, so a client that merges it into its list does not lose them.
	items, err := s.Preferences(ctx, tenant, user)
	if err != nil {
		return saved, nil
	}
	for _, item := range items {
		if item.EventType == string(event) && item.Channel == channel {
			return item, nil
		}
	}
	return saved, nil
}

type mailJob struct {
	EventID        shared.ID `json:"event_id"`
	UserID         shared.ID `json:"user_id"`
	ContactID      shared.ID `json:"contact_id"`
	ContactVersion int       `json:"contact_version"`
}

func (s *Service) HandleJob(ctx context.Context, job ports.QueuedJob) error {
	channel, known := jobChannels[job.Kind]
	if !known {
		return &mailError{code: "invalid personal mail job", terminal: true}
	}
	if channel != notification.PersonalEmail {
		return s.handleChannelJob(ctx, job, channel)
	}
	var payload mailJob
	if len(job.Payload) > 512 || json.Unmarshal(job.Payload, &payload) != nil || payload.EventID.IsZero() || payload.UserID.IsZero() || payload.ContactID.IsZero() || payload.ContactVersion < 1 {
		return &mailError{code: "invalid personal mail payload", terminal: true}
	}
	recipient, title, summary, ok, err := s.store.LoadPersonalMail(ctx, job.TenantID, payload.UserID, payload.EventID, payload.ContactID, payload.ContactVersion)
	if err != nil || !ok {
		return err
	}
	if s.mailer == nil {
		return &mailError{code: "smtp_not_configured", terminal: true}
	}
	result := s.mailer.SendPersonalNotice(ctx, recipient, title, summary, payload.EventID)
	if result.ErrorCode != "" {
		return &mailError{code: result.ErrorCode, terminal: !result.Retryable}
	}
	return nil
}

type mailError struct {
	code     string
	terminal bool
	// after is the provider's wait for a rate-limited message.
	after time.Duration
}

func (e *mailError) Error() string             { return e.code }
func (e *mailError) Terminal() bool            { return e.terminal }
func (e *mailError) RetryAfter() time.Duration { return e.after }
func (e *mailError) MaxAttempts() int          { return 8 }

func encodeCursor(unread bool, at time.Time, id shared.ID) string {
	flag := "0"
	if unread {
		flag = "1"
	}
	return base64.RawURLEncoding.EncodeToString([]byte(flag + "|" + at.UTC().Format(time.RFC3339Nano) + "|" + id.String()))
}

func decodeCursor(raw string, unread bool) (time.Time, shared.ID, error) {
	if raw == "" {
		return time.Time{}, "", nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: invalid inbox cursor", shared.ErrValidation)
	}
	flag, rest, ok := strings.Cut(string(decoded), "|")
	stamp, id, okID := strings.Cut(rest, "|")
	at, err := time.Parse(time.RFC3339Nano, stamp)
	if !ok || !okID || (flag != "0" && flag != "1") || err != nil || id == "" || strings.ContainsAny(id, "\r\n") {
		return time.Time{}, "", fmt.Errorf("%w: invalid inbox cursor", shared.ErrValidation)
	}
	if (flag == "1") != unread {
		return time.Time{}, "", fmt.Errorf("%w: inbox cursor does not match the unread filter", shared.ErrValidation)
	}
	return at, shared.ID(id), nil
}
