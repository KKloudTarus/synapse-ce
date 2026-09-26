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
	before, beforeID, err := decodeCursor(cursor)
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
		page.Next = encodeCursor(last.CreatedAt, last.ID)
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
	return s.store.ListInboxPreferences(ctx, shared.TenantOrDefault(tenant), user)
}

func (s *Service) SavePreference(ctx context.Context, tenant, user shared.ID, event notification.EventType, channel string, state notification.Preference, revision int) (ports.InboxPreference, error) {
	if !state.Valid() || (channel != notification.PersonalInApp && channel != notification.PersonalEmail) {
		return ports.InboxPreference{}, fmt.Errorf("%w: preference channel or state is invalid", shared.ErrValidation)
	}
	if event == notification.EventDestinationChanged && channel == notification.PersonalInApp && state == notification.PreferenceDisabled {
		return ports.InboxPreference{}, fmt.Errorf("%w: in-app destination notices are mandatory", shared.ErrValidation)
	}
	known := event == notification.EventDestinationChanged && channel == notification.PersonalEmail
	for _, candidate := range notification.ConfigurableEvents() {
		if candidate == event {
			known = true
		}
	}
	if !known || !event.Valid() || event == notification.EventTest {
		return ports.InboxPreference{}, fmt.Errorf("%w: unsupported notification preference", shared.ErrValidation)
	}
	return s.store.SaveInboxPreference(ctx, shared.TenantOrDefault(tenant), user, event, channel, state, revision, s.clock.Now().UTC())
}

type mailJob struct {
	EventID        shared.ID `json:"event_id"`
	UserID         shared.ID `json:"user_id"`
	ContactID      shared.ID `json:"contact_id"`
	ContactVersion int       `json:"contact_version"`
}

func (s *Service) HandleJob(ctx context.Context, job ports.QueuedJob) error {
	if job.Kind != JobKind {
		return &mailError{code: "invalid personal mail job", terminal: true}
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
}

func (e *mailError) Error() string             { return e.code }
func (e *mailError) Terminal() bool            { return e.terminal }
func (e *mailError) RetryAfter() time.Duration { return 0 }
func (e *mailError) MaxAttempts() int          { return 8 }

func encodeCursor(at time.Time, id shared.ID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(at.UTC().Format(time.RFC3339Nano) + "|" + id.String()))
}

func decodeCursor(raw string) (time.Time, shared.ID, error) {
	if raw == "" {
		return time.Time{}, "", nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: invalid inbox cursor", shared.ErrValidation)
	}
	stamp, id, ok := strings.Cut(string(decoded), "|")
	at, err := time.Parse(time.RFC3339Nano, stamp)
	if !ok || err != nil || id == "" || strings.ContainsAny(id, "\r\n") {
		return time.Time{}, "", fmt.Errorf("%w: invalid inbox cursor", shared.ErrValidation)
	}
	return at, shared.ID(id), nil
}
