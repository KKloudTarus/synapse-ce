package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type InboxItem struct {
	ID        shared.ID  `json:"id"`
	EventID   shared.ID  `json:"event_id"`
	EventType string     `json:"event_type"`
	Title     string     `json:"title"`
	Summary   string     `json:"summary"`
	LinkPath  string     `json:"link_path"`
	CreatedAt time.Time  `json:"created_at"`
	ReadAt    *time.Time `json:"read_at,omitempty"`
}

type InboxPage struct {
	Items []InboxItem `json:"items"`
	Next  string      `json:"next,omitempty"`
}

type InboxPreference struct {
	EventType string                  `json:"event_type"`
	Channel   string                  `json:"channel"`
	State     notification.Preference `json:"state"`
	Revision  int                     `json:"revision"`
	Mandatory bool                    `json:"mandatory"`
	Available bool                    `json:"available"`
	Reason    string                  `json:"reason,omitempty"`
}

type InboxStore interface {
	ListInbox(context.Context, shared.ID, shared.ID, time.Time, shared.ID, bool, int) ([]InboxItem, error)
	UnreadInbox(context.Context, shared.ID, shared.ID) (int, error)
	MarkInboxRead(context.Context, shared.ID, shared.ID, shared.ID, time.Time) error
	MarkInboxAllRead(context.Context, shared.ID, shared.ID, time.Time) error
	ListInboxPreferences(context.Context, shared.ID, shared.ID) ([]InboxPreference, error)
	SaveInboxPreference(context.Context, shared.ID, shared.ID, notification.EventType, string, notification.Preference, int, time.Time) (InboxPreference, error)
	LoadPersonalMail(context.Context, shared.ID, shared.ID, shared.ID, shared.ID, int) (string, string, string, bool, error)
}

type PersonalNoticeMailer interface {
	SendPersonalNotice(context.Context, string, string, string, shared.ID) NotificationSendResult
}
