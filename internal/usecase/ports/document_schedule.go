package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// DocumentScheduleStore owns durable schedule admission, occurrence leases and
// per-recipient mail progress. Callers never derive an occurrence in memory.
type DocumentScheduleStore interface {
	SaveDocumentSchedule(context.Context, shared.ID, docpublish.Schedule, int) (docpublish.Schedule, error)
	GetDocumentSchedule(context.Context, shared.ID, shared.ID) (docpublish.Schedule, error)
	ListDocumentSchedules(context.Context, shared.ID, docpublish.Scope, shared.ID, int) ([]docpublish.Schedule, error)
	DeleteDocumentSchedule(context.Context, shared.ID, shared.ID, int, time.Time) error
	ClaimDueDocumentScheduleOccurrences(context.Context, shared.ID, int, time.Time) ([]DocumentScheduleWork, error)
	GetDocumentScheduleOccurrence(context.Context, shared.ID, shared.ID) (DocumentScheduleOccurrence, error)
	SaveDocumentScheduleOccurrence(context.Context, shared.ID, DocumentScheduleOccurrence, int, time.Time) (DocumentScheduleOccurrence, error)
	GetDocumentScheduleDelivery(context.Context, shared.ID, shared.ID, string) (DocumentScheduleDelivery, error)
	SaveDocumentScheduleDelivery(context.Context, shared.ID, DocumentScheduleDelivery, int, time.Time) (DocumentScheduleDelivery, error)
}

// DocumentScheduleWork is claimed under a durable schedule version. The store
// advances NextDueAt while admitting at most one due occurrence, preventing a
// worker restart from replaying every missed calendar period.
type DocumentScheduleWork struct {
	Schedule   docpublish.Schedule
	Occurrence DocumentScheduleOccurrence
}

type DocumentScheduleOccurrence struct {
	Occurrence     docpublish.ScheduleOccurrence
	Artifact       DocumentArtifact
	ArtifactStored bool
}

type DocumentScheduleDeliveryState string

const (
	DocumentScheduleDeliveryPending   DocumentScheduleDeliveryState = "pending"
	DocumentScheduleDeliveryInFlight  DocumentScheduleDeliveryState = "in_flight"
	DocumentScheduleDeliveryDone      DocumentScheduleDeliveryState = "done"
	DocumentScheduleDeliveryUncertain DocumentScheduleDeliveryState = "uncertain"
	DocumentScheduleDeliveryFailed    DocumentScheduleDeliveryState = "failed"
	// Rejected is a definitive SMTP refusal; unlike failed it is never retried.
	DocumentScheduleDeliveryRejected DocumentScheduleDeliveryState = "rejected"
)

type DocumentScheduleDelivery struct {
	ID            shared.ID
	TenantID      shared.ID
	OccurrenceID  shared.ID
	Recipient     string
	RecipientHash string
	MessageID     shared.ID
	State         DocumentScheduleDeliveryState
	Version       int
	LeaseUntil    *time.Time
	ErrorCode     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// DocumentScheduleChannelReader deliberately exposes only safe channel metadata.
type DocumentScheduleChannelReader interface {
	GetChannel(context.Context, shared.ID, shared.ID) (notification.Channel, error)
	ListChannels(context.Context, shared.ID) ([]notification.Channel, error)
}

// DocumentScheduleEmailConfig resolves the current recipient verification and
// relay using the existing notification service; no second SMTP secret path is
// introduced for report scheduling.
type DocumentScheduleEmailConfig interface {
	EmailChannelConfig(context.Context, NotificationWork, NotificationChannelConfig) (NotificationChannelConfig, string)
}
