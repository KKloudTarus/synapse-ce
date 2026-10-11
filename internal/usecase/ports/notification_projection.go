package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// NotificationEventProjector completes an event before it is stored (#1344): it names the subject
// and takes the template context snapshot. The repository calls it once per new event, in the
// publishing transaction, so ctx carries that transaction.
type NotificationEventProjector interface {
	Project(ctx context.Context, e notification.Event) (notification.Event, error)
}

// NotificationRelevance answers the source facts a queued delivery is re-checked against before it
// is sent. The per-event rules that ask them live with the event builders in the notification use
// case; the store only reads the authoritative rows.
type NotificationRelevance interface {
	// ScanJobSucceeded reports whether the scan job still exists as succeeded and finished.
	ScanJobSucceeded(ctx context.Context, tenant shared.ID, scanJobID string) (bool, error)
	// SLAReminderDue reports whether the assessment is still the finding's current one, with the
	// same deadline, still in the future, and the finding still open.
	SLAReminderDue(ctx context.Context, tenant shared.ID, reminder SLAReminder) (bool, error)
	// FleetAgentLastSeen reports whether the agent is still enrolled and last seen at exactly lastSeen,
	// so the offline episode the event describes has not ended.
	FleetAgentLastSeen(ctx context.Context, tenant shared.ID, agentID string, lastSeen time.Time) (bool, error)
}

// SLAReminder identifies the assessment deadline an sla.approaching_deadline event warned about.
type SLAReminder struct {
	AssessmentID string
	EngagementID string
	FindingID    string
	Deadline     time.Time
}
