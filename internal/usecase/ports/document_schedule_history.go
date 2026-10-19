package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// DocumentScheduleRunView is a safe, aggregate-only account of one scheduled
// occurrence. It deliberately excludes email recipients, owner identity, PDF
// bytes, destination configuration, and raw provider errors.
type DocumentScheduleRunView struct {
	ID             shared.ID
	DueAt          time.Time
	State          docpublish.ScheduleOccurrenceState
	ContentHash    string
	RemotePageID   string
	RemoteVersion  int
	DeliveredCount int
	UncertainCount int
	FailedCount    int
	UpdatedAt      time.Time
}

// DocumentScheduleHistoryReader exposes only bounded, tenant-scoped run state.
type DocumentScheduleHistoryReader interface {
	ListDocumentScheduleRuns(context.Context, shared.ID, shared.ID, int) ([]DocumentScheduleRunView, error)
}
