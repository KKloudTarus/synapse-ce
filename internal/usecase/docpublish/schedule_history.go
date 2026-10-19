package docpublish

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const scheduleHistoryLimit = 20

type scheduleReader interface {
	GetDocumentSchedule(context.Context, shared.ID, shared.ID) (docpublish.Schedule, error)
}

// ScheduleHistoryService first resolves the schedule in the caller's tenant,
// then reads its bounded aggregate run history. The schedule lookup prevents an
// occurrence identifier from becoming a cross-tenant history oracle.
type ScheduleHistoryService struct {
	schedules scheduleReader
	history   ports.DocumentScheduleHistoryReader
}

func NewScheduleHistoryService(schedules scheduleReader, history ports.DocumentScheduleHistoryReader) (*ScheduleHistoryService, error) {
	if schedules == nil || history == nil {
		return nil, fmt.Errorf("%w: document schedule history dependencies required", shared.ErrValidation)
	}
	return &ScheduleHistoryService{schedules: schedules, history: history}, nil
}

func (s *ScheduleHistoryService) RunHistory(ctx context.Context, tenant, scheduleID shared.ID) ([]ports.DocumentScheduleRunView, error) {
	if tenant.IsZero() || scheduleID.IsZero() {
		return nil, shared.ErrValidation
	}
	if _, err := s.schedules.GetDocumentSchedule(ctx, tenant, scheduleID); err != nil {
		return nil, err
	}
	return s.history.ListDocumentScheduleRuns(ctx, tenant, scheduleID, scheduleHistoryLimit)
}
