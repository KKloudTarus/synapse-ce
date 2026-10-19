package memory

import (
	"context"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.DocumentScheduleHistoryReader = (*DocumentStore)(nil)

func (s *DocumentStore) ListDocumentScheduleRuns(ctx context.Context, tenant, scheduleID shared.ID, limit int) ([]ports.DocumentScheduleRunView, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || scheduleID.IsZero() || limit < 1 || limit > 50 {
		return nil, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ports.DocumentScheduleRunView, 0, limit)
	for _, occurrence := range s.occurrences[tenant] {
		if occurrence.Occurrence.ScheduleID != scheduleID {
			continue
		}
		view := ports.DocumentScheduleRunView{ID: occurrence.Occurrence.ID, DueAt: occurrence.Occurrence.DueAt, State: occurrence.Occurrence.State, ContentHash: occurrence.Occurrence.ArtifactDigest, RemotePageID: occurrence.Occurrence.RemotePageID, RemoteVersion: occurrence.Occurrence.RemoteVersion, UpdatedAt: occurrence.Occurrence.UpdatedAt}
		for _, delivery := range s.deliveries[tenant] {
			if delivery.OccurrenceID != occurrence.Occurrence.ID {
				continue
			}
			switch delivery.State {
			case ports.DocumentScheduleDeliveryDone:
				view.DeliveredCount++
			case ports.DocumentScheduleDeliveryUncertain:
				view.UncertainCount++
			case ports.DocumentScheduleDeliveryFailed, ports.DocumentScheduleDeliveryRejected:
				view.FailedCount++
			}
		}
		out = append(out, view)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].DueAt.Equal(out[j].DueAt) {
			return out[i].DueAt.After(out[j].DueAt)
		}
		return out[i].ID > out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
