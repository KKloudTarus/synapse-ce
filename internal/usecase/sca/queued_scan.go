package sca

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// StartQueuedScanWithOptions prevents inline work within a webhook transaction.
func (s *Service) StartQueuedScanWithOptions(ctx context.Context, actor string, engagementID shared.ID, req ports.AcquireRequest, opts ScanOptions) (ports.ScanJob, error) {
	if s.jobQueue == nil {
		return ports.ScanJob{}, fmt.Errorf("%w: durable scan queue is required", shared.ErrValidation)
	}
	return s.StartScanWithOptions(ctx, actor, engagementID, req, opts)
}
