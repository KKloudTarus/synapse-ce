package sca

import (
	"context"
	"errors"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// StartQueuedScanWithOptions commits durable work without reserving the
// engagement's single running-scan slot. The worker admits each scan when that
// slot becomes free, so multi-ref pushes and updates during a scan remain queued.
func (s *Service) StartQueuedScanWithOptions(ctx context.Context, actor string, engagementID shared.ID, req ports.AcquireRequest, opts ScanOptions) (ports.ScanJob, error) {
	if s == nil || s.jobQueue == nil || s.jobs == nil || s.ids == nil {
		return ports.ScanJob{}, fmt.Errorf("%w: durable scan queue and tracking store are required", shared.ErrValidation)
	}
	return s.startScanWithOptions(ctx, actor, engagementID, req, opts, true)
}

// admitQueuedScanJob returns true for an already terminal scan. Contention is
// retryable without consuming queue delivery attempts; database errors remain
// ordinary failures. The existing unique running-scan index is the arbiter.
func (s *Service) admitQueuedScanJob(ctx context.Context, p scaJobPayload) (bool, error) {
	if s.jobs == nil || !validQueuedScanIdentity(p) {
		return false, fmt.Errorf("%w: invalid queued scan identity", shared.ErrValidation)
	}
	stored, err := s.jobs.GetJob(ctx, p.Job.ID)
	if err == nil {
		if stored.EngagementID != p.EngagementID || stored.Target != p.Job.Target || stored.Kind != p.Job.Kind {
			return false, fmt.Errorf("%w: queued scan identity changed", shared.ErrValidation)
		}
		if stored.Status != ports.ScanRunning && stored.Status != ports.ScanSucceeded && stored.Status != ports.ScanFailed {
			return false, fmt.Errorf("%w: invalid queued scan state", shared.ErrValidation)
		}
		return stored.Status == ports.ScanSucceeded || stored.Status == ports.ScanFailed, nil
	}
	if !errors.Is(err, shared.ErrNotFound) {
		return false, fmt.Errorf("load queued scan: %w", err)
	}
	if err := s.jobs.CreateRunning(ctx, p.Job); err != nil {
		if errors.Is(err, shared.ErrConflict) {
			return false, fmt.Errorf("engagement scan slot occupied: %w", ports.ErrRetryable)
		}
		return false, fmt.Errorf("admit queued scan: %w", err)
	}
	return false, nil
}

func validQueuedScanIdentity(p scaJobPayload) bool {
	return p.Job.ID != "" && p.Job.Status == ports.ScanRunning && p.Job.EngagementID == p.EngagementID && p.Job.Target == p.Req.Value && p.Job.Kind == kindOrLocal(p.Req.Kind)
}
