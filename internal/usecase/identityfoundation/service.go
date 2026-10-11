package identityfoundation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// MaxBackfillBatches bounds one run so a misbehaving checkpoint cannot loop forever.
const MaxBackfillBatches = 100000

// BackfillOptions configures one tenant backfill.
type BackfillOptions struct {
	Actor      string
	Issuer     string
	BatchSize  int
	Lease      time.Duration
	Thresholds ports.IdentityShadowThresholds
}

// BackfillResult is the outcome of one tenant backfill.
type BackfillResult struct {
	Run    ports.IdentityBackfillRun
	Report ports.IdentityShadowReport
}

// Service runs backfill, shadow parity and person-audit delivery.
type Service struct {
	backfill ports.IdentityBackfillStore
	delivery ports.IdentityAuditDeliveryStore
	clock    ports.Clock
	ids      ports.IDGenerator
}

// NewService validates its collaborators.
func NewService(backfill ports.IdentityBackfillStore, delivery ports.IdentityAuditDeliveryStore, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if backfill == nil || delivery == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: identity foundation service requires stores, clock and ids", shared.ErrValidation)
	}
	return &Service{backfill: backfill, delivery: delivery, clock: clock, ids: ids}, nil
}

// Backfill runs one fenced, resumable pass over tenantID, then records the shadow parity report.
// A cancelled context stops between batches; the next run resumes from the committed checkpoint.
func (s *Service) Backfill(ctx context.Context, tenantID shared.ID, opts BackfillOptions) (BackfillResult, error) {
	if tenantID.IsZero() || opts.Actor == "" || opts.BatchSize < 1 || opts.Lease <= 0 {
		return BackfillResult{}, fmt.Errorf("%w: tenant, actor, batch size and lease are required", shared.ErrValidation)
	}
	run, err := s.backfill.StartRun(ctx, tenantID, s.ids.NewID(), opts.Actor, opts.BatchSize, opts.Lease, s.clock.Now().UTC())
	if err != nil {
		return BackfillResult{}, fmt.Errorf("start identity backfill: %w", err)
	}
	classify := NewClassifier(opts.Issuer)
	var runErr error
	for batches := 0; ; batches++ {
		if batches >= MaxBackfillBatches {
			runErr = fmt.Errorf("identity backfill exceeded %d batches", MaxBackfillBatches)
			break
		}
		if err := ctx.Err(); err != nil {
			runErr = err
			break
		}
		batch, err := s.backfill.ApplyBatch(ctx, &run, opts.Issuer, classify, s.clock.Now().UTC())
		if err != nil {
			runErr = err
			break
		}
		if batch.Done {
			break
		}
	}
	if runErr != nil {
		// A lost fence belongs to the newer run; a cancelled context leaves the run to expire.
		if !errors.Is(runErr, ports.ErrIdentityFenceLost) && ctx.Err() == nil {
			_ = s.backfill.FinishRun(ctx, run, runErr, s.clock.Now().UTC())
		}
		return BackfillResult{Run: run}, fmt.Errorf("identity backfill: %w", runErr)
	}
	if err := s.backfill.FinishRun(ctx, run, nil, s.clock.Now().UTC()); err != nil {
		return BackfillResult{Run: run}, fmt.Errorf("finish identity backfill: %w", err)
	}
	report, err := s.backfill.RecordShadowReport(ctx, tenantID, s.ids.NewID(), run.ID, opts.Thresholds, s.clock.Now().UTC())
	if err != nil {
		return BackfillResult{Run: run}, fmt.Errorf("record shadow report: %w", err)
	}
	return BackfillResult{Run: run, Report: report}, nil
}

// Shadow records a parity report without running a backfill.
func (s *Service) Shadow(ctx context.Context, tenantID shared.ID, thresholds ports.IdentityShadowThresholds) (ports.IdentityShadowReport, error) {
	return s.backfill.RecordShadowReport(ctx, tenantID, s.ids.NewID(), "", thresholds, s.clock.Now().UTC())
}

// Rollback drops the tenant's derived identity rows while users stays authoritative.
func (s *Service) Rollback(ctx context.Context, tenantID shared.ID, actor string) error {
	return s.backfill.Rollback(ctx, tenantID, actor, s.clock.Now().UTC())
}

// DeliverPersonAudit runs one bounded delivery pass for each tenant. It is a library call; no
// service loop is wired, so a caller owns scheduling.
func (s *Service) DeliverPersonAudit(ctx context.Context, tenants []shared.ID, limit int) (ports.IdentityDeliveryStats, error) {
	var total ports.IdentityDeliveryStats
	var combined error
	for _, tenantID := range tenants {
		stats, err := s.delivery.DeliverPersonAudit(ctx, tenantID, s.clock.Now().UTC(), limit)
		if err != nil {
			combined = errors.Join(combined, fmt.Errorf("tenant %s: %w", tenantID, err))
			continue
		}
		total.Delivered += stats.Delivered
		total.Failed += stats.Failed
		total.Exhausted += stats.Exhausted
	}
	return total, combined
}
