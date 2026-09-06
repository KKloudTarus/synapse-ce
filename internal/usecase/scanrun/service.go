package scanrun

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service coordinates domain rules, persistence, and audit logging for scan runs and sealed provenance.
type Service struct {
	runs        ports.ScanRunProvenanceStore
	engagements ports.EngagementRepository
	tx          ports.TenantTransactionRunner
	ids         ports.IDGenerator
	clock       ports.Clock
	audit       ports.IdempotentAuditLogger
}

// NewService constructs a validated ScanRun application service.
func NewService(
	runs ports.ScanRunProvenanceStore,
	engagements ports.EngagementRepository,
	tx ports.TenantTransactionRunner,
	ids ports.IDGenerator,
	clock ports.Clock,
	audit ports.IdempotentAuditLogger,
) (*Service, error) {
	if runs == nil || engagements == nil || tx == nil || ids == nil || clock == nil || audit == nil {
		return nil, fmt.Errorf("%w: scan run service is missing a dependency", shared.ErrValidation)
	}
	return &Service{
		runs:        runs,
		engagements: engagements,
		tx:          tx,
		ids:         ids,
		clock:       clock,
		audit:       audit,
	}, nil
}

// CreateNativeScanRunInput carries arguments to create a new native scan run in building state.
type CreateNativeScanRunInput struct {
	TenantID     shared.ID `json:"tenant_id"`
	EngagementID shared.ID `json:"engagement_id"`
	RunID        string    `json:"run_id,omitempty"`
	Actor        string    `json:"actor,omitempty"`
}

// CreateNativeScanRun initializes a new native scan run header.
func (s *Service) CreateNativeScanRun(ctx context.Context, in CreateNativeScanRunInput) (scanrun.ScanRun, error) {
	if in.TenantID.IsZero() {
		return scanrun.ScanRun{}, fmt.Errorf("%w: tenant ID is required", shared.ErrValidation)
	}
	if in.EngagementID.IsZero() {
		return scanrun.ScanRun{}, fmt.Errorf("%w: engagement ID is required", shared.ErrValidation)
	}
	actor := strings.TrimSpace(in.Actor)
	if actor == "" {
		return scanrun.ScanRun{}, fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}

	runID := strings.TrimSpace(in.RunID)
	if runID == "" {
		runID = s.ids.NewID().String()
	}

	now := s.clock.Now().UTC().Truncate(time.Microsecond)
	run := scanrun.ScanRun{
		TenantID:              in.TenantID,
		EngagementID:          in.EngagementID,
		ID:                    runID,
		Provenance:            scanrun.ProvenanceNative,
		TerminalStatus:        scanrun.StatusBuilding,
		ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion,
		CreatedAt:             now,
		UpdatedAt:             now,
	}

	if err := run.Validate(); err != nil {
		return scanrun.ScanRun{}, err
	}

	err := s.tx.Run(ctx, in.TenantID, func(txCtx context.Context) error {
		// Ownership validation and persistence share the tenant-bound transaction.
		if _, err := s.engagements.GetByIDInTenant(txCtx, in.TenantID, in.EngagementID); err != nil {
			return fmt.Errorf("load engagement: %w", err)
		}
		if err := s.runs.SaveScanRun(txCtx, run); err != nil {
			return err
		}
		return s.recordAudit(txCtx, in.TenantID, ports.AuditEntry{
			Actor:  actor,
			Action: "scan_run.provenance_created",
			Target: runID,
			At:     now,
			Metadata: map[string]string{
				"idempotency_key": "scan_run.provenance_created:" + in.TenantID.String() + ":" + runID,
				"engagement_id":   in.EngagementID.String(),
				"provenance":      string(scanrun.ProvenanceNative),
			},
		})
	})
	if err != nil {
		return scanrun.ScanRun{}, err
	}

	return run, nil
}

// SealScanRunInput carries arguments to seal a scan run with its normalized producer lanes.
type SealScanRunInput struct {
	TenantID       shared.ID              `json:"tenant_id"`
	RunID          string                 `json:"run_id"`
	TerminalStatus scanrun.TerminalStatus `json:"terminal_status"`
	Lanes          []scanrun.Lane         `json:"lanes"`
	Actor          string                 `json:"actor,omitempty"`
}

// SealScanRun validates lane facts, computes manifest hashes, and atomically seals the scan run.
func (s *Service) SealScanRun(ctx context.Context, in SealScanRunInput) (scanrun.ScanRun, error) {
	if in.TenantID.IsZero() {
		return scanrun.ScanRun{}, fmt.Errorf("%w: tenant ID is required", shared.ErrValidation)
	}
	runID := strings.TrimSpace(in.RunID)
	if runID == "" {
		return scanrun.ScanRun{}, fmt.Errorf("%w: scan run ID is required", shared.ErrValidation)
	}
	if !in.TerminalStatus.Valid() || !in.TerminalStatus.IsTerminal() {
		return scanrun.ScanRun{}, fmt.Errorf("%w: invalid terminal status %q", shared.ErrValidation, in.TerminalStatus)
	}
	if len(in.Lanes) == 0 {
		return scanrun.ScanRun{}, fmt.Errorf("%w: at least one producer lane is required to seal", shared.ErrValidation)
	}
	actor := strings.TrimSpace(in.Actor)
	if actor == "" {
		return scanrun.ScanRun{}, fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}

	now := s.clock.Now().UTC().Truncate(time.Microsecond)

	// Validate lanes and compute lane manifest hashes
	preparedLanes := make([]scanrun.Lane, len(in.Lanes))
	for i, l := range in.Lanes {
		l.TenantID = in.TenantID
		l.ScanRunID = runID
		l.SealedAt = &now
		if l.FinishedAt == nil || l.FinishedAt.IsZero() {
			finish := now
			l.FinishedAt = &finish
		}
		if l.ManifestSchemaVersion < 1 {
			l.ManifestSchemaVersion = scanrun.CurrentManifestSchemaVersion
		}

		if err := l.Validate(); err != nil {
			return scanrun.ScanRun{}, fmt.Errorf("invalid lane %q: %w", l.LaneKey, err)
		}

		hash, err := scanrun.ComputeManifestHash(l)
		if err != nil {
			return scanrun.ScanRun{}, fmt.Errorf("compute lane %q manifest hash: %w", l.LaneKey, err)
		}
		l.ManifestHash = hash
		preparedLanes[i] = l
	}
	manifestSchemaVersion := preparedLanes[0].ManifestSchemaVersion
	for _, lane := range preparedLanes[1:] {
		if lane.ManifestSchemaVersion != manifestSchemaVersion {
			return scanrun.ScanRun{}, fmt.Errorf("%w: lanes use different manifest schema versions", shared.ErrValidation)
		}
	}

	manifestHash, err := scanrun.ComputeRunManifestHash(preparedLanes)
	if err != nil {
		return scanrun.ScanRun{}, fmt.Errorf("compute run manifest hash: %w", err)
	}

	var sealedRun scanrun.ScanRun
	err = s.tx.Run(ctx, in.TenantID, func(txCtx context.Context) error {
		if err := s.runs.SealScanRun(txCtx, ports.SealScanRunCommand{
			TenantID:              in.TenantID,
			RunID:                 runID,
			TerminalStatus:        in.TerminalStatus,
			Lanes:                 preparedLanes,
			ManifestSchemaVersion: manifestSchemaVersion,
			ManifestHash:          manifestHash,
			SealedAt:              now,
		}); err != nil {
			return err
		}
		var err error
		sealedRun, err = s.runs.GetScanRun(txCtx, in.TenantID, runID)
		if err != nil {
			return err
		}
		return s.recordAudit(txCtx, in.TenantID, ports.AuditEntry{
			Actor:  actor,
			Action: "scan_run.provenance_sealed",
			Target: runID,
			At:     now,
			Metadata: map[string]string{
				"idempotency_key": "scan_run.provenance_sealed:" + in.TenantID.String() + ":" + runID + ":" + manifestHash,
				"terminal_status": string(in.TerminalStatus),
				"manifest_hash":   manifestHash,
				"lane_count":      fmt.Sprintf("%d", len(preparedLanes)),
			},
		})
	})
	if err != nil {
		if errors.Is(err, shared.ErrConflict) {
			auditErr := s.recordAudit(shared.WithTenant(ctx, in.TenantID), in.TenantID, ports.AuditEntry{
				Actor:  actor,
				Action: "scan_run.provenance_conflict",
				Target: runID,
				At:     now,
				Metadata: map[string]string{
					"idempotency_key": "scan_run.provenance_conflict:" + in.TenantID.String() + ":" + runID + ":" + manifestHash,
					"reason":          "seal_conflict",
				},
			})
			if auditErr != nil {
				return scanrun.ScanRun{}, fmt.Errorf("seal scan run: %w (record conflict audit: %v)", err, auditErr)
			}
		}
		return scanrun.ScanRun{}, err
	}

	return sealedRun, nil
}

// GetScanRun retrieves a single scan run with all normalized lane facts.
func (s *Service) GetScanRun(ctx context.Context, tenantID shared.ID, runID string) (scanrun.ScanRun, error) {
	return s.runs.GetScanRun(ctx, tenantID, runID)
}

// ListScanRuns returns all scan runs for an engagement.
func (s *Service) ListScanRuns(ctx context.Context, tenantID, engagementID shared.ID) ([]scanrun.ScanRun, error) {
	return s.runs.ListScanRuns(ctx, tenantID, engagementID)
}

func (s *Service) recordAudit(ctx context.Context, tenantID shared.ID, entry ports.AuditEntry) error {
	if _, ok := shared.TenantFrom(ctx); !ok {
		ctx = shared.WithTenant(ctx, tenantID)
	}
	if err := s.audit.RecordOnce(ctx, entry); err != nil {
		return fmt.Errorf("record %s audit: %w", entry.Action, err)
	}
	return nil
}
