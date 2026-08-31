package scanrun

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service coordinates domain rules, persistence, and audit logging for scan runs and sealed provenance.
type Service struct {
	runs        ports.ScanRunStore
	engagements ports.EngagementRepository
	tx          ports.TenantTransactionRunner
	ids         ports.IDGenerator
	clock       ports.Clock
	audit       ports.AuditLogger
}

// NewService constructs a validated ScanRun application service.
func NewService(
	runs ports.ScanRunStore,
	engagements ports.EngagementRepository,
	tx ports.TenantTransactionRunner,
	ids ports.IDGenerator,
	clock ports.Clock,
	audit ports.AuditLogger,
) (*Service, error) {
	if runs == nil {
		return nil, fmt.Errorf("%w: scan run store is required", shared.ErrValidation)
	}
	if clock == nil {
		return nil, fmt.Errorf("%w: clock is required", shared.ErrValidation)
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

	runID := strings.TrimSpace(in.RunID)
	if runID == "" {
		if s.ids != nil {
			runID = s.ids.NewID().String()
		} else {
			return scanrun.ScanRun{}, fmt.Errorf("%w: run ID is required", shared.ErrValidation)
		}
	}

	now := s.clock.Now().UTC()
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

	// Verify engagement exists if engagement repository is provided
	if s.engagements != nil {
		if _, err := s.engagements.GetByIDInTenant(ctx, in.TenantID, in.EngagementID); err != nil {
			return scanrun.ScanRun{}, fmt.Errorf("load engagement: %w", err)
		}
	}

	if s.tx != nil {
		err := s.tx.Run(ctx, in.TenantID, func(txCtx context.Context) error {
			return s.runs.SaveScanRun(txCtx, run)
		})
		if err != nil {
			return scanrun.ScanRun{}, err
		}
	} else {
		if err := s.runs.SaveScanRun(ctx, run); err != nil {
			return scanrun.ScanRun{}, err
		}
	}

	s.recordAudit(ctx, in.TenantID, ports.AuditEntry{
		Actor:  in.Actor,
		Action: "scan_run.provenance_created",
		Target: runID,
		At:     now,
		Metadata: map[string]string{
			"engagement_id": in.EngagementID.String(),
			"provenance":    string(scanrun.ProvenanceNative),
		},
	})

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
	if strings.TrimSpace(in.RunID) == "" {
		return scanrun.ScanRun{}, fmt.Errorf("%w: scan run ID is required", shared.ErrValidation)
	}
	if !in.TerminalStatus.Valid() || !in.TerminalStatus.IsTerminal() {
		return scanrun.ScanRun{}, fmt.Errorf("%w: invalid terminal status %q", shared.ErrValidation, in.TerminalStatus)
	}
	if len(in.Lanes) == 0 {
		return scanrun.ScanRun{}, fmt.Errorf("%w: at least one producer lane is required to seal", shared.ErrValidation)
	}

	now := s.clock.Now().UTC()

	// Validate lanes and compute lane manifest hashes
	preparedLanes := make([]scanrun.Lane, len(in.Lanes))
	for i, l := range in.Lanes {
		l.TenantID = in.TenantID
		l.ScanRunID = in.RunID
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

	manifestHash, err := scanrun.ComputeRunManifestHash(preparedLanes)
	if err != nil {
		return scanrun.ScanRun{}, fmt.Errorf("compute run manifest hash: %w", err)
	}

	if s.tx != nil {
		err := s.tx.Run(ctx, in.TenantID, func(txCtx context.Context) error {
			return s.runs.SealScanRun(txCtx, in.TenantID, in.RunID, in.TerminalStatus, preparedLanes, scanrun.CurrentManifestSchemaVersion, manifestHash, now)
		})
		if err != nil {
			s.recordAudit(ctx, in.TenantID, ports.AuditEntry{
				Actor:  in.Actor,
				Action: "scan_run.provenance_conflict",
				Target: in.RunID,
				At:     now,
				Metadata: map[string]string{
					"error": err.Error(),
				},
			})
			return scanrun.ScanRun{}, err
		}
	} else {
		if err := s.runs.SealScanRun(ctx, in.TenantID, in.RunID, in.TerminalStatus, preparedLanes, scanrun.CurrentManifestSchemaVersion, manifestHash, now); err != nil {
			s.recordAudit(ctx, in.TenantID, ports.AuditEntry{
				Actor:  in.Actor,
				Action: "scan_run.provenance_conflict",
				Target: in.RunID,
				At:     now,
				Metadata: map[string]string{
					"error": err.Error(),
				},
			})
			return scanrun.ScanRun{}, err
		}
	}

	sealedRun, err := s.runs.GetScanRun(ctx, in.TenantID, in.RunID)
	if err != nil {
		return scanrun.ScanRun{}, err
	}

	s.recordAudit(ctx, in.TenantID, ports.AuditEntry{
		Actor:  in.Actor,
		Action: "scan_run.provenance_sealed",
		Target: in.RunID,
		At:     now,
		Metadata: map[string]string{
			"terminal_status": string(in.TerminalStatus),
			"manifest_hash":   manifestHash,
			"lane_count":      fmt.Sprintf("%d", len(preparedLanes)),
		},
	})

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

func (s *Service) recordAudit(ctx context.Context, tenantID shared.ID, entry ports.AuditEntry) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Record(ctx, entry)
}
