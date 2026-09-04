package assessmentsnapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxSelectedRuns    = 100
	maxSelectedLanes   = 100
	maxSelectionIDSize = 256
	maxRequestKeySize  = 128
)

var ErrIdempotencyBodyMismatch = errors.New("assessment snapshot idempotency body mismatch")

type Service struct {
	snapshots   ports.AssessmentSnapshotRepository
	cycles      ports.AssessmentCycleRepository
	engagements ports.EngagementRepository
	runs        ports.AssessmentSnapshotRunReader
	jobs        ports.ScanJobStore
	tx          ports.TenantTransactionRunner
	ids         ports.IDGenerator
	clock       ports.Clock
	audit       ports.AuditLogger
}

func NewService(snapshots ports.AssessmentSnapshotRepository, cycles ports.AssessmentCycleRepository, engagements ports.EngagementRepository, runs ports.AssessmentSnapshotRunReader, tx ports.TenantTransactionRunner, ids ports.IDGenerator, clock ports.Clock, audit ports.AuditLogger) (*Service, error) {
	if snapshots == nil || cycles == nil || engagements == nil || runs == nil || tx == nil || ids == nil || clock == nil || audit == nil {
		return nil, fmt.Errorf("%w: assessment snapshot dependencies are required", shared.ErrValidation)
	}
	return &Service{snapshots: snapshots, cycles: cycles, engagements: engagements, runs: runs, tx: tx, ids: ids, clock: clock, audit: audit}, nil
}

func (service *Service) SetScanJobStore(jobs ports.ScanJobStore) { service.jobs = jobs }

type FinalizeInput struct {
	TenantID               shared.ID
	CycleID                shared.ID
	AssessmentID           shared.ID
	SelectedRunIDs         []string
	SelectedRuns           []RunSelection
	RequestKey             string
	ExpectedDefaultVersion int64
	Actor                  string
}

type RunSelection struct {
	RunID    string
	LaneKeys []string
}

func (service *Service) Finalize(ctx context.Context, input FinalizeInput) (*domain.Snapshot, bool, error) {
	tenantID := shared.TenantOrDefault(input.TenantID)
	requestKey := strings.TrimSpace(input.RequestKey)
	actor := strings.TrimSpace(input.Actor)
	selectedRuns, err := normalizedRunSelections(input.SelectedRunIDs, input.SelectedRuns)
	if err != nil {
		return nil, false, err
	}
	if tenantID.IsZero() || input.AssessmentID.IsZero() || requestKey == "" || actor == "" {
		return nil, false, fmt.Errorf("%w: snapshot tenant, assessment, request key, and actor are required", shared.ErrValidation)
	}
	if len(requestKey) > maxRequestKeySize {
		return nil, false, fmt.Errorf("%w: snapshot request key exceeds %d bytes", shared.ErrValidation, maxRequestKeySize)
	}
	if input.ExpectedDefaultVersion < 0 {
		return nil, false, fmt.Errorf("%w: expected default version cannot be negative", shared.ErrValidation)
	}
	if input.CycleID.IsZero() {
		cycle, err := service.cycles.GetCycleByAssessment(ctx, tenantID, input.AssessmentID)
		if err != nil {
			return nil, false, err
		}
		input.CycleID = cycle.ID
	}
	selectedRuns, err = service.expandRunSelections(ctx, tenantID, input.AssessmentID, selectedRuns)
	if err != nil {
		return nil, false, err
	}
	if replay, err := service.snapshots.GetByRequestKey(ctx, tenantID, input.AssessmentID, requestKey); err == nil {
		if replay.CycleID != input.CycleID || !sameRunSelection(replay.RunReferences, selectedRuns) {
			return nil, false, idempotencyBodyMismatch()
		}
		return replay, false, nil
	} else if !errors.Is(err, shared.ErrNotFound) {
		return nil, false, err
	}

	var finalized *domain.Snapshot
	created := false
	err = service.tx.Run(ctx, tenantID, func(txCtx context.Context) error {
		cycle, err := service.cycles.LockCycleForUpdate(txCtx, tenantID, input.CycleID)
		if err != nil {
			return err
		}
		if cycle.Status != assessmentcycle.StatusOpen {
			return fmt.Errorf("%w: snapshots require an open assessment cycle", shared.ErrValidation)
		}
		if _, err := service.cycles.GetMember(txCtx, tenantID, input.CycleID, input.AssessmentID); err != nil {
			return err
		}
		assessment, err := service.engagements.GetByIDInTenant(txCtx, tenantID, input.AssessmentID)
		if err != nil {
			return err
		}
		if assessment.Status != engagement.StatusDraft && assessment.Status != engagement.StatusActive {
			return fmt.Errorf("%w: snapshots require a draft or active assessment", shared.ErrValidation)
		}

		trustedRuns := make([]domain.SelectedRun, 0, len(selectedRuns))
		for _, selection := range selectedRuns {
			runID := selection.RunID
			if service.jobs != nil {
				job, jobErr := service.jobs.GetJob(txCtx, runID)
				if jobErr == nil && job.Status == ports.ScanRunning {
					return fmt.Errorf("%w: selected scan job %q is still running", shared.ErrConflict, runID)
				}
				if jobErr != nil && !errors.Is(jobErr, shared.ErrNotFound) {
					return jobErr
				}
			}
			run, err := service.runs.GetScanRun(txCtx, tenantID, runID)
			if err != nil {
				return err
			}
			if run.EngagementID != input.AssessmentID {
				return fmt.Errorf("%w: selected scan run %q belongs to another assessment", shared.ErrValidation, runID)
			}
			selected, err := trustedSelectedRun(run, selection.LaneKeys)
			if err != nil {
				return err
			}
			trustedRuns = append(trustedRuns, selected)
		}

		now := service.clock.Now().UTC()
		candidate, err := domain.NewFinalized(tenantID, service.ids.NewID(), input.CycleID, input.AssessmentID, domain.Boundary{
			Kind: cycle.BoundaryKind, BusinessAssetID: cycle.BusinessAssetID, ProjectID: cycle.ProjectID,
		}, requestKey, actor, now, trustedRuns)
		if err != nil {
			return err
		}
		finalized, created, err = service.snapshots.CreateFinalizedCAS(txCtx, candidate, input.ExpectedDefaultVersion)
		if err != nil {
			return classifySnapshotError(err)
		}
		if !created {
			return nil
		}
		if err := service.audit.Record(txCtx, ports.AuditEntry{
			Actor: actor, Action: "assessment_snapshot.finalized", Target: finalized.ID.String(), At: now,
			Metadata: map[string]string{
				"tenant_id": tenantID.String(), "cycle_id": input.CycleID.String(), "assessment_id": input.AssessmentID.String(),
				"snapshot_number": fmt.Sprintf("%d", finalized.SnapshotNumber), "content_hash": finalized.ContentHash,
			},
		}); err != nil {
			return fmt.Errorf("audit assessment snapshot finalization: %w", err)
		}
		return nil
	})
	return finalized, created, err
}

func (service *Service) Get(ctx context.Context, tenantID, snapshotID shared.ID) (*domain.Snapshot, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || snapshotID.IsZero() {
		return nil, fmt.Errorf("%w: snapshot tenant and id are required", shared.ErrValidation)
	}
	return service.snapshots.Get(ctx, tenantID, snapshotID)
}

func (service *Service) ListByAssessment(ctx context.Context, tenantID, assessmentID shared.ID) ([]domain.Snapshot, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || assessmentID.IsZero() {
		return nil, fmt.Errorf("%w: snapshot tenant and assessment are required", shared.ErrValidation)
	}
	return service.snapshots.ListByAssessment(ctx, tenantID, assessmentID)
}

func (service *Service) GetDefault(ctx context.Context, tenantID, assessmentID shared.ID) (*domain.Snapshot, ports.AssessmentSnapshotDefault, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || assessmentID.IsZero() {
		return nil, ports.AssessmentSnapshotDefault{}, fmt.Errorf("%w: snapshot tenant and assessment are required", shared.ErrValidation)
	}
	return service.snapshots.GetDefault(ctx, tenantID, assessmentID)
}

func (service *Service) Compare(ctx context.Context, tenantID, baselineSnapshotID, currentSnapshotID shared.ID) ([]domain.DimensionComparison, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	baseline, err := service.snapshots.Get(ctx, tenantID, baselineSnapshotID)
	if err != nil {
		return nil, err
	}
	current, err := service.snapshots.Get(ctx, tenantID, currentSnapshotID)
	if err != nil {
		return nil, err
	}
	return domain.Compare(baseline, current)
}

func trustedSelectedRun(run scanrun.ScanRun, laneKeys []string) (domain.SelectedRun, error) {
	selected := domain.SelectedRun{ID: run.ID, Provenance: run.Provenance, TerminalStatus: run.TerminalStatus, Lanes: run.Lanes}
	switch run.Provenance {
	case scanrun.ProvenanceNative:
		if err := validateTrustedScanRun(run); err != nil {
			return domain.SelectedRun{}, fmt.Errorf("selected scan run %q is not trusted: %w", run.ID, err)
		}
		selected.ManifestHash, selected.Trusted = run.ManifestHash, true
	case scanrun.ProvenanceLegacy:
		selected.ManifestHash = legacyRunHash(run)
	default:
		return domain.SelectedRun{}, fmt.Errorf("%w: selected scan run provenance is invalid", shared.ErrValidation)
	}
	lanes, err := selectRunLanes(run.Lanes, laneKeys)
	if err != nil {
		return domain.SelectedRun{}, fmt.Errorf("selected scan run %q: %w", run.ID, err)
	}
	selected.Lanes = lanes
	return selected, nil
}

func validateTrustedScanRun(run scanrun.ScanRun) error {
	if err := run.Validate(); err != nil {
		return err
	}
	if run.Provenance != scanrun.ProvenanceNative || !run.TerminalStatus.IsTerminal() || !run.IsSealed() || len(run.Lanes) == 0 {
		return fmt.Errorf("%w: native run must have terminal, sealed provenance", shared.ErrValidation)
	}
	want, err := scanrun.ComputeRunManifestHash(run.Lanes)
	if err != nil {
		return err
	}
	if want == "" || want != run.ManifestHash {
		return fmt.Errorf("%w: run manifest hash mismatch", shared.ErrValidation)
	}
	return nil
}

func legacyRunHash(run scanrun.ScanRun) string {
	findingKeys := append([]string(nil), run.LegacyFindingKeys...)
	sort.Strings(findingKeys)
	payload, _ := json.Marshal(struct {
		CreatedAt    string          `json:"created_at"`
		EngagementID string          `json:"engagement_id"`
		FindingKeys  []string        `json:"finding_keys"`
		ID           string          `json:"id"`
		Manifest     json.RawMessage `json:"manifest"`
	}{run.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"), run.EngagementID.String(), findingKeys, run.ID, run.LegacyManifest})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func normalizedRunSelections(runIDs []string, selections []RunSelection) ([]RunSelection, error) {
	if len(runIDs) > 0 && len(selections) > 0 {
		return nil, fmt.Errorf("%w: use either selected run ids or selected runs", shared.ErrValidation)
	}
	if len(selections) == 0 {
		selections = make([]RunSelection, len(runIDs))
		for index, runID := range runIDs {
			selections[index].RunID = runID
		}
	}
	if len(selections) == 0 {
		return nil, fmt.Errorf("%w: at least one selected scan run is required", shared.ErrValidation)
	}
	if len(selections) > maxSelectedRuns {
		return nil, fmt.Errorf("%w: at most %d scan runs may be selected", shared.ErrValidation, maxSelectedRuns)
	}
	seen := map[string]struct{}{}
	out := make([]RunSelection, 0, len(selections))
	for _, selection := range selections {
		selection.RunID = strings.TrimSpace(selection.RunID)
		if selection.RunID == "" || len(selection.RunID) > maxSelectionIDSize {
			return nil, fmt.Errorf("%w: selected scan run id is required", shared.ErrValidation)
		}
		if _, exists := seen[selection.RunID]; exists {
			return nil, fmt.Errorf("%w: selected scan run %q is duplicated", shared.ErrValidation, selection.RunID)
		}
		seen[selection.RunID] = struct{}{}
		if len(selection.LaneKeys) > maxSelectedLanes {
			return nil, fmt.Errorf("%w: at most %d lanes may be selected per run", shared.ErrValidation, maxSelectedLanes)
		}
		laneSeen := map[string]struct{}{}
		lanes := make([]string, 0, len(selection.LaneKeys))
		for _, laneKey := range selection.LaneKeys {
			laneKey = strings.TrimSpace(laneKey)
			if laneKey == "" || len(laneKey) > maxSelectionIDSize {
				return nil, fmt.Errorf("%w: selected lane key is invalid", shared.ErrValidation)
			}
			if _, exists := laneSeen[laneKey]; exists {
				return nil, fmt.Errorf("%w: selected lane %q is duplicated", shared.ErrValidation, laneKey)
			}
			laneSeen[laneKey] = struct{}{}
			lanes = append(lanes, laneKey)
		}
		sort.Strings(lanes)
		selection.LaneKeys = lanes
		out = append(out, selection)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RunID < out[j].RunID })
	return out, nil
}

func sameRunSelection(references []domain.RunReference, selected []RunSelection) bool {
	if len(references) != len(selected) {
		return false
	}
	byRun := make(map[string]domain.RunReference, len(references))
	for _, reference := range references {
		byRun[reference.RunID] = reference
	}
	for _, selection := range selected {
		reference, ok := byRun[selection.RunID]
		if !ok {
			return false
		}
		if len(reference.LaneReferences) != len(selection.LaneKeys) {
			return false
		}
		for index, lane := range reference.LaneReferences {
			if lane.LaneKey != selection.LaneKeys[index] {
				return false
			}
		}
	}
	return true
}

func (service *Service) expandRunSelections(ctx context.Context, tenantID, assessmentID shared.ID, selections []RunSelection) ([]RunSelection, error) {
	for index := range selections {
		if len(selections[index].LaneKeys) > 0 {
			continue
		}
		run, err := service.runs.GetScanRun(ctx, tenantID, selections[index].RunID)
		if err != nil {
			return nil, err
		}
		if run.EngagementID != assessmentID {
			return nil, fmt.Errorf("%w: selected scan run %q belongs to another assessment", shared.ErrValidation, run.ID)
		}
		if len(run.Lanes) == 0 {
			return nil, fmt.Errorf("%w: selected scan run %q has no provenance lanes", shared.ErrValidation, run.ID)
		}
		laneKeys := make([]string, len(run.Lanes))
		for laneIndex, lane := range run.Lanes {
			laneKeys[laneIndex] = lane.LaneKey
		}
		sort.Strings(laneKeys)
		selections[index].LaneKeys = laneKeys
	}
	return selections, nil
}

func selectRunLanes(lanes []scanrun.Lane, selectedKeys []string) ([]scanrun.Lane, error) {
	if len(lanes) == 0 {
		return nil, fmt.Errorf("%w: selected run has no provenance lanes", shared.ErrValidation)
	}
	if len(selectedKeys) == 0 {
		return append([]scanrun.Lane(nil), lanes...), nil
	}
	byKey := make(map[string]scanrun.Lane, len(lanes))
	for _, lane := range lanes {
		byKey[lane.LaneKey] = lane
	}
	selected := make([]scanrun.Lane, 0, len(selectedKeys))
	for _, key := range selectedKeys {
		lane, ok := byKey[key]
		if !ok {
			return nil, fmt.Errorf("%w: lane %q does not belong to the run", shared.ErrValidation, key)
		}
		selected = append(selected, lane)
	}
	return selected, nil
}

func idempotencyBodyMismatch() error {
	return fmt.Errorf("%w: %w", shared.ErrConflict, ErrIdempotencyBodyMismatch)
}

func classifySnapshotError(err error) error {
	if errors.Is(err, shared.ErrConflict) && strings.Contains(err.Error(), "request key was reused with different content") {
		return idempotencyBodyMismatch()
	}
	return err
}
