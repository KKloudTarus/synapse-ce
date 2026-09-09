package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type scanRunKey struct {
	TenantID shared.ID
	ID       string
}

// ScanRunStore is an in-memory store of scan-run manifests and sealed provenance.
type ScanRunStore struct {
	mu   sync.RWMutex
	runs map[scanRunKey]scanrun.ScanRun
}

// NewScanRunStore returns an empty in-memory scan-run store.
func NewScanRunStore() *ScanRunStore {
	return &ScanRunStore{
		runs: make(map[scanRunKey]scanrun.ScanRun),
	}
}

var (
	_ ports.ScanRunStore           = (*ScanRunStore)(nil)
	_ ports.ScanRunProvenanceStore = (*ScanRunStore)(nil)
)

// Save records a legacy scan run for backwards compatibility.
func (s *ScanRunStore) Save(ctx context.Context, run ports.ScanRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}

	manifestBytes, err := json.Marshal(run.Manifest)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	sr := scanrun.ScanRun{
		TenantID:              tenantID,
		EngagementID:          shared.ID(run.EngagementID),
		ID:                    run.ID,
		Provenance:            scanrun.ProvenanceLegacy,
		TerminalStatus:        scanrun.StatusUnknown,
		ManifestSchemaVersion: 1,
		CreatedAt:             run.CreatedAt,
		UpdatedAt:             run.CreatedAt,
		LegacyManifest:        manifestBytes,
		LegacyFindingKeys:     run.FindingKeys,
	}

	key := scanRunKey{TenantID: tenantID, ID: run.ID}
	if existing, ok := s.runs[key]; ok {
		if existing.IsSealed() {
			return fmt.Errorf("%w: cannot overwrite sealed scan run %s", shared.ErrConflict, run.ID)
		}
		return nil
	}
	s.runs[key] = sr
	return nil
}

// List returns legacy scan runs for an engagement.
func (s *ScanRunStore) List(ctx context.Context, engagementID shared.ID) ([]ports.ScanRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}

	var out []ports.ScanRun
	for key, r := range s.runs {
		if key.TenantID != tenantID {
			continue
		}
		if r.EngagementID == engagementID {
			out = append(out, toPortsScanRun(r))
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// Get returns a legacy scan run by ID.
func (s *ScanRunStore) Get(ctx context.Context, runID string) (ports.ScanRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return ports.ScanRun{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}

	for key, r := range s.runs {
		if key.TenantID == tenantID && r.ID == runID {
			return toPortsScanRun(r), nil
		}
	}
	return ports.ScanRun{}, fmt.Errorf("scan run %s: %w", runID, shared.ErrNotFound)
}

// SaveScanRun persists a tenant-owned native or legacy scan run.
func (s *ScanRunStore) SaveScanRun(ctx context.Context, run scanrun.ScanRun) error {
	if err := run.Validate(); err != nil {
		return err
	}
	if run.IsSealed() || strings.TrimSpace(run.ManifestHash) != "" || len(run.Lanes) != 0 {
		return fmt.Errorf("%w: SaveScanRun only creates unsealed headers", shared.ErrValidation)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := scanRunKey{TenantID: run.TenantID, ID: run.ID}
	if _, ok := s.runs[key]; ok {
		return fmt.Errorf("%w: scan run %s already exists", shared.ErrConflict, run.ID)
	}

	s.runs[key] = cloneScanRun(run)
	return nil
}

// GetScanRun returns a scan run with all normalized lanes scoped to tenantID.
func (s *ScanRunStore) GetScanRun(_ context.Context, tenantID shared.ID, runID string) (scanrun.ScanRun, error) {
	if tenantID.IsZero() || runID == "" {
		return scanrun.ScanRun{}, fmt.Errorf("%w: tenant ID and scan run ID are required", shared.ErrValidation)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	key := scanRunKey{TenantID: tenantID, ID: runID}
	run, ok := s.runs[key]
	if !ok {
		return scanrun.ScanRun{}, fmt.Errorf("scan run %s: %w", runID, shared.ErrNotFound)
	}
	return cloneScanRun(run), nil
}

// ListScanRuns lists all scan runs for a tenant's engagement, sorted newest first.
func (s *ScanRunStore) ListScanRuns(_ context.Context, tenantID, engagementID shared.ID) ([]scanrun.ScanRun, error) {
	if tenantID.IsZero() || engagementID.IsZero() {
		return nil, fmt.Errorf("%w: tenant ID and engagement ID are required", shared.ErrValidation)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []scanrun.ScanRun
	for key, r := range s.runs {
		if key.TenantID == tenantID && r.EngagementID == engagementID {
			out = append(out, cloneScanRun(r))
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// SealScanRun atomically seals a scan run and records its normalized lanes, versions, and stages.
func (s *ScanRunStore) SealScanRun(_ context.Context, command ports.SealScanRunCommand) error {
	tenantID := command.TenantID
	runID := command.RunID
	terminalStatus := command.TerminalStatus
	lanes := command.Lanes
	manifestSchemaVersion := command.ManifestSchemaVersion
	manifestHash := command.ManifestHash
	sealedAt := command.SealedAt
	if tenantID.IsZero() || runID == "" {
		return fmt.Errorf("%w: tenant ID and scan run ID are required", shared.ErrValidation)
	}
	if !terminalStatus.Valid() || !terminalStatus.IsTerminal() {
		return fmt.Errorf("%w: invalid terminal status %q for sealing", shared.ErrValidation, terminalStatus)
	}
	if len(lanes) == 0 || strings.TrimSpace(manifestHash) == "" {
		return fmt.Errorf("%w: at least one lane and a manifest hash are required", shared.ErrValidation)
	}
	if sealedAt.IsZero() {
		return fmt.Errorf("%w: sealed_at timestamp is required", shared.ErrValidation)
	}
	sealedAt = sealedAt.UTC().Truncate(time.Microsecond)
	computedHash, err := validateSealPayload(lanes, manifestSchemaVersion)
	if err != nil {
		return err
	}
	if computedHash != manifestHash {
		return fmt.Errorf("%w: run manifest hash mismatch", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := scanRunKey{TenantID: tenantID, ID: runID}
	existing, ok := s.runs[key]
	if !ok {
		return fmt.Errorf("scan run %s: %w", runID, shared.ErrNotFound)
	}
	if existing.Provenance != scanrun.ProvenanceNative {
		return fmt.Errorf("%w: only native scan runs can be sealed", shared.ErrValidation)
	}

	for _, lane := range lanes {
		if lane.TenantID != tenantID || lane.EngagementID != existing.EngagementID || lane.ScanRunID != runID {
			return fmt.Errorf("%w: lane %q ownership does not match scan run", shared.ErrValidation, lane.LaneKey)
		}
	}

	// Idempotency is evaluated only after the submitted facts and ownership have
	// been independently verified; a matching caller-supplied digest is not trust.
	if existing.IsSealed() {
		if existing.TerminalStatus == terminalStatus && existing.ManifestHash == manifestHash {
			return nil
		}
		return fmt.Errorf("%w: scan run %s is already sealed with different state", shared.ErrConflict, runID)
	}

	// Check lane keys uniqueness
	seenLanes := make(map[string]bool)
	for _, lane := range lanes {
		if seenLanes[lane.LaneKey] {
			return fmt.Errorf("%w: duplicate lane key %q in scan run %s", shared.ErrConflict, lane.LaneKey, runID)
		}
		seenLanes[lane.LaneKey] = true

		// Check version uniqueness
		seenVersions := make(map[string]bool)
		for _, v := range lane.Versions {
			vKey := string(v.VersionKind) + "/" + v.Name
			if seenVersions[vKey] {
				return fmt.Errorf("%w: duplicate version %q in lane %s", shared.ErrConflict, vKey, lane.LaneKey)
			}
			seenVersions[vKey] = true
		}
	}

	existing.TerminalStatus = terminalStatus
	existing.ManifestSchemaVersion = manifestSchemaVersion
	existing.ManifestHash = manifestHash
	existing.SealedAt = &sealedAt
	existing.UpdatedAt = sealedAt
	existing.Lanes = make([]scanrun.Lane, len(lanes))
	for i, l := range lanes {
		l.TenantID = tenantID
		l.EngagementID = existing.EngagementID
		l.ScanRunID = runID
		l.SealedAt = &sealedAt
		existing.Lanes[i] = cloneLane(l)
	}

	s.runs[key] = existing
	return nil
}

func validateSealPayload(lanes []scanrun.Lane, manifestSchemaVersion int) (string, error) {
	if manifestSchemaVersion < 1 {
		return "", fmt.Errorf("%w: manifest schema version must be >= 1", shared.ErrValidation)
	}
	for _, lane := range lanes {
		if err := lane.Validate(); err != nil {
			return "", err
		}
		if lane.ManifestSchemaVersion != manifestSchemaVersion {
			return "", fmt.Errorf("%w: lane %q manifest schema version does not match header", shared.ErrValidation, lane.LaneKey)
		}
		if strings.TrimSpace(lane.ManifestHash) == "" {
			return "", fmt.Errorf("%w: lane %q manifest hash is required", shared.ErrValidation, lane.LaneKey)
		}
	}
	return scanrun.ComputeRunManifestHash(lanes)
}

func toPortsScanRun(r scanrun.ScanRun) ports.ScanRun {
	var manifest ports.ScanManifest
	if len(r.LegacyManifest) > 0 {
		_ = json.Unmarshal(r.LegacyManifest, &manifest)
	}
	return ports.ScanRun{
		ID:           r.ID,
		EngagementID: r.EngagementID.String(),
		CreatedAt:    r.CreatedAt,
		Manifest:     manifest,
		FindingKeys:  append([]string(nil), r.LegacyFindingKeys...),
	}
}

func cloneLane(l scanrun.Lane) scanrun.Lane {
	out := l
	if l.FinishedAt != nil {
		t := *l.FinishedAt
		out.FinishedAt = &t
	}
	if l.SealedAt != nil {
		t := *l.SealedAt
		out.SealedAt = &t
	}
	if len(l.AuthoritativeFindingKinds) > 0 {
		out.AuthoritativeFindingKinds = append([]string(nil), l.AuthoritativeFindingKinds...)
	}
	if len(l.IncludedScope) > 0 {
		out.IncludedScope = append([]string(nil), l.IncludedScope...)
	}
	if len(l.ExcludedScope) > 0 {
		out.ExcludedScope = append([]string(nil), l.ExcludedScope...)
	}
	if len(l.Versions) > 0 {
		out.Versions = append([]scanrun.LaneVersion(nil), l.Versions...)
	}
	if len(l.Stages) > 0 {
		out.Stages = make([]scanrun.LaneStage, len(l.Stages))
		for i, stage := range l.Stages {
			out.Stages[i] = stage
			if stage.FinishedAt != nil {
				t := *stage.FinishedAt
				out.Stages[i].FinishedAt = &t
			}
		}
	}
	return out
}

func cloneScanRun(r scanrun.ScanRun) scanrun.ScanRun {
	out := r
	if r.SealedAt != nil {
		t := *r.SealedAt
		out.SealedAt = &t
	}
	if len(r.LegacyFindingKeys) > 0 {
		out.LegacyFindingKeys = append([]string(nil), r.LegacyFindingKeys...)
	}
	if len(r.LegacyManifest) > 0 {
		out.LegacyManifest = append([]byte(nil), r.LegacyManifest...)
	}
	if len(r.Lanes) > 0 {
		out.Lanes = make([]scanrun.Lane, len(r.Lanes))
		for i, l := range r.Lanes {
			out.Lanes[i] = cloneLane(l)
		}
	}
	return out
}
