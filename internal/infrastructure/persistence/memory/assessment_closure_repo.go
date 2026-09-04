package memory

import (
	"context"
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentclosure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (r *AssessmentCycleRepository) NextManifestVersion(_ context.Context, tenantID, cycleID shared.ID) (int64, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || cycleID.IsZero() {
		return 0, fmt.Errorf("%w: tenant and cycle ids are required", shared.ErrValidation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cycles[tenantID][cycleID] == nil {
		return 0, fmt.Errorf("%w: assessment cycle %q not found", shared.ErrNotFound, cycleID)
	}
	return nextMemoryManifestVersion(r.closureManifests[tenantID][cycleID]), nil
}

func (r *AssessmentCycleRepository) CommitClosure(_ context.Context, commit ports.AssessmentClosureCommit) error {
	if commit.Manifest == nil || commit.Cycle == nil || commit.ExpectedCycleVersion < 1 {
		return fmt.Errorf("%w: closure manifest, cycle, and expected version are required", shared.ErrValidation)
	}
	if err := commit.Manifest.Validate(); err != nil {
		return err
	}
	if err := commit.Cycle.Validate(); err != nil {
		return err
	}
	tenantID := shared.TenantOrDefault(commit.Cycle.TenantID)
	if commit.Manifest.TenantID != tenantID || commit.Manifest.CycleID != commit.Cycle.ID || commit.Manifest.Lifecycle != assessmentclosure.LifecycleActive ||
		commit.Cycle.Status != assessmentcycle.StatusCompleted || commit.Cycle.ActiveClosureManifestID != commit.Manifest.ID ||
		commit.Manifest.CycleVersion != commit.Cycle.Version || commit.Cycle.Version != commit.ExpectedCycleVersion+1 {
		return fmt.Errorf("%w: closure manifest and completed cycle do not match", shared.ErrValidation)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	existing := r.cycles[tenantID][commit.Cycle.ID]
	if existing == nil {
		return fmt.Errorf("%w: assessment cycle %q not found", shared.ErrNotFound, commit.Cycle.ID)
	}
	if existing.Version != commit.ExpectedCycleVersion || existing.Status != assessmentcycle.StatusOpen || !existing.ActiveClosureManifestID.IsZero() {
		return fmt.Errorf("%w: assessment cycle version or closure state changed", shared.ErrConflict)
	}
	if commit.Manifest.ManifestVersion != nextMemoryManifestVersion(r.closureManifests[tenantID][commit.Cycle.ID]) {
		return fmt.Errorf("%w: closure manifest version changed", shared.ErrConflict)
	}
	for _, manifest := range r.closureManifests[tenantID][commit.Cycle.ID] {
		if manifest.Lifecycle == assessmentclosure.LifecycleActive {
			return fmt.Errorf("%w: assessment cycle already has an active closure manifest", shared.ErrConflict)
		}
	}
	if r.closureManifests[tenantID] == nil {
		r.closureManifests[tenantID] = map[shared.ID]map[shared.ID]*assessmentclosure.Manifest{}
	}
	if r.closureManifests[tenantID][commit.Cycle.ID] == nil {
		r.closureManifests[tenantID][commit.Cycle.ID] = map[shared.ID]*assessmentclosure.Manifest{}
	}
	if r.closureManifests[tenantID][commit.Cycle.ID][commit.Manifest.ID] != nil {
		return fmt.Errorf("%w: closure manifest %q already exists", shared.ErrConflict, commit.Manifest.ID)
	}
	r.closureManifests[tenantID][commit.Cycle.ID][commit.Manifest.ID] = cloneClosureManifest(commit.Manifest)
	r.cycles[tenantID][commit.Cycle.ID] = cloneCycle(commit.Cycle)
	return nil
}

func (r *AssessmentCycleRepository) ReopenClosure(_ context.Context, reopen ports.AssessmentClosureReopen) error {
	if reopen.Manifest == nil || reopen.Cycle == nil || reopen.ExpectedCycleVersion < 1 {
		return fmt.Errorf("%w: superseded manifest, cycle, and expected version are required", shared.ErrValidation)
	}
	if err := reopen.Manifest.Validate(); err != nil {
		return err
	}
	if err := reopen.Cycle.Validate(); err != nil {
		return err
	}
	tenantID := shared.TenantOrDefault(reopen.Cycle.TenantID)
	if reopen.Manifest.TenantID != tenantID || reopen.Manifest.CycleID != reopen.Cycle.ID || reopen.Manifest.Lifecycle != assessmentclosure.LifecycleSuperseded ||
		reopen.Cycle.Status != assessmentcycle.StatusOpen || !reopen.Cycle.ActiveClosureManifestID.IsZero() || reopen.Cycle.Version != reopen.ExpectedCycleVersion+1 {
		return fmt.Errorf("%w: superseded manifest and reopened cycle do not match", shared.ErrValidation)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	existingCycle := r.cycles[tenantID][reopen.Cycle.ID]
	if existingCycle == nil {
		return fmt.Errorf("%w: assessment cycle %q not found", shared.ErrNotFound, reopen.Cycle.ID)
	}
	if existingCycle.Version != reopen.ExpectedCycleVersion || existingCycle.Status != assessmentcycle.StatusCompleted || existingCycle.ActiveClosureManifestID != reopen.Manifest.ID {
		return fmt.Errorf("%w: assessment cycle version or active manifest changed", shared.ErrConflict)
	}
	existingManifest := r.closureManifests[tenantID][reopen.Cycle.ID][reopen.Manifest.ID]
	if existingManifest == nil {
		return fmt.Errorf("%w: active closure manifest %q not found", shared.ErrNotFound, reopen.Manifest.ID)
	}
	if existingManifest.Lifecycle != assessmentclosure.LifecycleActive || existingManifest.ContentHash != reopen.Manifest.ContentHash || existingManifest.CanonicalInputHash != reopen.Manifest.CanonicalInputHash {
		return fmt.Errorf("%w: active closure manifest changed", shared.ErrConflict)
	}
	r.closureManifests[tenantID][reopen.Cycle.ID][reopen.Manifest.ID] = cloneClosureManifest(reopen.Manifest)
	r.cycles[tenantID][reopen.Cycle.ID] = cloneCycle(reopen.Cycle)
	return nil
}

func (r *AssessmentCycleRepository) GetClosureManifest(_ context.Context, tenantID, cycleID, manifestID shared.ID) (*assessmentclosure.Manifest, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || cycleID.IsZero() || manifestID.IsZero() {
		return nil, fmt.Errorf("%w: tenant, cycle, and manifest ids are required", shared.ErrValidation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	manifest := r.closureManifests[tenantID][cycleID][manifestID]
	if manifest == nil {
		return nil, fmt.Errorf("%w: closure manifest %q not found", shared.ErrNotFound, manifestID)
	}
	return cloneClosureManifest(manifest), nil
}

func (r *AssessmentCycleRepository) GetActiveClosureManifest(_ context.Context, tenantID, cycleID shared.ID) (*assessmentclosure.Manifest, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || cycleID.IsZero() {
		return nil, fmt.Errorf("%w: tenant and cycle ids are required", shared.ErrValidation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, manifest := range r.closureManifests[tenantID][cycleID] {
		if manifest.Lifecycle == assessmentclosure.LifecycleActive {
			return cloneClosureManifest(manifest), nil
		}
	}
	return nil, fmt.Errorf("%w: active closure manifest not found", shared.ErrNotFound)
}

func (r *AssessmentCycleRepository) ListClosureManifests(_ context.Context, tenantID, cycleID shared.ID) ([]assessmentclosure.Manifest, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || cycleID.IsZero() {
		return nil, fmt.Errorf("%w: tenant and cycle ids are required", shared.ErrValidation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cycles[tenantID][cycleID] == nil {
		return nil, fmt.Errorf("%w: assessment cycle %q not found", shared.ErrNotFound, cycleID)
	}
	manifests := make([]assessmentclosure.Manifest, 0, len(r.closureManifests[tenantID][cycleID]))
	for _, manifest := range r.closureManifests[tenantID][cycleID] {
		manifests = append(manifests, *cloneClosureManifest(manifest))
	}
	sort.Slice(manifests, func(left, right int) bool { return manifests[left].ManifestVersion > manifests[right].ManifestVersion })
	return manifests, nil
}

func nextMemoryManifestVersion(manifests map[shared.ID]*assessmentclosure.Manifest) int64 {
	var version int64 = 1
	for _, manifest := range manifests {
		if manifest.ManifestVersion >= version {
			version = manifest.ManifestVersion + 1
		}
	}
	return version
}

func cloneClosureManifest(manifest *assessmentclosure.Manifest) *assessmentclosure.Manifest {
	if manifest == nil {
		return nil
	}
	copy := *manifest
	copy.CoverageDecisions.Initial = cloneClosureSlice(manifest.CoverageDecisions.Initial)
	copy.CoverageDecisions.Final = cloneClosureSlice(manifest.CoverageDecisions.Final)
	copy.ScopeProfileChanges = cloneClosureSlice(manifest.ScopeProfileChanges)
	copy.OverrideBlockerIDs = cloneClosureSlice(manifest.OverrideBlockerIDs)
	copy.NonFinalBranches = cloneClosureSlice(manifest.NonFinalBranches)
	copy.Path = cloneClosureSlice(manifest.Path)
	copy.References = cloneClosureSlice(manifest.References)
	for index := range copy.References {
		copy.References[index].Metadata = append([]byte(nil), manifest.References[index].Metadata...)
		if manifest.References[index].ExpiresAt != nil {
			expiresAt := *manifest.References[index].ExpiresAt
			copy.References[index].ExpiresAt = &expiresAt
		}
	}
	if manifest.SealedAt != nil {
		sealedAt := *manifest.SealedAt
		copy.SealedAt = &sealedAt
	}
	if manifest.SupersededAt != nil {
		supersededAt := *manifest.SupersededAt
		copy.SupersededAt = &supersededAt
	}
	return &copy
}

func cloneClosureSlice[T any](values []T) []T {
	if values == nil {
		return nil
	}
	return append(make([]T, 0, len(values)), values...)
}
