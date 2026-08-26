package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// FindingRepository is an in-memory finding store (dev/tests), deduped per
// engagement by dedup key. Replaced by Postgres when a DB is configured.
type FindingRepository struct {
	mu                sync.RWMutex
	data              map[shared.ID]map[string]finding.Finding // engagementID -> dedupKey -> finding
	projections       map[shared.ID]map[shared.ID]ports.FindingProjectionMode
	cloudObservations *CloudObservationStore
}

// NewFindingRepository returns an empty in-memory finding repository.
func NewFindingRepository() *FindingRepository {
	return &FindingRepository{
		data:        map[shared.ID]map[string]finding.Finding{},
		projections: map[shared.ID]map[shared.ID]ports.FindingProjectionMode{},
	}
}

var _ ports.FindingRepository = (*FindingRepository)(nil)

// ClaimFindingProjection atomically selects the CapSAST projection mode for a judgment.
func (r *FindingRepository) SetCloudObservationStore(store *CloudObservationStore) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cloudObservations = store
}

func (r *FindingRepository) ClaimFindingProjection(_ context.Context, _ shared.ID, engagementID, judgmentID shared.ID, mode ports.FindingProjectionMode) error {
	if mode != ports.FindingProjectionSAST && mode != ports.FindingProjectionDAST {
		return fmt.Errorf("%w: unknown finding projection mode %q", shared.ErrValidation, mode)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	byJudgment := r.projections[engagementID]
	if byJudgment == nil {
		byJudgment = map[shared.ID]ports.FindingProjectionMode{}
		r.projections[engagementID] = byJudgment
	}
	if existing, ok := byJudgment[judgmentID]; ok && existing != mode {
		return fmt.Errorf("judgment %s already claimed for %s: %w", judgmentID, existing, shared.ErrConflict)
	}
	byJudgment[judgmentID] = mode
	return nil
}

// Upsert inserts or updates findings, deduped by (engagement, dedup key). On
// update it preserves the existing triage status + created timestamp.
func (r *FindingRepository) Upsert(_ context.Context, findings []finding.Finding) error {
	if err := validateFindingBatch(findings); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range findings {
		f = cloneFinding(f)
		byKey := r.data[f.EngagementID]
		if byKey == nil {
			byKey = map[string]finding.Finding{}
			r.data[f.EngagementID] = byKey
		}
		key := f.DedupKey
		if key == "" {
			key = f.ID.String()
		}
		if existing, ok := byKey[key]; ok {
			machineChanged := findingMachineProjectionChanged(existing, f)
			f.ID = existing.ID
			f.Status = existing.Status // preserve triage
			f.Assignee = existing.Assignee
			f.Audit.CreatedAt = existing.Audit.CreatedAt
			f.Version = existing.Version
			if machineChanged {
				f.Version++
			}
			f.EvidenceScore = existing.EvidenceScore // moves only via SetEvidenceScore; a re-upsert never changes it – mirrors the postgres ON CONFLICT set
			f.Priority = existing.Priority           // preserve promoted priority; PromotionStore.Apply is the only path that moves it
		} else if f.Version <= 0 {
			f.Version = 1
		}
		byKey[key] = cloneFinding(f)
	}
	return nil
}

func findingMachineProjectionChanged(existing, incoming finding.Finding) bool {
	return existing.Title != incoming.Title ||
		existing.Description != incoming.Description ||
		existing.Severity != incoming.Severity ||
		existing.CVSSVector != incoming.CVSSVector ||
		existing.KEV != incoming.KEV ||
		existing.RiskScore != incoming.RiskScore ||
		!sameStrings(existing.Sources, incoming.Sources) ||
		existing.Confidence != incoming.Confidence ||
		existing.Class != incoming.Class ||
		existing.Scope != incoming.Scope ||
		existing.Reachability != incoming.Reachability ||
		existing.Impact != incoming.Impact ||
		existing.Kind != incoming.Kind ||
		existing.ClassReachability != incoming.ClassReachability ||
		existing.RuleKey != incoming.RuleKey ||
		existing.AdvisoryID != incoming.AdvisoryID ||
		existing.OccurrenceID != incoming.OccurrenceID ||
		existing.ComponentFingerprint != incoming.ComponentFingerprint ||
		existing.FixedVersion != incoming.FixedVersion ||
		existing.DetectionState != incoming.DetectionState ||
		existing.RiskAssessmentID != incoming.RiskAssessmentID ||
		!finding.EqualDataFlowTrace(existing.DataFlow, incoming.DataFlow) ||
		!sameFindingTime(existing.EvaluatedAt, incoming.EvaluatedAt)
}

func cloneFinding(in finding.Finding) finding.Finding {
	out := in
	out.Sources = append([]string(nil), in.Sources...)
	if in.SourceLocation != nil {
		location := cloneFindingSourceLocation(*in.SourceLocation)
		out.SourceLocation = &location
	}
	out.DataFlow = finding.CloneDataFlowTrace(in.DataFlow)
	if in.EvaluatedAt != nil {
		value := *in.EvaluatedAt
		out.EvaluatedAt = &value
	}
	return out
}

func cloneFindingSourceLocation(in finding.SourceLocation) finding.SourceLocation {
	out := in
	if in.StartColumn != nil {
		value := *in.StartColumn
		out.StartColumn = &value
	}
	if in.EndColumn != nil {
		value := *in.EndColumn
		out.EndColumn = &value
	}
	return out
}

func sameFindingTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// UpdateStatus sets a finding's triage status with optimistic concurrency
// (expectedVersion must match the stored version), bumping the version. Returns
// shared.ErrConflict on a version mismatch, shared.ErrNotFound if absent.
func (r *FindingRepository) UpdateStatus(_ context.Context, engagementID, findingID shared.ID, status finding.Status, expectedVersion int) (finding.Finding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, f := range r.data[engagementID] {
		if f.ID == findingID {
			if f.Version != expectedVersion {
				return finding.Finding{}, fmt.Errorf("finding %s changed since you loaded it: %w", findingID, shared.ErrConflict)
			}
			f.Status = status
			f.Version++
			r.data[engagementID][key] = cloneFinding(f)
			return cloneFinding(f), nil
		}
	}
	return finding.Finding{}, fmt.Errorf("finding %s: %w", findingID, shared.ErrNotFound)
}

// SetAssignee sets a finding's assignee with the same optimistic-concurrency guard.
func (r *FindingRepository) SetAssignee(_ context.Context, engagementID, findingID shared.ID, assignee string, expectedVersion int) (finding.Finding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, f := range r.data[engagementID] {
		if f.ID == findingID {
			if f.Version != expectedVersion {
				return finding.Finding{}, fmt.Errorf("finding %s changed since you loaded it: %w", findingID, shared.ErrConflict)
			}
			f.Assignee = assignee
			f.Version++
			r.data[engagementID][key] = cloneFinding(f)
			return cloneFinding(f), nil
		}
	}
	return finding.Finding{}, fmt.Errorf("finding %s: %w", findingID, shared.ErrNotFound)
}

// GetByEngagementAndID loads a single finding by engagement and finding ID.
func (r *FindingRepository) GetByEngagementAndID(_ context.Context, engagementID, findingID shared.ID) (finding.Finding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, f := range r.data[engagementID] {
		if f.ID == findingID {
			return cloneFinding(f), nil
		}
	}
	return finding.Finding{}, fmt.Errorf("finding %s in engagement %s: %w", findingID, engagementID, shared.ErrNotFound)
}

// SetEvidenceScore sets a finding's evidence score with the same optimistic-concurrency
// guard as UpdateStatus (the adversarial-verdict path). Returns
// shared.ErrConflict on a version mismatch, shared.ErrNotFound if absent.
func (r *FindingRepository) SetEvidenceScore(_ context.Context, engagementID, findingID shared.ID, score, expectedVersion int) (finding.Finding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, f := range r.data[engagementID] {
		if f.ID == findingID {
			if f.Version != expectedVersion {
				return finding.Finding{}, fmt.Errorf("finding %s changed since you loaded it: %w", findingID, shared.ErrConflict)
			}
			f.EvidenceScore = score
			f.Version++
			r.data[engagementID][key] = cloneFinding(f)
			return cloneFinding(f), nil
		}
	}
	return finding.Finding{}, fmt.Errorf("finding %s: %w", findingID, shared.ErrNotFound)
}

// setPriorityInternal sets a finding's priority and increments its version. It
// is package-private: only PromotionStore.Apply calls it after its own lock
// acquisition and priority/version verification. The caller MUST hold
// PromotionStore.mu; this method acquires FindingRepository.mu (lock ordering:
// PromotionStore.mu before FindingRepository.mu).
func (r *FindingRepository) setPriorityInternal(engagementID, findingID shared.ID, priority, expectedVersion int) (finding.Finding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, f := range r.data[engagementID] {
		if f.ID == findingID {
			if f.Version != expectedVersion {
				return finding.Finding{}, fmt.Errorf("finding %s changed since you loaded it: %w", findingID, shared.ErrConflict)
			}
			f.Priority = priority
			f.Version++
			r.data[engagementID][key] = cloneFinding(f)
			return cloneFinding(f), nil
		}
	}
	return finding.Finding{}, fmt.Errorf("finding %s: %w", findingID, shared.ErrNotFound)
}

// ListByEngagement returns the engagement's findings, highest risk first (KEV -> EPSS x CVSS).
func (r *FindingRepository) ListByEngagement(ctx context.Context, engagementID shared.ID) ([]finding.Finding, error) {
	r.mu.RLock()
	byKey := r.data[engagementID]
	observationStore := r.cloudObservations
	candidates := make([]finding.Finding, 0, len(byKey))
	for _, f := range byKey {
		candidates = append(candidates, cloneFinding(f))
	}
	r.mu.RUnlock()
	tenantID, _ := shared.TenantFrom(ctx)
	out := make([]finding.Finding, 0, len(candidates))
	for _, f := range candidates {
		if f.Kind == finding.KindCloudPosture && (observationStore == nil || tenantID.IsZero() || !observationStore.FindingActive(tenantID, engagementID, f.ID)) {
			continue
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.KEV != b.KEV {
			return a.KEV
		}
		if a.RiskScore != b.RiskScore {
			return a.RiskScore > b.RiskScore
		}
		if ra, rb := shared.SeverityRank(a.Severity), shared.SeverityRank(b.Severity); ra != rb {
			return ra > rb
		}
		return a.Title < b.Title
	})
	return out, nil
}

// ListPublishableByEngagement returns only the engagement's findings that clear the
// evidence gate, reusing the single domain rule finding.Publishable.
func (r *FindingRepository) ListPublishableByEngagement(ctx context.Context, engagementID shared.ID) ([]finding.Finding, error) {
	all, err := r.ListByEngagement(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	return finding.Publishable(all), nil
}

// validateFindingBatch asserts domain invariants (like RuleKey constraints) for a
// batch before writing to the database. An atomic failure prevents partial writes.
func validateFindingBatch(findings []finding.Finding) error {
	for _, f := range findings {
		if err := f.ValidateRuleKey(); err != nil {
			return fmt.Errorf("finding %s (kind %s): %w", f.DedupKey, f.Kind, err)
		}
		if f.DataFlow != nil {
			if err := f.DataFlow.Validate(); err != nil {
				return fmt.Errorf("finding %s data flow: %w", f.DedupKey, err)
			}
		}
	}
	return nil
}
