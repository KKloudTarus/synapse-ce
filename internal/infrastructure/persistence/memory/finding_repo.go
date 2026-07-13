package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// FindingRepository is an in-memory finding store (dev/tests), deduped per
// engagement by dedup key. Replaced by Postgres when a DB is configured.
type FindingRepository struct {
	mu   sync.RWMutex
	data map[shared.ID]map[string]finding.Finding // engagementID -> dedupKey -> finding
}

// NewFindingRepository returns an empty in-memory finding repository.
func NewFindingRepository() *FindingRepository {
	return &FindingRepository{data: map[shared.ID]map[string]finding.Finding{}}
}

var _ ports.FindingRepository = (*FindingRepository)(nil)

// Upsert inserts or updates findings, deduped by (engagement, dedup key). On
// update it preserves the existing triage status + created timestamp.
func (r *FindingRepository) Upsert(_ context.Context, findings []finding.Finding) error {
	if err := validateFindingBatch(findings); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range findings {
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
			f.Status = existing.Status // preserve triage
			f.Assignee = existing.Assignee
			f.Audit.CreatedAt = existing.Audit.CreatedAt
			f.Version = existing.Version             // version is a triage token; re-scans preserve it
			f.EvidenceScore = existing.EvidenceScore // moves only via SetEvidenceScore; a re-upsert never changes it – mirrors the postgres ON CONFLICT set
		} else if f.Version <= 0 {
			f.Version = 1
		}
		byKey[key] = f
	}
	return nil
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
			r.data[engagementID][key] = f
			return f, nil
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
			r.data[engagementID][key] = f
			return f, nil
		}
	}
	return finding.Finding{}, fmt.Errorf("finding %s: %w", findingID, shared.ErrNotFound)
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
			r.data[engagementID][key] = f
			return f, nil
		}
	}
	return finding.Finding{}, fmt.Errorf("finding %s: %w", findingID, shared.ErrNotFound)
}

// ListByEngagement returns the engagement's findings, highest risk first (KEV -> EPSS x CVSS).
func (r *FindingRepository) ListByEngagement(_ context.Context, engagementID shared.ID) ([]finding.Finding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	byKey := r.data[engagementID]
	out := make([]finding.Finding, 0, len(byKey))
	for _, f := range byKey {
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
	}
	return nil
}
