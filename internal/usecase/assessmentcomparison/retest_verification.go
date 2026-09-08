package assessmentcomparison

import (
	"context"
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// RetestVerificationReader projects append-only Finding retest decisions onto
// immutable lineage identities. The newest decision along the supplied Snapshot
// order is the single effective decision for an identity.
type RetestVerificationReader struct {
	lineage   ports.FindingLineageRepository
	snapshots ports.AssessmentSnapshotRepository
	retests   ports.RetestRepository
}

func NewRetestVerificationReader(lineage ports.FindingLineageRepository, snapshots ports.AssessmentSnapshotRepository, retests ports.RetestRepository) (*RetestVerificationReader, error) {
	if lineage == nil || snapshots == nil || retests == nil {
		return nil, fmt.Errorf("%w: comparison verification dependencies are required", shared.ErrValidation)
	}
	return &RetestVerificationReader{lineage: lineage, snapshots: snapshots, retests: retests}, nil
}

func (reader *RetestVerificationReader) ListEffectiveComparisonVerifications(ctx context.Context, tenantID, cycleID shared.ID, snapshotIDs []shared.ID) ([]ports.AssessmentComparisonVerification, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || cycleID.IsZero() {
		return nil, fmt.Errorf("%w: comparison verification ownership is required", shared.ErrValidation)
	}
	if contextTenant, ok := shared.TenantFrom(ctx); ok && contextTenant != tenantID {
		return nil, fmt.Errorf("%w: comparison verification tenant mismatch", shared.ErrValidation)
	}
	ctx = shared.WithTenant(ctx, tenantID)
	type effectiveDecision struct {
		verification ports.AssessmentComparisonVerification
		order        int
		atUnixNano   int64
	}
	effective := make(map[shared.ID]effectiveDecision)
	for order, snapshotID := range snapshotIDs {
		if snapshotID.IsZero() {
			return nil, fmt.Errorf("%w: comparison verification Snapshot is required", shared.ErrValidation)
		}
		snapshot, err := reader.snapshots.Get(ctx, tenantID, snapshotID)
		if err != nil {
			return nil, err
		}
		if snapshot.CycleID != cycleID {
			return nil, fmt.Errorf("%w: comparison verification Snapshot belongs to another Cycle", shared.ErrValidation)
		}
		observations, err := reader.lineage.ListObservationsBySnapshot(ctx, tenantID, cycleID, snapshotID)
		if err != nil {
			return nil, err
		}
		latest, err := reader.latestDecisions(ctx, snapshot.AssessmentID, observations)
		if err != nil {
			return nil, err
		}
		for _, observation := range observations {
			if observation.SourceFindingID == "" {
				continue
			}
			decision, found := latest[shared.ID(observation.SourceFindingID)]
			if !found {
				continue
			}
			{
				// A prior verification cannot attest evidence captured later. Keep
				// it at the last eligible Snapshot so later detection can reopen it.
				asOf := snapshot.CreatedAt
				if snapshot.FinalizedAt != nil {
					asOf = *snapshot.FinalizedAt
				}
				if decision.At.Before(asOf) {
					continue
				}
				if !decision.Outcome.Valid() || decision.ID.IsZero() {
					return nil, fmt.Errorf("%w: persisted Finding retest decision is invalid", shared.ErrValidation)
				}
				candidate := effectiveDecision{
					verification: ports.AssessmentComparisonVerification{
						ID: decision.ID, IdentityID: observation.IdentityID, EffectiveSnapshotID: snapshotID,
						State: string(decision.Outcome), Remediated: decision.Outcome == finding.RetestRemediated,
					},
					order: order, atUnixNano: decision.At.UTC().UnixNano(),
				}
				current, exists := effective[observation.IdentityID]
				if !exists || candidate.order > current.order || (candidate.order == current.order && (candidate.atUnixNano > current.atUnixNano || (candidate.atUnixNano == current.atUnixNano && candidate.verification.ID > current.verification.ID))) {
					effective[observation.IdentityID] = candidate
				}
			}
		}
	}
	out := make([]ports.AssessmentComparisonVerification, 0, len(effective))
	for _, decision := range effective {
		out = append(out, decision.verification)
	}
	sort.Slice(out, func(left, right int) bool { return out[left].IdentityID < out[right].IdentityID })
	return out, nil
}

var _ ports.AssessmentComparisonVerificationReader = (*RetestVerificationReader)(nil)

func (reader *RetestVerificationReader) latestDecisions(ctx context.Context, assessmentID shared.ID, observations []findinglineage.Observation) (map[shared.ID]finding.Retest, error) {
	ids := make([]shared.ID, 0, len(observations))
	seen := make(map[shared.ID]bool, len(observations))
	for _, observation := range observations {
		id := shared.ID(observation.SourceFindingID)
		if !id.IsZero() && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	out := make(map[shared.ID]finding.Retest)
	if bulk, ok := reader.retests.(ports.RetestLatestReader); ok {
		for offset := 0; offset < len(ids); offset += 1000 {
			values, err := bulk.LatestByEngagementFindings(ctx, assessmentID, ids[offset:min(offset+1000, len(ids))])
			if err != nil {
				return nil, err
			}
			for id, value := range values {
				if !seen[id] || value.FindingID != id || value.EngagementID != assessmentID {
					return nil, shared.ErrValidation
				}
				out[id] = value
			}
		}
		return out, nil
	}
	// Compatibility for alternative adapters. Production memory/PostgreSQL use batches.
	for _, id := range ids {
		values, err := reader.retests.ListByEngagementFinding(ctx, assessmentID, id)
		if err != nil {
			return nil, err
		}
		for _, value := range values {
			previous, exists := out[id]
			if !exists || value.At.After(previous.At) || value.At.Equal(previous.At) && value.ID > previous.ID {
				out[id] = value
			}
		}
	}
	return out, nil
}
