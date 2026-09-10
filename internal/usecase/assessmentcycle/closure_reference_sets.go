package assessmentcycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	closuredom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentclosure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const closureReferenceSetThreshold = 256

type sourceFinding struct{ assessmentID, findingID shared.ID }
type closureSourceHistory struct {
	retests     []finding.Retest
	assessments []sla.Assessment
	events      []sla.LifecycleEvent
}

func (reader *ClosureDecisionReader) histories(ctx context.Context, tenantID shared.ID, sources map[string]sourceFinding) (map[string]closureSourceHistory, error) {
	byAssessment := map[shared.ID][]shared.ID{}
	for _, source := range sources {
		byAssessment[source.assessmentID] = append(byAssessment[source.assessmentID], source.findingID)
	}
	out := map[string]closureSourceHistory{}
	for assessmentID, ids := range byAssessment {
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for start := 0; start < len(ids); start += 1000 {
			batch := ids[start:min(start+1000, len(ids))]
			retests := map[shared.ID][]finding.Retest{}
			slaHistory := ports.SLAHistoryBatch{Assessments: map[shared.ID][]sla.Assessment{}, Events: map[shared.ID][]sla.LifecycleEvent{}}
			var err error
			if bulk, ok := reader.retests.(ports.RetestHistoryBatchReader); ok {
				retests, err = bulk.RetestHistories(ctx, assessmentID, batch)
				if err != nil {
					return nil, err
				}
			} else {
				for _, id := range batch {
					retests[id], err = reader.retests.ListByEngagementFinding(ctx, assessmentID, id)
					if err != nil {
						return nil, err
					}
				}
			}
			if bulk, ok := reader.sla.(ports.SLAHistoryBatchReader); ok {
				slaHistory, err = bulk.SLAHistories(ctx, tenantID, assessmentID, batch)
				if err != nil {
					return nil, err
				}
			} else {
				for _, id := range batch {
					slaHistory.Assessments[id], err = reader.sla.AssessmentHistory(ctx, tenantID, assessmentID, id)
					if err != nil && !errors.Is(err, shared.ErrNotFound) {
						return nil, err
					}
					slaHistory.Events[id], err = reader.sla.LifecycleEvents(ctx, tenantID, assessmentID, id)
					if err != nil && !errors.Is(err, shared.ErrNotFound) {
						return nil, err
					}
				}
			}
			for _, id := range batch {
				value := closureSourceHistory{retests[id], slaHistory.Assessments[id], slaHistory.Events[id]}
				if len(value.retests)+len(value.assessments)+len(value.events) != 0 {
					out[assessmentID.String()+"\x00"+id.String()] = value
				}
			}
		}
	}
	return out, nil
}

func isClosureReferenceSet(kind string) bool {
	switch kind {
	case closureReferenceFindingObservation + "_set", closureReferenceRetestDecision + "_set", closureReferenceSLAAssessment + "_set", closureReferenceSLADecision + "_set":
		return true
	default:
		return false
	}
}

// Large cohorts retain a hash of the entire ordered reference set, not a sample.
// Resolution re-reads the immutable Snapshot sources at the manifest's as-of time
// and reconstructs exactly the same set. The earliest expiry preserves the
// fail-closed decision policy while keeping HTTP receipts and reports bounded.
func compactClosureReferences(query ports.AssessmentClosureReferenceQuery, references []closuredom.Reference) ([]closuredom.Reference, error) {
	groups := map[string][]closuredom.Reference{}
	for _, reference := range references {
		groups[reference.Kind] = append(groups[reference.Kind], reference)
	}
	out := map[string]closuredom.Reference{}
	for kind, group := range groups {
		if len(group) <= closureReferenceSetThreshold || !isClosureReferenceSet(kind+"_set") {
			for _, reference := range group {
				out[closureReferenceKey(reference.Kind, reference.ID)] = reference
			}
			continue
		}
		sort.Slice(group, func(i, j int) bool { return group[i].ID < group[j].ID })
		var expiresAt *time.Time
		for _, reference := range group {
			if reference.ExpiresAt != nil && (expiresAt == nil || reference.ExpiresAt.Before(*expiresAt)) {
				value := reference.ExpiresAt.UTC()
				expiresAt = &value
			}
		}
		metadata, err := json.Marshal(struct {
			SourceKind string `json:"source_kind"`
			Count      int    `json:"count"`
		}{kind, len(group)})
		if err != nil {
			return nil, err
		}
		idHash := sha256.Sum256([]byte(query.CycleID.String() + "\x00" + kind))
		reference, err := immutableClosureReference(kind+"_set", shared.ID(hex.EncodeToString(idHash[:16])), 1, expiresAt, metadata, group)
		if err != nil {
			return nil, err
		}
		out[closureReferenceKey(reference.Kind, reference.ID)] = reference
	}
	return sortedClosureReferences(out), nil
}
