package assessmentcycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	closuredom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentclosure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	lineagedom "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	closureReferenceFindingObservation = "finding_observation"
	closureReferenceRetestDecision     = "retest_decision"
	closureReferenceSLAAssessment      = "sla_assessment"
	closureReferenceSLADecision        = "sla_decision"
)

type ClosureDecisionReader struct {
	lineage   ports.FindingLineageRepository
	snapshots ports.AssessmentSnapshotRepository
	retests   ports.RetestRepository
	sla       ports.SLAStore
}

func NewClosureDecisionReader(lineage ports.FindingLineageRepository, snapshots ports.AssessmentSnapshotRepository, retests ports.RetestRepository, slaStore ports.SLAStore) (*ClosureDecisionReader, error) {
	if lineage == nil || snapshots == nil || retests == nil || slaStore == nil {
		return nil, fmt.Errorf("%w: assessment closure decision dependencies are required", shared.ErrValidation)
	}
	return &ClosureDecisionReader{lineage: lineage, snapshots: snapshots, retests: retests, sla: slaStore}, nil
}

func (reader *ClosureDecisionReader) ListAssessmentClosureReferences(ctx context.Context, tenantID shared.ID, query ports.AssessmentClosureReferenceQuery) ([]closuredom.Reference, error) {
	artifacts, err := reader.artifacts(ctx, tenantID, query, true)
	if err != nil {
		return nil, err
	}
	return sortedClosureReferences(artifacts), nil
}

func (reader *ClosureDecisionReader) ResolveAssessmentClosureReference(ctx context.Context, tenantID shared.ID, query ports.AssessmentClosureReferenceQuery, expected closuredom.Reference) error {
	artifacts, err := reader.artifacts(ctx, tenantID, query, false)
	if err != nil {
		return err
	}
	actual, ok := artifacts[closureReferenceKey(expected.Kind, expected.ID)]
	if !ok {
		return fmt.Errorf("%w: closure reference %s/%s", shared.ErrNotFound, expected.Kind, expected.ID)
	}
	if actual.Version != expected.Version || actual.ContentHash != expected.ContentHash || !sameReferenceExpiry(actual.ExpiresAt, expected.ExpiresAt) {
		return fmt.Errorf("%w: closure reference %s/%s changed", shared.ErrConflict, expected.Kind, expected.ID)
	}
	return nil
}

func (reader *ClosureDecisionReader) artifacts(ctx context.Context, tenantID shared.ID, query ports.AssessmentClosureReferenceQuery, effectiveOnly bool) (map[string]closuredom.Reference, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if tenantID.IsZero() || query.CycleID.IsZero() || len(query.SnapshotIDs) == 0 || query.AsOfAt.IsZero() {
		return nil, fmt.Errorf("%w: assessment closure reference query is incomplete", shared.ErrValidation)
	}
	ctx = shared.WithTenant(ctx, tenantID)
	wantedVerifications := make(map[shared.ID]struct{}, len(query.VerificationIDs))
	for _, id := range query.VerificationIDs {
		if !id.IsZero() {
			wantedVerifications[id] = struct{}{}
		}
	}
	artifacts := map[string]closuredom.Reference{}
	type sourceFinding struct{ assessmentID, findingID shared.ID }
	sources := map[string]sourceFinding{}
	for _, snapshotID := range query.SnapshotIDs {
		snapshot, err := reader.snapshots.Get(ctx, tenantID, snapshotID)
		if err != nil {
			return nil, err
		}
		if snapshot.CycleID != query.CycleID {
			return nil, fmt.Errorf("%w: closure reference Snapshot belongs to another Cycle", shared.ErrValidation)
		}
		observations, err := reader.lineage.ListObservationsBySnapshot(ctx, tenantID, query.CycleID, snapshotID)
		if err != nil {
			return nil, err
		}
		for _, observation := range observations {
			reference, err := observationClosureReference(observation)
			if err != nil {
				return nil, err
			}
			artifacts[closureReferenceKey(reference.Kind, reference.ID)] = reference
			if observation.SourceFindingID != "" {
				findingID := shared.ID(observation.SourceFindingID)
				sources[snapshot.AssessmentID.String()+"\x00"+findingID.String()] = sourceFinding{snapshot.AssessmentID, findingID}
			}
		}
	}
	for _, source := range sources {
		retests, err := reader.retests.ListByEngagementFinding(ctx, source.assessmentID, source.findingID)
		if err != nil {
			return nil, err
		}
		for _, decision := range retests {
			if effectiveOnly {
				if _, wanted := wantedVerifications[decision.ID]; !wanted {
					continue
				}
			}
			reference, err := retestClosureReference(decision)
			if err != nil {
				return nil, err
			}
			artifacts[closureReferenceKey(reference.Kind, reference.ID)] = reference
		}

		assessments, err := reader.sla.AssessmentHistory(ctx, tenantID, source.assessmentID, source.findingID)
		if err != nil && !errors.Is(err, shared.ErrNotFound) {
			return nil, err
		}
		if effectiveOnly {
			if current, ok := effectiveSLAAssessment(assessments, query.AsOfAt); ok {
				reference, err := slaAssessmentClosureReference(current)
				if err != nil {
					return nil, err
				}
				artifacts[closureReferenceKey(reference.Kind, reference.ID)] = reference
			}
		} else {
			for _, assessment := range assessments {
				reference, err := slaAssessmentClosureReference(assessment)
				if err != nil {
					return nil, err
				}
				artifacts[closureReferenceKey(reference.Kind, reference.ID)] = reference
			}
		}

		events, err := reader.sla.LifecycleEvents(ctx, tenantID, source.assessmentID, source.findingID)
		if err != nil && !errors.Is(err, shared.ErrNotFound) {
			return nil, err
		}
		if effectiveOnly {
			if current, ok := effectiveSLAEvent(events, query.AsOfAt); ok {
				reference, err := slaDecisionClosureReference(current)
				if err != nil {
					return nil, err
				}
				artifacts[closureReferenceKey(reference.Kind, reference.ID)] = reference
			}
		} else {
			for _, event := range events {
				reference, err := slaDecisionClosureReference(event)
				if err != nil {
					return nil, err
				}
				artifacts[closureReferenceKey(reference.Kind, reference.ID)] = reference
			}
		}
	}
	if effectiveOnly {
		for verificationID := range wantedVerifications {
			if _, ok := artifacts[closureReferenceKey(closureReferenceRetestDecision, verificationID)]; !ok {
				return nil, fmt.Errorf("%w: comparison verification %s", shared.ErrNotFound, verificationID)
			}
		}
	}
	return artifacts, nil
}

func observationClosureReference(value lineagedom.Observation) (closuredom.Reference, error) {
	metadata, err := json.Marshal(struct {
		FindingKind string `json:"finding_kind"`
	}{FindingKind: value.FindingKind})
	if err != nil {
		return closuredom.Reference{}, err
	}
	return immutableClosureReference(closureReferenceFindingObservation, value.ID, 1, nil, metadata, value)
}

func retestClosureReference(value finding.Retest) (closuredom.Reference, error) {
	metadata, err := json.Marshal(struct {
		Outcome finding.RetestOutcome `json:"outcome"`
		At      time.Time             `json:"at"`
	}{Outcome: value.Outcome, At: value.At})
	if err != nil {
		return closuredom.Reference{}, err
	}
	return immutableClosureReference(closureReferenceRetestDecision, value.ID, 1, nil, metadata, value)
}

func slaAssessmentClosureReference(value sla.Assessment) (closuredom.Reference, error) {
	metadata, err := json.Marshal(struct {
		AssessedAt time.Time `json:"assessed_at"`
	}{AssessedAt: value.AssessedAt})
	if err != nil {
		return closuredom.Reference{}, err
	}
	return immutableClosureReference(closureReferenceSLAAssessment, value.ID, 1, nil, metadata, value)
}

func slaDecisionClosureReference(value sla.LifecycleEvent) (closuredom.Reference, error) {
	metadata, err := json.Marshal(struct {
		State sla.RemediationStatus `json:"state"`
		At    time.Time             `json:"at"`
	}{State: value.To, At: value.At})
	if err != nil {
		return closuredom.Reference{}, err
	}
	return immutableClosureReference(closureReferenceSLADecision, value.ID, int64(value.AfterVersion), value.AcceptanceExpiresAt, metadata, value)
}

func immutableClosureReference(kind string, id shared.ID, version int64, expiresAt *time.Time, metadata json.RawMessage, value any) (closuredom.Reference, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return closuredom.Reference{}, fmt.Errorf("marshal %s closure reference: %w", kind, err)
	}
	digest := sha256.Sum256(encoded)
	return closuredom.Reference{Kind: kind, ID: id, Version: version, ContentHash: hex.EncodeToString(digest[:]), ExpiresAt: expiresAt, Metadata: metadata}, nil
}

func effectiveSLAAssessment(items []sla.Assessment, asOf time.Time) (sla.Assessment, bool) {
	var selected sla.Assessment
	found := false
	for _, item := range items {
		if item.AssessedAt.After(asOf) {
			continue
		}
		if !found || item.AssessedAt.After(selected.AssessedAt) || item.AssessedAt.Equal(selected.AssessedAt) && item.ID > selected.ID {
			selected, found = item, true
		}
	}
	return selected, found
}

func effectiveSLAEvent(items []sla.LifecycleEvent, asOf time.Time) (sla.LifecycleEvent, bool) {
	var selected sla.LifecycleEvent
	found := false
	for _, item := range items {
		if item.At.After(asOf) {
			continue
		}
		if !found || item.AfterVersion > selected.AfterVersion || item.AfterVersion == selected.AfterVersion && (item.At.After(selected.At) || item.At.Equal(selected.At) && item.ID > selected.ID) {
			selected, found = item, true
		}
	}
	return selected, found
}

func closureReferenceKey(kind string, id shared.ID) string { return kind + "\x00" + id.String() }

func sortedClosureReferences(values map[string]closuredom.Reference) []closuredom.Reference {
	out := make([]closuredom.Reference, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	sort.Slice(out, func(left, right int) bool {
		if out[left].Kind == out[right].Kind {
			return out[left].ID < out[right].ID
		}
		return out[left].Kind < out[right].Kind
	})
	return out
}

func sameReferenceExpiry(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

var _ ports.AssessmentClosureDecisionReader = (*ClosureDecisionReader)(nil)
