package detectledger

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detectionprovenance"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ProvenanceReader exposes durable lifecycle facts without tying the HTTP adapter to persistence.
type provenanceReadStore interface {
	ListCurrent(ctx context.Context, engagementID shared.ID) ([]detectionprovenance.Current, error)
	ListTransitions(ctx context.Context, engagementID, detectionID shared.ID) ([]detectionprovenance.Transition, error)
}

type ProvenanceReader struct {
	store provenanceReadStore
}

func NewProvenanceReader(store provenanceReadStore) (*ProvenanceReader, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: provenance reader is missing a store", shared.ErrValidation)
	}
	return &ProvenanceReader{store: store}, nil
}

func (r *ProvenanceReader) ListDetectionProvenance(ctx context.Context, engagementID shared.ID) ([]detectionprovenance.Current, error) {
	if engagementID.IsZero() {
		return nil, fmt.Errorf("%w: provenance read needs an engagement", shared.ErrValidation)
	}
	current, err := r.store.ListCurrent(ctx, engagementID)
	if err != nil {
		return nil, fmt.Errorf("list detection provenance: %w", err)
	}
	return current, nil
}

func (r *ProvenanceReader) DetectionProvenanceTransitions(ctx context.Context, engagementID, detectionID shared.ID) ([]detectionprovenance.Transition, error) {
	if engagementID.IsZero() || detectionID.IsZero() {
		return nil, fmt.Errorf("%w: provenance transition read needs engagement and detection", shared.ErrValidation)
	}
	transitions, err := r.store.ListTransitions(ctx, engagementID, detectionID)
	if err != nil {
		return nil, fmt.Errorf("list detection provenance transitions: %w", err)
	}
	return transitions, nil
}

func provenanceTransition(tenant, engagement, detectionID shared.ID, sequence uint64, kind detectionprovenance.TransitionKind, status detectionprovenance.Status, evidenceID shared.ID, reason string, at ports.Clock) detectionprovenance.Transition {
	return detectionprovenance.Transition{TenantID: tenant, EngagementID: engagement, DetectionID: detectionID, Sequence: sequence, Kind: kind, Status: status, EvidenceID: evidenceID, Reason: reason, OccurredAt: at.Now().UTC()}
}

func appendProvenance(ctx context.Context, store ports.DetectionProvenanceStore, tenant, engagement, detectionID shared.ID, kind detectionprovenance.TransitionKind, status detectionprovenance.Status, evidenceID shared.ID, reason string, clock ports.Clock) error {
	if store == nil {
		return nil
	}
	transition := provenanceTransition(tenant, engagement, detectionID, 1, kind, status, evidenceID, reason, clock)
	if err := store.AppendTransition(ctx, transition); err != nil {
		return fmt.Errorf("append %s detection provenance: %w", kind, err)
	}
	return nil
}

func admitProvenance(ctx context.Context, store ports.DetectionProvenanceStore, tenant, engagement shared.ID, batch fleetagent.AgentBatchV2, item fleetagent.DetectionBatchItemV2, pendingInput []byte, clock ports.Clock) error {
	if store == nil {
		return nil
	}
	current := detectionprovenance.Current{
		TenantID: tenant, EngagementID: engagement, DetectionID: item.ID, Status: detectionprovenance.StatusPending,
		PendingInput: append([]byte(nil), pendingInput...), UpdatedAt: clock.Now().UTC(),
	}
	received := provenanceTransition(tenant, engagement, item.ID, 1, detectionprovenance.Received, detectionprovenance.StatusPending, "", "v2 batch admitted", clock)
	received.TelemetryRefs = append([]fleetagent.TelemetryReference(nil), item.TelemetryRefs...)
	received.AgentID, received.AssetID = batch.AgentID, item.AssetID
	if err := store.AdmitPending(ctx, current, received); err != nil {
		return fmt.Errorf("admit pending detection provenance: %w", err)
	}
	return nil
}

func v2RefByID(batch fleetagent.AgentBatchV2, items []fleetagent.DetectionBatchItemV2) (map[shared.ID]fleetagent.DetectionRefV2, error) {
	refs := make(map[shared.ID]fleetagent.DetectionRefV2, len(batch.Detections))
	for _, ref := range batch.Detections {
		if _, exists := refs[ref.ID]; exists {
			return nil, fmt.Errorf("%w: v2 batch repeats detection id %s", shared.ErrValidation, ref.ID)
		}
		refs[ref.ID] = ref
	}
	if len(items) != len(refs) {
		return nil, fmt.Errorf("%w: v2 batch names %d detections but %d were supplied", shared.ErrValidation, len(refs), len(items))
	}
	seen := make(map[shared.ID]struct{}, len(items))
	for _, item := range items {
		if err := item.Validate(); err != nil {
			return nil, err
		}
		ref, ok := refs[item.ID]
		if !ok {
			return nil, fmt.Errorf("%w: v2 detection %s is absent from the signed manifest", shared.ErrValidation, item.ID)
		}
		if _, exists := seen[item.ID]; exists {
			return nil, fmt.Errorf("%w: v2 detection %s was supplied more than once", shared.ErrValidation, item.ID)
		}
		bodyRef, err := item.Reference()
		if err != nil {
			return nil, err
		}
		if !sameV2Ref(ref, bodyRef) {
			return nil, fmt.Errorf("%w: v2 detection %s does not match its signed manifest", shared.ErrValidation, item.ID)
		}
		seen[item.ID] = struct{}{}
	}
	return refs, nil
}

func sameV2Ref(left, right fleetagent.DetectionRefV2) bool {
	return left.ID == right.ID && left.ContentSHA256 == right.ContentSHA256 && left.AssetID == right.AssetID &&
		left.Rulepack == right.Rulepack && left.RedactionPolicyDigest == right.RedactionPolicyDigest &&
		sameTelemetryReferences(left.TelemetryRefs, right.TelemetryRefs)
}

func sameTelemetryReferences(left, right []fleetagent.TelemetryReference) bool {
	if len(left) != len(right) {
		return false
	}
	refs := make(map[string]string, len(left))
	for _, ref := range left {
		key := fmt.Sprintf("%s/%d/%d/%s", ref.StreamID, ref.Epoch, ref.Sequence, ref.EventID)
		if _, duplicate := refs[key]; duplicate {
			return false
		}
		refs[key] = ref.Digest
	}
	for _, ref := range right {
		key := fmt.Sprintf("%s/%d/%d/%s", ref.StreamID, ref.Epoch, ref.Sequence, ref.EventID)
		if digest, ok := refs[key]; !ok || digest != ref.Digest {
			return false
		}
	}
	return true
}
