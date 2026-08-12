package cspm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const cloudSnapshotEvidenceKind = "cspm_snapshot"

type snapshotEvidence struct {
	Provider  cloudposture.Provider        `json:"provider"`
	ScopeKey  string                       `json:"scope_key"`
	Complete  bool                         `json:"complete"`
	Resources []cloudposture.Resource      `json:"resources"`
	Relations []cloudposture.Relationship  `json:"relationships,omitempty"`
	Coverage  []cloudposture.CoverageIssue `json:"coverage,omitempty"`
}

// EvidenceSealer stores only sorted normalized observations, never raw SDK payloads or credentials.
type EvidenceSealer struct{ evidence ports.EvidenceAppender }

var _ ports.CloudEvidenceSealer = (*EvidenceSealer)(nil)

func NewEvidenceSealer(evidence ports.EvidenceAppender) (*EvidenceSealer, error) {
	if evidence == nil {
		return nil, fmt.Errorf("%w: CSPM evidence service is required", shared.ErrValidation)
	}
	return &EvidenceSealer{evidence: evidence}, nil
}

func (s *EvidenceSealer) SealCloudSnapshot(ctx context.Context, engagementID shared.ID, inventory cloudposture.Inventory, coverage []cloudposture.CoverageIssue, actor string) (shared.ID, string, error) {
	inventory.Sort()
	deduplicateGaps(&coverage)
	content, err := json.Marshal(snapshotEvidence{Provider: inventory.Provider, ScopeKey: inventory.ScopeKey, Complete: inventory.Complete, Resources: inventory.Resources, Relations: inventory.Relationships, Coverage: coverage})
	if err != nil {
		return "", "", fmt.Errorf("marshal CSPM snapshot: %w", err)
	}
	sealed, err := s.evidence.Seal(ctx, engagementID, cloudSnapshotEvidenceKind, content, actor)
	if err != nil {
		return "", "", err
	}
	return sealed.ID, sealed.Hash, nil
}
