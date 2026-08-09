package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestAttackPathStoreRejectsMismatchedBatchAtomically(t *testing.T) {
	s := NewAttackPathStore()
	ctx := context.Background()
	valid := attackpath.Binding{TenantID: "tenant", EngagementID: "engagement", AssetID: "asset", FindingID: "finding", TargetKind: attackpath.TargetCanonical, Producer: "producer", Provenance: "provenance", Confidence: asset.EdgeObserved}
	if err := s.ReplaceBindings(ctx, valid.TenantID, valid.EngagementID, valid.Producer, []attackpath.Binding{valid}); err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string]attackpath.Binding{
		"producer":   func() attackpath.Binding { b := valid; b.Producer = "other"; return b }(),
		"tenant":     func() attackpath.Binding { b := valid; b.TenantID = "other"; return b }(),
		"engagement": func() attackpath.Binding { b := valid; b.EngagementID = "other"; return b }(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := s.ReplaceBindings(ctx, valid.TenantID, valid.EngagementID, valid.Producer, []attackpath.Binding{invalid}); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("ReplaceBindings() error = %v, want validation", err)
			}
			got, err := s.ListBindings(ctx, valid.TenantID)
			if err != nil || len(got) != 1 || got[0] != valid {
				t.Fatalf("bindings after rejected replace = %#v, %v", got, err)
			}
		})
	}
}
