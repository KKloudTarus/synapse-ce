package asset

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestBusinessAssetLifecycleAndVersion(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	a, err := NewBusinessAsset("a1", "t1", "mobile", "Mobile Banking", "", BusinessAssetApplication, CriticalityCritical, "appsec", nil, "alice", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, next := range []BusinessAssetLifecycle{BusinessAssetActive, BusinessAssetDecommissioning, BusinessAssetRetired} {
		if err := a.Transition(next, a.Version, "alice", now); err != nil {
			t.Fatalf("transition %s: %v", next, err)
		}
	}
	if a.AcceptsAssignments() {
		t.Fatal("retired asset accepted assignment")
	}
	if err := a.Transition(BusinessAssetActive, a.Version, "alice", now); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected terminal lifecycle validation, got %v", err)
	}
	if err := a.Update(a.Name, a.Description, a.Type, a.Criticality, a.Owner, nil, 1, "alice", now); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected version conflict, got %v", err)
	}
}
