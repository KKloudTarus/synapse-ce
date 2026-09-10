package assessmentcycle_test

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestBoundaryEnforcementMatrix(t *testing.T) {
	assetID := shared.ID("asset-1")
	projectID := shared.ID("proj-1")
	zeroID := shared.ID("")

	tests := []struct {
		name      string
		kind      assessmentcycle.BoundaryKind
		assetID   shared.ID
		projectID shared.ID
		wantErr   bool
	}{
		// Standalone
		{"standalone valid", assessmentcycle.BoundaryStandalone, zeroID, zeroID, false},
		{"standalone with asset", assessmentcycle.BoundaryStandalone, assetID, zeroID, true},
		{"standalone with project", assessmentcycle.BoundaryStandalone, zeroID, projectID, true},
		{"standalone with both", assessmentcycle.BoundaryStandalone, assetID, projectID, true},

		// Asset
		{"asset valid", assessmentcycle.BoundaryAsset, assetID, zeroID, false},
		{"asset missing asset", assessmentcycle.BoundaryAsset, zeroID, zeroID, true},
		{"asset with project", assessmentcycle.BoundaryAsset, assetID, projectID, true},
		{"asset with only project", assessmentcycle.BoundaryAsset, zeroID, projectID, true},

		// Project
		{"project valid", assessmentcycle.BoundaryProject, zeroID, projectID, false},
		{"project missing project", assessmentcycle.BoundaryProject, zeroID, zeroID, true},
		{"project with asset", assessmentcycle.BoundaryProject, assetID, projectID, true},
		{"project with only asset", assessmentcycle.BoundaryProject, assetID, zeroID, true},

		// AssetProject
		{"asset_project valid", assessmentcycle.BoundaryAssetProject, assetID, projectID, false},
		{"asset_project missing asset", assessmentcycle.BoundaryAssetProject, zeroID, projectID, true},
		{"asset_project missing project", assessmentcycle.BoundaryAssetProject, assetID, zeroID, true},
		{"asset_project missing both", assessmentcycle.BoundaryAssetProject, zeroID, zeroID, true},

		// Invalid kind
		{"invalid kind", assessmentcycle.BoundaryKind("unknown"), zeroID, zeroID, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := assessmentcycle.ValidateBoundaryEnforcement(tt.kind, tt.assetID, tt.projectID)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateBoundaryEnforcement() err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("expected ErrValidation, got %v", err)
			}
		})
	}
}
