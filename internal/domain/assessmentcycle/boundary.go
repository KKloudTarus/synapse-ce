package assessmentcycle

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// BoundaryKind represents the frozen boundary type of an Assessment Cycle.
type BoundaryKind string

const (
	BoundaryStandalone   BoundaryKind = "standalone"
	BoundaryAsset        BoundaryKind = "asset"
	BoundaryProject      BoundaryKind = "project"
	BoundaryAssetProject BoundaryKind = "asset_project"
)

// Valid reports whether b is a recognized boundary kind.
func (b BoundaryKind) Valid() bool {
	switch b {
	case BoundaryStandalone, BoundaryAsset, BoundaryProject, BoundaryAssetProject:
		return true
	default:
		return false
	}
}

// ValidateBoundaryEnforcement verifies that the boundary kind exactly matches the provided
// businessAssetID and projectID tuple. Every mismatch is rejected.
func ValidateBoundaryEnforcement(kind BoundaryKind, businessAssetID, projectID shared.ID) error {
	if !kind.Valid() {
		return fmt.Errorf("%w: unknown boundary kind %q", shared.ErrValidation, kind)
	}

	hasAsset := !businessAssetID.IsZero()
	hasProject := !projectID.IsZero()

	switch kind {
	case BoundaryStandalone:
		if hasAsset || hasProject {
			return fmt.Errorf("%w: standalone boundary requires empty business asset and project IDs", shared.ErrValidation)
		}
	case BoundaryAsset:
		if !hasAsset || hasProject {
			return fmt.Errorf("%w: asset boundary requires business asset ID and empty project ID", shared.ErrValidation)
		}
	case BoundaryProject:
		if hasAsset || !hasProject {
			return fmt.Errorf("%w: project boundary requires project ID and empty business asset ID", shared.ErrValidation)
		}
	case BoundaryAssetProject:
		if !hasAsset || !hasProject {
			return fmt.Errorf("%w: asset_project boundary requires both business asset and project IDs", shared.ErrValidation)
		}
	}
	return nil
}
