package assessmentcycle

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var (
	ErrCycleNotFound             = fmt.Errorf("%w: assessment cycle not found", shared.ErrNotFound)
	ErrMemberNotFound            = fmt.Errorf("%w: cycle member not found", shared.ErrNotFound)
	ErrAssessmentAlreadyInCycle  = fmt.Errorf("%w: assessment already belongs to an assessment cycle", shared.ErrConflict)
	ErrCycleNotOpen              = fmt.Errorf("%w: assessment cycle is not open", shared.ErrValidation)
	ErrInvalidBranchHead         = fmt.Errorf("%w: target assessment is not a branch head", shared.ErrValidation)
	ErrCannotArchiveRoot         = fmt.Errorf("%w: root member cannot be archived", shared.ErrValidation)
	ErrCannotArchiveSelectedHead = fmt.Errorf("%w: currently selected head cannot be archived", shared.ErrValidation)
	ErrCycleBoundaryMismatch     = fmt.Errorf("%w: assessment does not match cycle boundary", shared.ErrValidation)
	ErrHiddenProjectContext      = fmt.Errorf("%w: hidden project analysis context assessment cannot become cycle member", shared.ErrValidation)
)
