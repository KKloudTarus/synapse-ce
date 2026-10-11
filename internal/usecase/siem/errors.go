package siemuc

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var errTenant = fmt.Errorf("%w: tenant context is required", shared.ErrValidation)

func conflict(msg string) error { return fmt.Errorf("%w: %s", shared.ErrConflict, msg) }
func missing(what string) error { return fmt.Errorf("%w: siem %s", shared.ErrNotFound, what) }
func invalid(msg string) error  { return fmt.Errorf("%w: %s", shared.ErrValidation, msg) }
func forbidden(msg string) error {
	return fmt.Errorf("%w: %s", shared.ErrForbidden, msg)
}
