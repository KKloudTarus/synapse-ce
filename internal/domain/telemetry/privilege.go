package telemetry

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// PrivilegeObservation is a raw privilege/capability-change observation (setuid/setresuid/capset) —
// telemetry's own type, distinct from detection.PrivilegeEvent. It links to the acting process by stable
// entity id.
type PrivilegeObservation struct {
	// Kind is "setuid", "setresuid", or "capset".
	Kind string
	PID  int
	// ProcessEntityID links the change to its process; empty when it could not be correlated.
	ProcessEntityID shared.ID
	Comm            string
	FromUID         int
	ToUID           int
	// Cap is the capability gained, when Kind is capset (empty otherwise).
	Cap string
}

// Validate enforces a well-formed privilege observation.
func (p PrivilegeObservation) Validate() error {
	switch p.Kind {
	case "setuid", "setresuid", "capset":
	default:
		return fmt.Errorf("%w: privilege observation has unknown kind %q", shared.ErrValidation, p.Kind)
	}
	if p.PID <= 0 {
		return fmt.Errorf("%w: privilege observation has non-positive pid %d", shared.ErrValidation, p.PID)
	}
	if p.Kind == "capset" && p.Cap == "" {
		return fmt.Errorf("%w: capset privilege observation carries no capability", shared.ErrValidation)
	}
	return nil
}

func (p PrivilegeObservation) clone() *PrivilegeObservation {
	c := p
	return &c
}
