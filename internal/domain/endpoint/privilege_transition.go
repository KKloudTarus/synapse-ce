package endpoint

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

// PrivilegeTransition is a privilege or capability change attributed to a process entity (B4). Privilege
// transitions are never-sampled upstream (A0.6), so every observed one is recorded here — a privilege
// escalation must always be visible. It is an immutable record of one event, keyed for dedupe by its
// source EventID.
type PrivilegeTransition struct {
	EventID         shared.ID
	TenantID        shared.ID
	AssetID         shared.ID
	ProcessEntityID shared.ID
	// Kind is "setuid", "setresuid", or "capset".
	Kind    string
	FromUID int
	ToUID   int
	// Cap is the capability gained when Kind is "capset".
	Cap string
	// Escalation flags a transition that raises privilege (to root, or a capability gain), so a consumer
	// can surface escalations without re-deriving the rule.
	Escalation bool
	OccurredAt time.Time
}

// Validate enforces a well-formed privilege transition.
func (p PrivilegeTransition) Validate() error {
	if p.EventID.IsZero() {
		return fmt.Errorf("%w: privilege transition has no event id", shared.ErrValidation)
	}
	if p.AssetID.IsZero() {
		return fmt.Errorf("%w: privilege transition has no asset id", shared.ErrValidation)
	}
	switch p.Kind {
	case "setuid", "setresuid", "capset":
	default:
		return fmt.Errorf("%w: privilege transition has unknown kind %q", shared.ErrValidation, p.Kind)
	}
	return nil
}

// privilegeSummary renders a human summary of a privilege observation for the timeline, built from the
// OBSERVATION so it is order-independent.
func privilegeSummary(obs *telemetry.PrivilegeObservation) string {
	if obs.Kind == "capset" {
		return fmt.Sprintf("capset +%s (pid=%d)", obs.Cap, obs.PID)
	}
	return fmt.Sprintf("%s uid %d->%d (pid=%d)", obs.Kind, obs.FromUID, obs.ToUID, obs.PID)
}

// isPrivilegeEscalation reports whether a transition raises privilege (to root, or a capability gain).
func isPrivilegeEscalation(obs *telemetry.PrivilegeObservation) bool {
	if obs.Kind == "capset" {
		return obs.Cap != ""
	}
	return obs.ToUID == 0 && obs.FromUID != 0
}
