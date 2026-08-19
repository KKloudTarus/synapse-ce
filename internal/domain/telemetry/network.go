package telemetry

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// NetworkObservation is a raw connect/sendmsg observation carrying the full 5-tuple and direction —
// telemetry's own type, distinct from detection.NetworkEvent. It links to the originating process by its
// stable entity id, not a bare PID.
type NetworkObservation struct {
	// Kind is "connect" or "sendmsg".
	Kind string
	// Proto is "tcp" or "udp".
	Proto string
	// Direction is "egress" or "ingress".
	Direction string
	// The 5-tuple: local and remote endpoints (LocalAddr/LocalPort may be empty/0 when the sensor sees
	// only the connect target).
	LocalAddr  string
	LocalPort  int
	RemoteAddr string
	RemotePort int
	PID        int
	// ProcessEntityID links the flow to its process; empty when the process could not be correlated.
	ProcessEntityID shared.ID
	Comm            string
}

// Validate enforces a well-formed network observation.
func (n NetworkObservation) Validate() error {
	switch n.Kind {
	case "connect", "sendmsg":
	default:
		return fmt.Errorf("%w: network observation has unknown kind %q", shared.ErrValidation, n.Kind)
	}
	switch n.Proto {
	case "tcp", "udp":
	default:
		return fmt.Errorf("%w: network observation has unknown proto %q", shared.ErrValidation, n.Proto)
	}
	switch n.Direction {
	case "egress", "ingress":
	default:
		return fmt.Errorf("%w: network observation has unknown direction %q", shared.ErrValidation, n.Direction)
	}
	if n.RemoteAddr == "" {
		return fmt.Errorf("%w: network observation has no remote address", shared.ErrValidation)
	}
	if n.RemotePort < 0 || n.RemotePort > 65535 {
		return fmt.Errorf("%w: network observation has out-of-range remote port %d", shared.ErrValidation, n.RemotePort)
	}
	if n.LocalPort < 0 || n.LocalPort > 65535 {
		return fmt.Errorf("%w: network observation has out-of-range local port %d", shared.ErrValidation, n.LocalPort)
	}
	return nil
}

func (n NetworkObservation) clone() *NetworkObservation {
	c := n
	return &c
}
