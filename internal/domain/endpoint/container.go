package endpoint

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ContainerInstance is a runtime container observed on the asset (B5, runtime inventory). It is projected
// from the ResourceContext every telemetry envelope already carries, so a container is inventoried the
// moment any event is seen from inside it — no separate collector. Its identity is the A1 ContainerTargetID
// (containerID + cgroupID + podUID + imageDigest), and the seen window is a min/max so it is
// order-independent. This is the runtime side that X5 (#634) fuses with installed SBOM for
// running-vs-installed exposure.
type ContainerInstance struct {
	TargetID    shared.ID
	TenantID    shared.ID
	AssetID     shared.ID
	ContainerID string
	CgroupID    uint64
	PodUID      string
	WorkloadUID string
	Namespace   string
	ImageDigest string
	Runtime     string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	// metaEventID is the EventID that last set the non-identity metadata (Namespace/WorkloadUID/Runtime) —
	// the tiebreak that keeps them reorder-invariant. Unexported bookkeeping.
	metaEventID shared.ID
}

// Validate enforces a well-formed container instance.
func (c ContainerInstance) Validate() error {
	if c.TargetID.IsZero() {
		return fmt.Errorf("%w: container instance has no target id", shared.ErrValidation)
	}
	if c.AssetID.IsZero() {
		return fmt.Errorf("%w: container instance has no asset id", shared.ErrValidation)
	}
	if c.ContainerID == "" {
		return fmt.Errorf("%w: container instance has no container id", shared.ErrValidation)
	}
	return nil
}

func (c ContainerInstance) clone() ContainerInstance { return c }
