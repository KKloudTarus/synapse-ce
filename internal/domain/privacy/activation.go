package privacy

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Activation is one immutable active-policy pointer transition. Revision is
// monotonic per tenant, so A -> B -> A remains three independently auditable
// governance facts while an exact retry can recover the original transition.
type Activation struct {
	TenantID      shared.ID `json:"tenant_id"`
	OperationID   shared.ID `json:"operation_id"`
	Revision      uint64    `json:"revision"`
	PolicyDigest  string    `json:"policy_digest"`
	PolicyVersion string    `json:"policy_version"`
	ActivatedBy   string    `json:"activated_by"`
	ActivatedAt   time.Time `json:"activated_at"`
}

func (a Activation) Validate() error {
	if a.TenantID.IsZero() || a.OperationID.IsZero() || a.Revision == 0 || strings.TrimSpace(a.PolicyDigest) == "" ||
		strings.TrimSpace(a.PolicyVersion) == "" || strings.TrimSpace(a.ActivatedBy) == "" || a.ActivatedAt.IsZero() {
		return fmt.Errorf("%w: privacy policy activation provenance is incomplete", shared.ErrValidation)
	}
	return nil
}
