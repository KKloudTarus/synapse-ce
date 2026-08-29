package privacy

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Assignment is an immutable tenant policy version. Active selection is stored
// separately so policy history remains append-only.
type Assignment struct {
	TenantID  shared.ID `json:"tenant_id"`
	Policy    Policy    `json:"policy"`
	Digest    string    `json:"digest"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// NewAssignment validates a source-safe policy and binds its immutable digest.
func NewAssignment(
	tenantID shared.ID,
	policy Policy,
	createdBy string,
	now time.Time,
) (Assignment, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	createdBy = strings.TrimSpace(createdBy)
	if tenantID.IsZero() || createdBy == "" || now.IsZero() {
		return Assignment{}, fmt.Errorf("%w: privacy policy tenant, actor, and time are required", shared.ErrValidation)
	}
	if err := policy.ValidateSourceFloor(); err != nil {
		return Assignment{}, err
	}
	return Assignment{
		TenantID:  tenantID,
		Policy:    clonePolicy(policy),
		Digest:    RedactionPolicyDigest(policy),
		CreatedBy: createdBy,
		CreatedAt: now.UTC().Truncate(time.Microsecond),
	}, nil
}

// Validate verifies durable provenance and recomputes policy identity.
func (a Assignment) Validate() error {
	if a.TenantID.IsZero() || strings.TrimSpace(a.CreatedBy) == "" || a.CreatedAt.IsZero() {
		return fmt.Errorf("%w: privacy policy provenance is incomplete", shared.ErrValidation)
	}
	if err := a.Policy.ValidateSourceFloor(); err != nil {
		return err
	}
	if RedactionPolicyDigest(a.Policy) != a.Digest {
		return fmt.Errorf("%w: privacy policy digest does not match policy", shared.ErrValidation)
	}
	return nil
}

// SameAssignment compares the declarative immutable policy-version identity.
// CreatedAt is server-owned admission metadata: insert-first stores preserve the
// first value when a client retries the same policy under a later server clock.
func SameAssignment(left, right Assignment) bool {
	if err := left.Validate(); err != nil {
		return false
	}
	if err := right.Validate(); err != nil {
		return false
	}
	return left.TenantID == right.TenantID &&
		left.Policy.Version == right.Policy.Version &&
		left.Digest == right.Digest &&
		left.CreatedBy == right.CreatedBy
}

func clonePolicy(policy Policy) Policy {
	policy.Dispositions = cloneDispositions(policy.Dispositions)
	return policy
}

func cloneDispositions(values map[FieldCategory]FieldDisposition) map[FieldCategory]FieldDisposition {
	if values == nil {
		return nil
	}
	copied := make(map[FieldCategory]FieldDisposition, len(values))
	for category, disposition := range values {
		copied[category] = disposition
	}
	return copied
}
