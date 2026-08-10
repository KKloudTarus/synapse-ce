package offensivepolicy

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// EvidenceChainSealer adapts the evidence service to EvidenceSealer, sealing under the one kind this
// package documents so an auditor can find every offensive authorization by kind alone.
type EvidenceChainSealer struct {
	seal func(ctx context.Context, engagementID shared.ID, kind string, content []byte, createdBy string) (shared.ID, error)
}

// NewEvidenceChainSealer wires a seal function — normally a closure over *evidence.Service — into the
// EvidenceSealer this package requires.
//
// A function rather than an interface because the evidence service returns a domain Evidence value whose
// shape this package has no reason to know; the composition root already knows both sides, so it is the
// right place to bridge them.
func NewEvidenceChainSealer(seal func(ctx context.Context, engagementID shared.ID, kind string, content []byte, createdBy string) (shared.ID, error)) *EvidenceChainSealer {
	return &EvidenceChainSealer{seal: seal}
}

var _ EvidenceSealer = (*EvidenceChainSealer)(nil)

// SealOffensiveAuthorization seals the authorization under EvidenceKindAuthorization.
func (e *EvidenceChainSealer) SealOffensiveAuthorization(ctx context.Context, engagementID shared.ID, content []byte, createdBy string) (shared.ID, error) {
	if e == nil || e.seal == nil {
		// Fail closed: a sealer that cannot seal must report failure, because Authorize treats a seal
		// failure as a refusal and would otherwise grant a permission with no record.
		return "", shared.ErrValidation
	}
	return e.seal(ctx, engagementID, EvidenceKindAuthorization, content, createdBy)
}
