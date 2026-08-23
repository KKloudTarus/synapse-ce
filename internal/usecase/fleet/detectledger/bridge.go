package detectledger

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// chainBridge adapts the evidence vault to the EvidenceChain this package consumes, via two closures the
// composition root supplies (like offensivepolicy's EvidenceChainSealer). Closures rather than an
// interface because *evidence.Service returns a domain Evidence value whose shape this package has no
// reason to know, and its Verify returns (Report, error) whose Intact=false-with-nil-error contract must
// be translated to an error at the root — the composition root knows both sides, so it bridges them.
type chainBridge struct {
	seal   func(ctx context.Context, engagementID shared.ID, kind, idempotencyKey string, content []byte, createdBy string) (shared.ID, error)
	verify func(ctx context.Context, engagementID shared.ID) error
}

var _ EvidenceChain = (*chainBridge)(nil)

// NewEvidenceChainBridge wires the seal-once and verify closures — normally over *evidence.Service
// (SealOnce and VerifyChainError) — into the EvidenceChain the ledger's write path requires. Both are
// required; a bridge that cannot seal or verify would let a detection through with no permanent record.
func NewEvidenceChainBridge(
	seal func(ctx context.Context, engagementID shared.ID, kind, idempotencyKey string, content []byte, createdBy string) (shared.ID, error),
	verify func(ctx context.Context, engagementID shared.ID) error,
) (EvidenceChain, error) {
	if seal == nil || verify == nil {
		return nil, fmt.Errorf("%w: evidence chain bridge needs both a seal and a verify function", shared.ErrValidation)
	}
	return &chainBridge{seal: seal, verify: verify}, nil
}

func (b *chainBridge) SealOnce(ctx context.Context, engagementID shared.ID, kind, idempotencyKey string, content []byte, createdBy string) (shared.ID, error) {
	if b == nil || b.seal == nil {
		// Fail closed: a chain that cannot seal must report failure, never return an empty id that would
		// let Ingest persist a projection row bound to no evidence link.
		return "", fmt.Errorf("%w: evidence chain bridge has no seal function", shared.ErrValidation)
	}
	return b.seal(ctx, engagementID, kind, idempotencyKey, content, createdBy)
}

func (b *chainBridge) Verify(ctx context.Context, engagementID shared.ID) error {
	if b == nil || b.verify == nil {
		return fmt.Errorf("%w: evidence chain bridge has no verify function", shared.ErrValidation)
	}
	return b.verify(ctx, engagementID)
}
