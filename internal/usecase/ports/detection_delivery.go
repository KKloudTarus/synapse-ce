package ports

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// DetectionDeliveryStateVersion is the on-disk schema understood by the agent detection shipper.
const DetectionDeliveryStateVersion = 1

// DetectionTransport is the agent-plane surface used to register a purpose-bound signing key and
// deliver the batches covered by that key.
type DetectionTransport interface {
	RegisterDetectionKey(ctx context.Context, token string, key fleetagent.AgentSigningKey, proof string) error
	SendDetectionBatch(ctx context.Context, token string, batch fleetagent.AgentBatch, items []fleetagent.DetectionBatchItem) error
}

// DetectionSigningKeyState is the private half of one purpose-bound agent key. Only Key.PublicKey and
// a proof produced from PrivateKey may leave the host.
type DetectionSigningKeyState struct {
	Key        fleetagent.AgentSigningKey
	PrivateKey ed25519.PrivateKey
}

// Validate rejects malformed or mismatched public/private key material.
func (k DetectionSigningKeyState) Validate() error {
	if err := k.Key.Validate(); err != nil {
		return err
	}
	if len(k.PrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: local detection private key has invalid size", shared.ErrValidation)
	}
	canonicalPrivate := ed25519.NewKeyFromSeed(k.PrivateKey.Seed())
	if !bytes.Equal(canonicalPrivate, k.PrivateKey) {
		return fmt.Errorf("%w: local detection private key seed/public material is inconsistent", shared.ErrValidation)
	}
	derived, ok := k.PrivateKey.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(derived, k.Key.PublicKey) {
		return fmt.Errorf("%w: local detection private key does not match its public key", shared.ErrValidation)
	}
	if k.Key.Purpose != fleetagent.PurposeDetectionBatch {
		return fmt.Errorf("%w: local key has purpose %q, want detection-batch", shared.ErrValidation, k.Key.Purpose)
	}
	return nil
}

// DetectionPendingBatch is persisted before the network call. EngagementID binds already-confirmed
// membership to its original attribution so a configuration change cannot re-sign it elsewhere.
type DetectionPendingBatch struct {
	EngagementID shared.ID
	Sequence     uint64
	Epoch        uint64
	Through      uint64
	EventIDs     []shared.ID
}

// Validate rejects incomplete pending coordinates or attribution.
func (p DetectionPendingBatch) Validate() error {
	if p.EngagementID.IsZero() || p.Sequence == 0 || p.Epoch == 0 || p.Through == 0 || len(p.EventIDs) == 0 {
		return fmt.Errorf("%w: pending detection batch has incomplete attribution or coordinates", shared.ErrValidation)
	}
	for _, id := range p.EventIDs {
		if id.IsZero() {
			return fmt.Errorf("%w: pending detection batch has an empty event id", shared.ErrValidation)
		}
	}
	return nil
}

// DetectionDeliveryState is the complete secret-bearing agent-side detection transport state.
type DetectionDeliveryState struct {
	Version         int
	NextSequence    uint64
	Key             *DetectionSigningKeyState
	RegisteredKeyID string
	Pending         *DetectionPendingBatch
}

// Validate rejects corrupt or tampered local state instead of silently minting a new identity and
// abandoning an in-flight sequence.
func (s DetectionDeliveryState) Validate() error {
	if s.Version != DetectionDeliveryStateVersion || s.NextSequence == 0 {
		return fmt.Errorf("%w: unsupported or incomplete detection delivery state", shared.ErrValidation)
	}
	if s.Key == nil && s.RegisteredKeyID != "" {
		return fmt.Errorf("%w: registered key id exists without local key material", shared.ErrValidation)
	}
	if s.Key != nil {
		if err := s.Key.Validate(); err != nil {
			return err
		}
		if s.RegisteredKeyID != "" && s.RegisteredKeyID != s.Key.Key.KeyID {
			return fmt.Errorf("%w: registered key id does not match local key", shared.ErrValidation)
		}
	}
	if s.Pending != nil {
		if err := s.Pending.Validate(); err != nil {
			return err
		}
		if s.Pending.Sequence != s.NextSequence {
			return fmt.Errorf("%w: pending sequence %d disagrees with next sequence %d", shared.ErrValidation, s.Pending.Sequence, s.NextSequence)
		}
	}
	return nil
}

// DetectionStateStore durably persists private signing material and the in-flight batch coordinate.
type DetectionStateStore interface {
	Load() (DetectionDeliveryState, bool, error)
	Save(DetectionDeliveryState) error
}
