package ports

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestDetectionDeliveryStateRequiresPendingEngagementAttribution(t *testing.T) {
	key := testDetectionSigningKeyState(t)
	state := DetectionDeliveryState{Version: DetectionDeliveryStateVersion, NextSequence: 1, Key: &key,
		RegisteredKeyID: key.Key.KeyID, Pending: &DetectionPendingBatch{
			Sequence: 1, Epoch: 2, Through: 3, EventIDs: []shared.ID{"det-3"},
		}}
	if err := state.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing pending engagement error = %v", err)
	}
	state.Pending.EngagementID = "eng-1"
	if err := state.Validate(); err != nil {
		t.Fatalf("valid attributed state: %v", err)
	}
}

func testDetectionSigningKeyState(t *testing.T) DetectionSigningKeyState {
	t.Helper()
	pub, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	key, err := fleetagent.NewSigningKey("agent-1", fleetagent.PurposeDetectionBatch, pub,
		now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return DetectionSigningKeyState{Key: key, PrivateKey: privateKey}
}
