package agentstate

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/fssecurity"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestDetectionStoreRoundTripsSecretStateAt0600(t *testing.T) {
	dir := t.TempDir()
	store := NewDetectionStore(dir)
	key := testLocalKey(t)
	want := ports.DetectionDeliveryState{Version: 1, NextSequence: 3, Key: &key, RegisteredKeyID: key.Key.KeyID,
		Pending: &ports.DetectionPendingBatch{EngagementID: "eng-1", Sequence: 3, Epoch: 2, Through: 7,
			EventIDs: []shared.ID{"det-6", "det-7"}}}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Load()
	if err != nil || !ok {
		t.Fatalf("Load ok=%v err=%v", ok, err)
	}
	if got.RegisteredKeyID != want.RegisteredKeyID || got.NextSequence != 3 || got.Pending == nil || got.Pending.Through != 7 {
		t.Fatalf("round trip = %#v", got)
	}
	if string(got.Key.PrivateKey) != string(want.Key.PrivateKey) {
		t.Fatal("private key did not round-trip")
	}
	want.NextSequence = 4
	want.Pending = nil
	if err := store.Save(want); err != nil {
		t.Fatalf("replace state: %v", err)
	}
	got, ok, err = store.Load()
	if err != nil || !ok || got.NextSequence != 4 || got.Pending != nil {
		t.Fatalf("replacement state = %#v ok=%v err=%v", got, ok, err)
	}
	if fssecurity.UnixModeEnforced() {
		info, err := os.Stat(filepath.Join(dir, detectionStateFile))
		if err != nil {
			t.Fatal(err)
		}
		if gotMode := info.Mode().Perm(); gotMode != 0o600 {
			t.Fatalf("state mode = %v, want 0600", gotMode)
		}
	}
}

func TestDetectionStoreDistinguishesMissingAndCorruptState(t *testing.T) {
	dir := t.TempDir()
	store := NewDetectionStore(dir)
	if _, ok, err := store.Load(); err != nil || ok {
		t.Fatalf("missing state ok=%v err=%v", ok, err)
	}
	if err := os.WriteFile(filepath.Join(dir, detectionStateFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.Load(); err == nil || ok {
		t.Fatalf("corrupt state ok=%v err=%v", ok, err)
	}
}

func TestDetectionStoreRefusesInvalidState(t *testing.T) {
	store := NewDetectionStore(t.TempDir())
	if err := store.Save(ports.DetectionDeliveryState{}); err == nil {
		t.Fatal("invalid zero state persisted")
	}
}

func testLocalKey(t *testing.T) ports.DetectionSigningKeyState {
	t.Helper()
	pub, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	key, err := fleetagent.NewSigningKey("agent-1", fleetagent.PurposeDetectionBatch, pub, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return ports.DetectionSigningKeyState{Key: key, PrivateKey: privateKey}
}
