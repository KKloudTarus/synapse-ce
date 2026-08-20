package blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestMemoryRoundTrip(t *testing.T) {
	var s ports.BlobStore = NewMemory()
	ctx := context.Background()

	if _, err := s.Get(ctx, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("missing key: want ErrNotFound, got %v", err)
	}

	data := []byte("artifact bytes")
	if err := s.Put(ctx, "k1", data); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.Get(ctx, "k1")
	if err != nil || string(got) != string(data) {
		t.Fatalf("get: got=%q err=%v", got, err)
	}

	// Get returns a copy – mutating it must not corrupt the store.
	got[0] = 'X'
	again, _ := s.Get(ctx, "k1")
	if string(again) != string(data) {
		t.Errorf("store mutated via returned slice: %q", again)
	}
}

func TestMemoryStatAndVerifyHashStoredBytes(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()
	good := []byte("original artifact")
	sum := sha256.Sum256(good)
	key := hex.EncodeToString(sum[:])
	if err := store.Put(ctx, key, good); err != nil {
		t.Fatalf("put: %v", err)
	}

	// Simulate storage corruption beneath an otherwise valid content-address key.
	store.mu.Lock()
	store.m[key] = []byte("corrupted artifact")
	store.mu.Unlock()

	metadata, err := store.Stat(ctx, key)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if metadata.SHA256 == key {
		t.Fatal("stat must derive checksum from corrupted stored bytes, not trust key")
	}
	if err := store.Verify(ctx, key, key); err == nil {
		t.Fatal("verification must reject bytes corrupted under a valid content-address key")
	}
}
