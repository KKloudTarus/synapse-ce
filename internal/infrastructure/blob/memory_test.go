package blob

import (
	"context"
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
