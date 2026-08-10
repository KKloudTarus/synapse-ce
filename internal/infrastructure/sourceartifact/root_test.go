package sourceartifact

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestAllSourceArtifactWritersRejectRelativeRoot(t *testing.T) {
	store := New("relative/project-source-artifacts", 0, 0, 0)
	if _, err := store.Capture(context.Background(), "tenant", "project", "analysis", t.TempDir()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("Capture relative-root error=%v, want validation", err)
	}
	if _, err := store.CaptureBase(context.Background(), "tenant", "project", "analysis", map[string][]byte{"main.go": []byte("package main\n")}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("CaptureBase relative-root error=%v, want validation", err)
	}
}
