package sourceartifact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestCaptureRejectsArtifactRootInsideScannedTreeBeforeWriting(t *testing.T) {
	source := t.TempDir()
	root := filepath.Join(source, ".synapse-artifacts")
	store := New(root, 0, 0, 0)
	_, err := store.Capture(context.Background(), "tenant", "project", "analysis", source)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("capture error=%v, want validation", err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact root was created inside scanned tree: %v", err)
	}
}

func TestCaptureRejectsArtifactRootWhoseParentSymlinkResolvesInsideTree(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "artifact-parent")
	if err := os.Symlink(source, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	root := filepath.Join(alias, "retained")
	store := New(root, 0, 0, 0)
	_, err := store.Capture(context.Background(), "tenant", "project", "analysis", source)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("capture error=%v, want validation", err)
	}
	if _, err := os.Lstat(filepath.Join(source, "retained")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resolved artifact root was created inside scanned tree: %v", err)
	}
}
