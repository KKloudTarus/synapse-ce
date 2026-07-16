package file

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestProjectArchiveStore(t *testing.T) {
	s := NewProjectArchiveStore(t.TempDir(), 4)
	path, err := s.Save(context.Background(), "p1", "source.ZIP", bytes.NewBufferString("zip"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "zip" {
		t.Fatalf("stored=%q err=%v", got, err)
	}
	if err := s.Delete(context.Background(), "p1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("archive still exists: %v", err)
	}
}

func TestProjectArchiveStoreRejectsInvalidAndOversized(t *testing.T) {
	s := NewProjectArchiveStore(t.TempDir(), 3)
	if _, err := s.Save(context.Background(), "p1", "source.rar", bytes.NewBuffer(nil)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unsupported=%v", err)
	}
	if _, err := s.Save(context.Background(), "p1", "source.tar.gz", bytes.NewBufferString("four")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversized=%v", err)
	}
}
