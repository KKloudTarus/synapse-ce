//go:build linux

package scabench

import (
	"context"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestTrustedInputArchiveCollectorRejectsSpecialFiles(t *testing.T) {
	root, catalog, spec, store := trustedInputArchiveFixture(t)
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CollectTrustedInputArchive(context.Background(), catalog, spec, root, store); err == nil || !strings.Contains(err.Error(), "special") {
		t.Fatalf("CollectTrustedInputArchive() error = %v, want special-file failure", err)
	}
}
