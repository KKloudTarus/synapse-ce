//go:build linux

package scabench

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPinArchiveCopyToRejectsSymlinkBlob(t *testing.T) {
	store := newStore(t)
	payload := []byte("retained materialized input")
	digest := digestOf(payload)
	if err := store.Put(digest, payload); err != nil {
		t.Fatalf("archive payload: %v", err)
	}
	path, err := store.blobPath(digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove blob: %v", err)
	}
	target := filepath.Join(t.TempDir(), "replacement")
	if err := os.WriteFile(target, payload, 0o600); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("substitute symlink: %v", err)
	}
	if _, err := store.CopyTo(digest, int64(len(payload)), &bytes.Buffer{}); err == nil {
		t.Fatal("CopyTo must reject a substituted symlink")
	}
}

func TestPinArchiveCopyToRejectsFIFOBlob(t *testing.T) {
	store := newStore(t)
	digest := "sha256:" + strings.Repeat("a", 64)
	path, err := store.blobPath(digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("create FIFO: %v", err)
	}
	if _, err := store.CopyTo(digest, 0, &bytes.Buffer{}); err == nil {
		t.Fatal("CopyTo must reject a FIFO rather than stream it")
	}
}

func TestReadPinnedBundleFileRejectsSymlinkAndFIFO(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "metadata")
	if err := os.WriteFile(target, []byte("metadata"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(root, "catalog.json")); err != nil {
		t.Fatalf("create metadata symlink: %v", err)
	}
	if _, err := readPinnedBundleFile(root, "catalog.json", 1024); err == nil {
		t.Fatal("bundle metadata symlink must be rejected")
	}
	if err := unix.Mkfifo(filepath.Join(root, "input-archive.json"), 0o600); err != nil {
		t.Fatalf("create metadata FIFO: %v", err)
	}
	if _, err := readPinnedBundleFile(root, "input-archive.json", 1024); err == nil {
		t.Fatal("bundle metadata FIFO must be rejected")
	}
}
