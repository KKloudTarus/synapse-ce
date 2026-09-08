package blob

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestFilesystemDurableImmutableObjects(t *testing.T) {
	directory := t.TempDir()
	store, err := NewFilesystem(directory)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key := "tenant/version/archive.zip"
	data := []byte("uploaded bytes")
	if err := store.PutObject(ctx, key, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	if err := store.PutObject(ctx, key, bytes.NewReader([]byte("changed")), 7); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("immutable overwrite = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFilesystem(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	reader, err := reopened.OpenObject(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("reopened bytes = %q, %v", got, err)
	}
	info, err := os.Stat(filepath.Join(directory, key))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("object permission = %v, %v", info, err)
	}
	if err := reopened.DeleteObject(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.OpenObject(ctx, key); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("deleted object = %v", err)
	}
}

func TestFilesystemRejectsUnsafePathsAndPartialWrites(t *testing.T) {
	directory := t.TempDir()
	store, err := NewFilesystem(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	for _, key := range []string{"", "/outside", "../outside", "a/../../outside", "a\\outside", "a/./b", ".upload-secret", "a\nline"} {
		if err := store.PutObject(ctx, key, bytes.NewReader([]byte("x")), 1); err == nil {
			t.Errorf("accepted key %q", key)
		}
	}
	for _, size := range []int64{1, 3} {
		if err := store.PutObject(ctx, "partial", bytes.NewReader([]byte("xx")), size); err == nil {
			t.Fatalf("accepted invalid size %d", size)
		}
		if _, err := store.OpenObject(ctx, "partial"); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("partial object was published: %v", err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.PutObject(canceled, "canceled", bytes.NewReader([]byte("x")), 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled upload = %v", err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(directory, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := store.PutObject(ctx, "escape/object", bytes.NewReader([]byte("x")), 1); err == nil {
		t.Fatal("accepted symlink escape")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("outside directory changed: %v %v", entries, err)
	}
	entries, err = os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "escape" {
			t.Errorf("failed write left %q", entry.Name())
		}
	}
}
