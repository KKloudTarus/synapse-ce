package sourceupload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestStoreSaveGetMaterializeAndVerify(t *testing.T) {
	ctx := context.Background()
	objects := blob.NewMemory()
	store := NewStore(objects, 0)
	data := []byte("source archive bytes")
	item, err := store.Save(ctx, "tenant-a", "eng-a", "../source.tar.gz", "alice", time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC), int64(len(data)), digest(data), bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if item.Filename != "source.tar.gz" || item.Target() == "" || item.Locator == "" {
		t.Fatalf("saved item = %+v", item)
	}
	got, err := store.Get(ctx, "tenant-a", "eng-a")
	if err != nil || got.SHA256 != item.SHA256 {
		t.Fatalf("Get: item=%+v err=%v", got, err)
	}
	path, materialized, cleanup, err := store.Materialize(ctx, item.Locator)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if materialized.Target() != item.Target() {
		t.Fatalf("materialized target = %q, want %q", materialized.Target(), item.Target())
	}
	read, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(read, data) {
		t.Fatalf("materialized bytes = %q err=%v", read, err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("materialized path still exists: %v", err)
	}
	metadata, err := objects.Get(ctx, metadataKey(item.Locator))
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	foreignLocator := locatorFor("tenant-b", "eng-b")
	if err := objects.PutObject(ctx, metadataKey(foreignLocator), bytes.NewReader(metadata), int64(len(metadata))); err != nil {
		t.Fatalf("copy metadata: %v", err)
	}
	if _, _, _, err := store.Materialize(ctx, foreignLocator); err == nil {
		t.Fatal("Materialize accepted metadata under a different tenant/engagement locator")
	}

	tampered := bytes.Repeat([]byte("x"), len(data))
	archiveKey := item.Locator + "/archive.tar.gz"
	if err := objects.PutObject(ctx, archiveKey, bytes.NewReader(tampered), int64(len(tampered))); err != nil {
		t.Fatalf("tamper object: %v", err)
	}
	if _, _, _, err := store.Materialize(ctx, item.Locator); err == nil {
		t.Fatal("Materialize accepted tampered source bytes")
	}
}

type truncatingObjectStore struct {
	objects map[string][]byte
	deleted bool
}

func (s *truncatingObjectStore) PutObject(_ context.Context, key string, src io.Reader, size int64) error {
	data := make([]byte, size)
	if _, err := io.ReadFull(src, data); err != nil {
		return err
	}
	if s.objects == nil {
		s.objects = map[string][]byte{}
	}
	s.objects[key] = data
	return nil
}

func (s *truncatingObjectStore) OpenObject(_ context.Context, key string) (io.ReadCloser, error) {
	data, ok := s.objects[key]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (s *truncatingObjectStore) DeleteObject(_ context.Context, key string) error {
	delete(s.objects, key)
	s.deleted = true
	return nil
}

func TestStoreRejectsBytesBeyondDeclaredSize(t *testing.T) {
	objects := &truncatingObjectStore{}
	store := NewStore(objects, 0)
	data := []byte("archive-with-trailing-byte")
	declared := int64(len(data) - 1)
	_, err := store.Save(context.Background(), "tenant-a", "eng-a", "source.zip", "alice", time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC), declared, digest(data[:declared]), bytes.NewReader(data))
	if err == nil {
		t.Fatal("Save accepted a source stream longer than its declared size")
	}
	if !objects.deleted {
		t.Fatal("Save did not remove the partially stored archive")
	}
}

type captureAcquirer struct {
	archivePath string
	workspace   string
}

func (a *captureAcquirer) Acquire(_ context.Context, request ports.AcquireRequest) (*ports.Workspace, error) {
	a.archivePath = request.Value
	if _, err := os.Stat(request.Value); err != nil {
		return nil, err
	}
	workspace, err := os.MkdirTemp("", "sourceupload-workspace-*")
	if err != nil {
		return nil, err
	}
	a.workspace = workspace
	return &ports.Workspace{Dir: workspace, Cleanup: func() error { return os.RemoveAll(workspace) }}, nil
}

func TestAcquirerMaterializesAndCleansUploadedSource(t *testing.T) {
	ctx := context.Background()
	store := NewStore(blob.NewMemory(), 0)
	data := []byte("archive")
	item, err := store.Save(ctx, "tenant-a", "eng-a", "source.zip", "alice", time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC), int64(len(data)), digest(data), bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	next := &captureAcquirer{}
	workspace, err := NewAcquirer(next, store).Acquire(ctx, ports.AcquireRequest{Kind: ports.TargetUpload, Value: item.Target(), Locator: item.Locator})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if next.archivePath == "" || workspace.Dir != next.workspace {
		t.Fatalf("archive was not delegated: path=%q workspace=%+v", next.archivePath, workspace)
	}
	if err := workspace.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	for _, path := range []string{next.archivePath, next.workspace} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("cleanup left %q: %v", path, err)
		}
	}
}
