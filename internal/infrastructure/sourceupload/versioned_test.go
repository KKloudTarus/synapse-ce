package sourceupload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

func TestVersionedSourceDurableReuseAndImmutableBindings(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	directory := t.TempDir()
	objects, err := blob.NewFilesystem(directory)
	if err != nil {
		t.Fatal(err)
	}
	repo := memory.NewEngagementSourceRepository()
	store := NewStoreWithRepository(objects, repo, 0)
	data := []byte("source archive bytes")
	now := time.Date(2026, 9, 8, 10, 0, 0, 123456789, time.UTC)
	initial, err := store.Save(ctx, "tenant-a", "initial", "source.zip", "alice", now, int64(len(data)), digest(data), bytes.NewReader(data))
	if err != nil || initial.VersionID.IsZero() || initial.CreatedAt.Nanosecond() != 123456000 {
		t.Fatalf("save immutable package: %+v %v", initial, err)
	}
	if err := objects.Close(); err != nil {
		t.Fatal(err)
	}
	objects, err = blob.NewFilesystem(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = objects.Close() })
	// A fresh API/worker adapter can recover metadata and bytes independently.
	store = NewStoreWithRepository(objects, repo, 0)
	got, err := store.GetByVersion(ctx, "tenant-a", "initial", initial.VersionID)
	if err != nil || got != initial {
		t.Fatalf("reopened metadata: %+v %v", got, err)
	}
	child, err := store.Reuse(ctx, "tenant-a", "initial", "retest-1", initial.VersionID, "bob", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	grandchild, err := store.Reuse(ctx, "tenant-a", "retest-1", "retest-2", child.VersionID, "carol", now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []sourcepackage.Package{child, grandchild} {
		if item.VersionID == initial.VersionID || item.ObjectKey != initial.ObjectKey || item.SHA256 != initial.SHA256 || item.CreatedBy != "alice" || !item.CreatedAt.Equal(initial.CreatedAt) || item.AssociatedBy == "alice" {
			t.Fatalf("reuse did not retain original attribution and immutable bytes: %+v", item)
		}
		path, materialized, cleanup, err := store.Materialize(ctx, item.Locator)
		if err != nil {
			t.Fatal(err)
		}
		read, err := os.ReadFile(path)
		_ = cleanup()
		if err != nil || !bytes.Equal(read, data) || materialized.VersionID != item.VersionID {
			t.Fatalf("child materialized wrong source: %q %+v %v", read, materialized, err)
		}
	}
	if grandchild.ReusedFromVersionID != child.VersionID || child.ReusedFromVersionID != initial.VersionID {
		t.Fatal("reuse chain lost immediate predecessor")
	}
	if _, err := store.Reuse(ctx, "tenant-a", "initial", "stale", child.VersionID, "bob", now); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("stale version = %v", err)
	}
	if _, _, _, err := store.Materialize(shared.WithTenant(ctx, "tenant-b"), child.Locator); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant materialization = %v", err)
	}
	if _, _, _, err := store.Materialize(context.Background(), child.Locator); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unscoped materialization = %v", err)
	}
	changed := []byte("new bytes")
	if _, err := store.Save(ctx, "tenant-a", "initial", "source.zip", "bob", now, int64(len(changed)), digest(changed), bytes.NewReader(changed)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("existing assessment source overwrite = %v", err)
	}
	if err := store.Delete(ctx, "tenant-a", "initial"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("referenced parent deletion = %v", err)
	}
	if err := store.DiscardUnpublished(ctx, child); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, "tenant-a", "retest-2"); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, "tenant-a", "retest-1"); err != nil {
		t.Fatal(err)
	}
	reader, err := objects.OpenObject(ctx, initial.ObjectKey)
	if err != nil {
		t.Fatalf("child cleanup deleted parent archive: %v", err)
	}
	_ = reader.Close()
}

func TestVersionedSourceLegacyPromotionRequiresVerifiedBytes(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	objects := blob.NewMemory()
	legacy := NewStoreWithRepository(objects, nil, 0)
	data := []byte("legacy archive")
	old, err := legacy.Save(ctx, "tenant-a", "legacy", "source.tar", "original", time.Now(), int64(len(data)), digest(data), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	store := NewStoreWithRepository(objects, memory.NewEngagementSourceRepository(), 0)
	promoted, err := store.Get(ctx, "tenant-a", "legacy")
	if err != nil || promoted.VersionID.IsZero() || promoted.CreatedBy != "original" || promoted.ObjectKey != old.Locator+"/archive.tar" {
		t.Fatalf("verified promotion: %+v %v", promoted, err)
	}
	if err := store.DiscardUnpublished(ctx, promoted); err != nil {
		t.Fatal(err)
	}
	if err := objects.DeleteObject(ctx, promoted.ObjectKey); err != nil {
		t.Fatal(err)
	}
	// A legacy manifest/digest alone must never be presented as reusable bytes.
	unrestored := NewStoreWithRepository(objects, memory.NewEngagementSourceRepository(), 0)
	if _, err := unrestored.Get(ctx, "tenant-a", "legacy"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("promoted missing bytes = %v", err)
	}
	if _, err := store.Reuse(ctx, "tenant-a", "legacy", "child", promoted.VersionID, "bob", time.Now()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("reused unavailable bytes = %v", err)
	}
	if err := objects.Put(ctx, promoted.ObjectKey, []byte("tampered bytes")); err != nil {
		t.Fatal(err)
	}
	if _, err := unrestored.Get(ctx, "tenant-a", "legacy"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("promoted corrupt bytes = %v", err)
	}
}

func TestVersionedSourceRollbackCompensationRetainsPublishedAndSharedBytes(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	objects := blob.NewMemory()
	repo := memory.NewEngagementSourceRepository()
	store := NewStoreWithRepository(objects, repo, 0)
	data := []byte("archive")
	var unpublished sourcepackage.Package
	failure := errors.New("audit completion failed")
	err := memory.NewTenantTransactionRunner().Run(ctx, "tenant-a", func(txCtx context.Context) error {
		var err error
		unpublished, err = store.Save(txCtx, "tenant-a", "child", "source.zip", "alice", time.Now(), int64(len(data)), digest(data), bytes.NewReader(data))
		if err != nil {
			return err
		}
		if err := store.DiscardUnpublished(txCtx, unpublished); err != nil {
			t.Fatalf("discard inside uncommitted transaction = %v", err)
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "tenant-a", "child"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("rolled back source metadata = %v", err)
	}
	if err := store.DiscardUnpublished(ctx, unpublished); err != nil {
		t.Fatal(err)
	}
	if _, err := objects.OpenObject(ctx, unpublished.ObjectKey); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("rollback orphan remained: %v", err)
	}
	published, err := store.Save(ctx, "tenant-a", "published", "source.zip", "alice", time.Now(), int64(len(data)), digest(data), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	err = memory.NewTenantTransactionRunner().Run(ctx, "tenant-a", func(txCtx context.Context) error {
		if err := store.Delete(txCtx, "tenant-a", "published"); err != nil {
			return err
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if err := store.DiscardUnpublished(ctx, published); err != nil {
		t.Fatal(err)
	}
	reader, err := objects.OpenObject(ctx, published.ObjectKey)
	if err != nil {
		t.Fatal("rollback or compensation deleted published bytes", err)
	}
	_ = reader.Close()
}

type unavailableSourceRepository struct {
	*memory.EngagementSourceRepository
}

func (r unavailableSourceRepository) ObjectUnreferenced(context.Context, shared.ID, string) (bool, error) {
	return false, io.ErrUnexpectedEOF
}

func TestVersionedSourceAmbiguousCleanupRetainsBytes(t *testing.T) {
	ctx := context.Background()
	objects := blob.NewMemory()
	repo := unavailableSourceRepository{memory.NewEngagementSourceRepository()}
	store := NewStoreWithRepository(objects, repo, 0)
	data := []byte("archive")
	item, err := store.Save(ctx, "tenant-a", "eng-a", "source.zip", "alice", time.Now(), int64(len(data)), digest(data), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DiscardUnpublished(ctx, item); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("uncertain query = %v", err)
	}
	reader, err := objects.OpenObject(ctx, item.ObjectKey)
	if err != nil {
		t.Fatal("ambiguous query removed bytes", err)
	}
	_ = reader.Close()
}

func TestVersionedSourceConcurrentUploadPublishesOneImmutableObject(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	directory := t.TempDir()
	objects, err := blob.NewFilesystem(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = objects.Close() })
	store := NewStoreWithRepository(objects, memory.NewEngagementSourceRepository(), 0)
	data := []byte("same archive uploaded concurrently")
	now := time.Now()
	const count = 16
	results := make([]sourcepackage.Package, count)
	errorsByIndex := make([]error, count)
	var workers sync.WaitGroup
	start := make(chan struct{})
	for index := range count {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			results[index], errorsByIndex[index] = store.Save(ctx, "tenant-a", "eng-a", "source.zip", "alice", now, int64(len(data)), digest(data), bytes.NewReader(data))
		}()
	}
	close(start)
	workers.Wait()
	for index, item := range results {
		if errorsByIndex[index] != nil || item.VersionID != results[0].VersionID || item.VersionID.IsZero() {
			t.Fatalf("concurrent upload %d = %+v %v", index, item, errorsByIndex[index])
		}
	}
	files := 0
	if err := filepath.WalkDir(directory, func(_ string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			files++
		}
		return err
	}); err != nil || files != 1 {
		t.Fatalf("concurrent uploads left %d files, %v", files, err)
	}
}

func TestVersionedSourceRejectsForgedObjectOwnership(t *testing.T) {
	ctx := context.Background()
	store := NewStore(blob.NewMemory(), 0)
	data := []byte("archive")
	item, err := store.Save(ctx, "tenant-a", "eng-a", "source.zip", "alice", time.Now(), int64(len(data)), digest(data), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	foreignTenant := sha256.Sum256([]byte("tenant-b"))
	ownerHash := sha256.Sum256([]byte(item.TenantID.String()))
	for _, key := range []string{
		// The real owner's hash in the engagement position must not satisfy tenancy.
		"engagement-sources/v2/" + hex.EncodeToString(foreignTenant[:]) + "/" + hex.EncodeToString(ownerHash[:]) + "/" + item.VersionID.String() + "/archive.zip",
		strings.Replace(item.ObjectKey, "/v2/", "/v1/", 1),
		strings.TrimSuffix(item.ObjectKey, ".zip") + ".tar",
		versionLocator(item.TenantID, "another-engagement", item.VersionID) + "/archive.zip",
	} {
		forged := item
		forged.ObjectKey = key
		if err := validateStoredVersion(forged); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("forged object key accepted: %q %v", key, err)
		}
	}
}
