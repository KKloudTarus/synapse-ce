package scabench

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func newStore(t *testing.T) *PinArchiveStore {
	t.Helper()
	store, err := NewPinArchiveStore(t.TempDir())
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	return store
}

// TestPinArchiveRoundTripsExactBytes is the core contract: bytes retrieved after the origin stopped
// serving them must be the pinned bytes, not merely something of the right length.
func TestPinArchiveRoundTripsExactBytes(t *testing.T) {
	store := newStore(t)
	payload := []byte(`{"document":{"tracking":{"version":"2"}}}`)
	digest := digestOf(payload)

	if err := store.Put(digest, payload); err != nil {
		t.Fatalf("archive bytes: %v", err)
	}
	got, err := store.Get(digest)
	if err != nil {
		t.Fatalf("retrieve archived bytes: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("archive must return the exact bytes, got %q", got)
	}
}

// TestPinArchivePutRejectsContentThatDisagreesWithItsDigest catches the failure this feature exists
// to prevent: a feed that drifted between pinning and archiving must not populate the archive with
// bytes no pin describes, because that archive would then "verify" a capture against the wrong
// evidence.
func TestPinArchivePutRejectsContentThatDisagreesWithItsDigest(t *testing.T) {
	store := newStore(t)
	pinned := digestOf([]byte("the bytes that were pinned"))
	drifted := []byte("the bytes the vendor serves now")

	err := store.Put(pinned, drifted)
	if err == nil {
		t.Fatal("content that does not hash to the expected digest must be refused")
	}
	if !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("error must report a digest mismatch, got %v", err)
	}
	// Nothing may be retained under either digest, or a later read would find partial evidence.
	if _, err := store.Get(pinned); err == nil {
		t.Fatal("a refused archive must retain nothing under the expected digest")
	}
	if _, err := store.Get(digestOf(drifted)); err == nil {
		t.Fatal("a refused archive must retain nothing under the content digest")
	}
}

// TestPinArchivePutIsIdempotent keeps a repeated archive from truncating a good blob.
func TestPinArchivePutIsIdempotent(t *testing.T) {
	store := newStore(t)
	payload := []byte("pinned vendor document")
	digest := digestOf(payload)

	for i := 0; i < 3; i++ {
		if err := store.Put(digest, payload); err != nil {
			t.Fatalf("archive attempt %d: %v", i, err)
		}
	}
	got, err := store.Get(digest)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("repeated archiving must preserve content, got %q err %v", got, err)
	}
}

func TestPinArchivePutRejectsCorruptExistingBlob(t *testing.T) {
	store := newStore(t)
	payload := []byte("pinned vendor document")
	digest := digestOf(payload)
	if err := store.Put(digest, payload); err != nil {
		t.Fatalf("archive bytes: %v", err)
	}
	path, err := store.blobPath(digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("unseal blob for tampering: %v", err)
	}
	tampered := append([]byte(nil), payload...)
	tampered[0] ^= 1
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("tamper with blob: %v", err)
	}
	if err := store.Put(digest, payload); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("repeated archive must reject a corrupt retained blob, got %v", err)
	}
}

func TestPinArchivePutRejectsNonRegularExistingBlob(t *testing.T) {
	store := newStore(t)
	payload := []byte("pinned vendor document")
	digest := digestOf(payload)
	path, err := store.blobPath(digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("create non-regular blob: %v", err)
	}
	if err := store.Put(digest, payload); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("archive must reject a non-regular retained blob, got %v", err)
	}
}

// TestPinArchiveGetDetectsCorruption is why Get re-hashes. An archive exists to be trusted after the
// origin is gone, so a silently altered blob must fail rather than be scored as the pinned artifact.
func TestPinArchiveGetDetectsCorruption(t *testing.T) {
	root := t.TempDir()
	store, err := NewPinArchiveStore(root)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	payload := []byte("pinned vendor document")
	digest := digestOf(payload)
	if err := store.Put(digest, payload); err != nil {
		t.Fatalf("archive bytes: %v", err)
	}

	blob := filepath.Join(root, "blobs", strings.TrimPrefix(digest, "sha256:"))
	if err := os.Chmod(blob, 0o600); err != nil {
		t.Fatalf("unseal blob for tampering: %v", err)
	}
	if err := os.WriteFile(blob, []byte("tampered vendor documnt"), 0o600); err != nil {
		t.Fatalf("tamper with blob: %v", err)
	}

	if _, err := store.Get(digest); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("a tampered blob must be reported as corrupt, got %v", err)
	}
}

// TestPinArchiveRejectsUnsafeDigests keeps the storage key from becoming a path-traversal primitive.
//
// The digest is interpolated into a filesystem path, and `filepath.Join` resolves `..` rather than
// refusing it: without validation, "sha256:../../etc/passwd" leaves the archive root entirely. This
// asserts on the resolved path, because an error alone would not distinguish a rejected key from a
// key that escaped to somewhere that merely happens not to exist.
func TestPinArchiveRejectsUnsafeDigests(t *testing.T) {
	store := newStore(t)
	for _, digest := range []string{
		"",
		"sha256:../../etc/passwd",
		"sha256:.." + string(filepath.Separator) + strings.Repeat("a", 61),
		"sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("a", 65),
		"sha256:" + strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("g", 64),
		strings.Repeat("a", 64),
		"../blobs/" + strings.Repeat("a", 64),
	} {
		if _, err := store.blobPath(digest); err == nil {
			t.Errorf("digest %q must be refused before it reaches a path", digest)
		}
		if _, err := store.Get(digest); err == nil {
			t.Errorf("digest %q must be rejected on read", digest)
		}
		if err := store.Put(digest, []byte("x")); err == nil {
			t.Errorf("digest %q must be rejected on write", digest)
		}
	}
}

// TestPinArchiveBlobPathStaysUnderTheRoot pins containment for keys that pass validation, so the
// layout cannot later be changed into one that escapes.
func TestPinArchiveBlobPathStaysUnderTheRoot(t *testing.T) {
	root := t.TempDir()
	store, err := NewPinArchiveStore(root)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	path, err := store.blobPath("sha256:" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("a valid digest must resolve: %v", err)
	}
	blobs := filepath.Join(root, "blobs")
	relative, err := filepath.Rel(blobs, path)
	if err != nil || relative != strings.Repeat("a", 64) {
		t.Fatalf("blob path %q must sit directly under %q, got relative %q err %v", path, blobs, relative, err)
	}
}

// TestPinArchiveRejectsEmptyContent keeps a zero-length fetch from being archived as though the
// vendor document had been preserved.
func TestPinArchiveRejectsEmptyContent(t *testing.T) {
	store := newStore(t)
	if err := store.Put(digestOf(nil), nil); err == nil {
		t.Fatal("empty content must not be archived")
	}
}

// TestNewPinArchiveStoreRequiresAbsoluteRoot keeps the archive from landing wherever the process
// happens to be working.
func TestNewPinArchiveStoreRequiresAbsoluteRoot(t *testing.T) {
	if _, err := NewPinArchiveStore("relative/archive"); err == nil {
		t.Fatal("a relative archive root must be rejected")
	}
}

// TestVerifyArchiveReportsTheMissingReference is the pre-capture check. It must say which pin is
// unretained, so an incomplete archive is actionable instead of surfacing later as an unexplained
// pin mismatch.
func TestVerifyArchiveReportsTheMissingReference(t *testing.T) {
	store := newStore(t)
	present := []byte("archived feed")
	absent := []byte("feed that was never archived")

	if err := store.Put(digestOf(present), present); err != nil {
		t.Fatalf("archive bytes: %v", err)
	}
	archive := bench.PinArchive{
		SchemaVersion:   bench.PinArchiveSchemaVersion,
		CatalogRevision: "same-sbom-linux-20260922",
		Entries: []bench.ArchivedPin{
			{Reference: "database:owned:present", Digest: digestOf(present), Bytes: int64(len(present)), CapturedAt: "2026-09-21T00:00:00Z"},
			{Reference: "database:owned:absent", Digest: digestOf(absent), Bytes: int64(len(absent)), CapturedAt: "2026-09-21T00:00:00Z"},
		},
	}

	err := VerifyArchive(store, archive)
	if err == nil {
		t.Fatal("an archive missing a claimed entry must fail verification")
	}
	if !strings.Contains(err.Error(), "database:owned:absent") {
		t.Fatalf("error must name the unretained reference, got %v", err)
	}

	// With every claimed entry retained, verification passes.
	archive.Entries = archive.Entries[:1]
	if err := VerifyArchive(store, archive); err != nil {
		t.Fatalf("a fully retained archive must verify: %v", err)
	}
}

// TestVerifyArchiveRejectsLengthDisagreement covers the manifest drifting from the stored bytes.
func TestVerifyArchiveRejectsLengthDisagreement(t *testing.T) {
	store := newStore(t)
	payload := []byte("archived feed")
	if err := store.Put(digestOf(payload), payload); err != nil {
		t.Fatalf("archive bytes: %v", err)
	}
	archive := bench.PinArchive{
		SchemaVersion:   bench.PinArchiveSchemaVersion,
		CatalogRevision: "rev-1",
		Entries: []bench.ArchivedPin{{
			Reference:  "database:owned:present",
			Digest:     digestOf(payload),
			Bytes:      int64(len(payload)) + 1,
			CapturedAt: "2026-09-21T00:00:00Z",
		}},
	}
	err := VerifyArchive(store, archive)
	if err == nil || !strings.Contains(err.Error(), "does not match manifest length") {
		t.Fatalf("a length disagreement must be rejected, got %v", err)
	}
}

// TestVerifyArchiveRequiresAStore keeps a nil store from reading as a clean verification.
func TestVerifyArchiveRequiresAStore(t *testing.T) {
	if err := VerifyArchive(nil, bench.PinArchive{}); err == nil {
		t.Fatal("a nil store must not verify")
	}
}
