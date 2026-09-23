package scabench

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

// maxArchivedPinBytes bounds a single archived artifact.
//
// The largest feed this corpus pins is a comparator vulnerability database in the tens of megabytes,
// so 512 MiB leaves substantial headroom while keeping a corrupt or hostile length from driving an
// unbounded read into memory.
const (
	maxArchivedPinBytes = 512 << 20
	// maxMaterializedInputObjectBytes is deliberately separate from the raw-origin PinArchive v1
	// bound. Materialized database trees can contain a larger individual object, but neither path
	// accepts unbounded archive input.
	maxMaterializedInputObjectBytes int64 = bench.MaxTrustedInputArchiveFileBytes
)

// PinArchiveStore holds the exact bytes of pinned benchmark inputs, addressed by their content
// digest.
//
// Layout mirrors the project source-artifact store: one flat directory of digest-named files. A pin
// digest is already a uniformly distributed sha256 and the archive holds tens of entries rather than
// millions, so prefix sharding would add path arithmetic without relieving any real directory
// pressure.
type PinArchiveStore struct{ root string }

// NewPinArchiveStore opens an archive root, creating it when absent.
func NewPinArchiveStore(root string) (*PinArchiveStore, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("pin archive root must be an absolute path")
	}
	blobs := filepath.Join(root, "blobs")
	if err := os.MkdirAll(blobs, 0o700); err != nil {
		return nil, fmt.Errorf("create pin archive root: %w", err)
	}
	info, err := os.Lstat(blobs)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("pin archive root must be a real directory")
	}
	return &PinArchiveStore{root: root}, nil
}

func (s *PinArchiveStore) blobPath(digest string) (string, error) {
	// The digest is the storage key, so an unvalidated one is a path-traversal primitive rather than
	// merely a lookup miss.
	if !validArchiveDigest(digest) {
		return "", fmt.Errorf("archive digest %q is not an immutable sha256", digest)
	}
	return filepath.Join(s.root, "blobs", strings.TrimPrefix(digest, "sha256:")), nil
}

// Put archives bytes under their own digest and reports the digest it stored.
//
// The caller's expected digest is checked against the content before anything is written, so a feed
// that drifted between pinning and archiving fails here instead of silently populating the archive
// with bytes that no pin describes.
func (s *PinArchiveStore) Put(expected string, data []byte) error {
	if len(data) == 0 {
		return errors.New("refusing to archive empty content")
	}
	if len(data) > maxArchivedPinBytes {
		return fmt.Errorf("archived content exceeds %d bytes", maxArchivedPinBytes)
	}
	sum := sha256.Sum256(data)
	actual := "sha256:" + hex.EncodeToString(sum[:])
	if actual != expected {
		return fmt.Errorf("archive digest mismatch: expected %s, content hashes to %s", expected, actual)
	}
	path, err := s.blobPath(actual)
	if err != nil {
		return err
	}
	// Identical content is already the same file, so a repeat archive is a no-op rather than a
	// rewrite. Skipping it keeps Put idempotent and avoids truncating a good blob if the source read
	// later fails.
	if _, err := os.Lstat(path); err == nil {
		return nil
	}
	temporary, err := os.CreateTemp(filepath.Join(s.root, "blobs"), ".partial-*")
	if err != nil {
		return fmt.Errorf("create archive blob: %w", err)
	}
	name := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(name)
	}()
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write archive blob: %w", err)
	}
	// An archive that survives a crash half-written would verify as corrupt on the next recapture and
	// be indistinguishable from vendor drift, so the bytes are durable before the name appears.
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync archive blob: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close archive blob: %w", err)
	}
	if err := os.Chmod(name, 0o400); err != nil {
		return fmt.Errorf("seal archive blob: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("publish archive blob: %w", err)
	}
	return nil
}

// StoreFile streams one non-symlink regular file into the archive's content-addressed blob store.
// Unlike Put, it accepts empty files and the materialized-input size bound without changing raw
// PinArchive v1's byte-oriented semantics.
func (s *PinArchiveStore) StoreFile(source string) (string, int64, error) {
	if s == nil {
		return "", 0, errors.New("pin archive store is required")
	}
	before, err := os.Lstat(source)
	if err != nil {
		return "", 0, fmt.Errorf("inspect materialized input file: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return "", 0, errors.New("materialized input path must be a regular non-symlink file")
	}
	if before.Size() < 0 || before.Size() > maxMaterializedInputObjectBytes {
		return "", 0, fmt.Errorf("materialized input file exceeds %d bytes", maxMaterializedInputObjectBytes)
	}
	input, err := os.Open(source) // #nosec G304 -- collector has validated the materialized input root
	if err != nil {
		return "", 0, fmt.Errorf("open materialized input file: %w", err)
	}
	opened, err := input.Stat()
	if err != nil {
		_ = input.Close()
		return "", 0, fmt.Errorf("inspect opened materialized input file: %w", err)
	}
	if !sameStableFile(before, opened) {
		_ = input.Close()
		return "", 0, errors.New("materialized input file changed while opening")
	}
	temporary, err := os.CreateTemp(filepath.Join(s.root, "blobs"), ".materialized-partial-*")
	if err != nil {
		_ = input.Close()
		return "", 0, fmt.Errorf("create materialized archive blob: %w", err)
	}
	name := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(name)
	}()
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(input, maxMaterializedInputObjectBytes+1))
	inputCloseErr := input.Close()
	if copyErr != nil || inputCloseErr != nil {
		return "", 0, errors.New("stream materialized input file")
	}
	if written != before.Size() || written > maxMaterializedInputObjectBytes {
		return "", 0, errors.New("materialized input file changed while reading")
	}
	after, err := os.Lstat(source)
	if err != nil || !sameStableFile(before, after) {
		return "", 0, errors.New("materialized input file changed while storing")
	}
	if err := temporary.Sync(); err != nil {
		return "", 0, fmt.Errorf("sync materialized archive blob: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", 0, fmt.Errorf("close materialized archive blob: %w", err)
	}
	digest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	path, err := s.blobPath(digest)
	if err != nil {
		return "", 0, err
	}
	if _, err := os.Lstat(path); err == nil {
		if _, err := s.CopyTo(digest, written, io.Discard); err != nil {
			return "", 0, err
		}
		return digest, written, nil
	}
	if err := os.Chmod(name, 0o400); err != nil {
		return "", 0, fmt.Errorf("seal materialized archive blob: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return "", 0, fmt.Errorf("publish materialized archive blob: %w", err)
	}
	if err := syncDirectory(filepath.Join(s.root, "blobs")); err != nil {
		return "", 0, fmt.Errorf("sync materialized archive directory: %w", err)
	}
	return digest, written, nil
}

// CopyTo rehashes a materialized archive object while streaming it to destination. The destination
// sees bytes only after the caller has selected an unpublished temporary file, so corruption cannot
// reach a restored input path.
func (s *PinArchiveStore) CopyTo(digest string, expectedBytes int64, destination io.Writer) (int64, error) {
	if s == nil {
		return 0, errors.New("pin archive store is required")
	}
	if destination == nil {
		return 0, errors.New("materialized archive destination is required")
	}
	if expectedBytes < 0 || expectedBytes > maxMaterializedInputObjectBytes {
		return 0, fmt.Errorf("materialized archive length must be between zero and %d", maxMaterializedInputObjectBytes)
	}
	path, err := s.blobPath(digest)
	if err != nil {
		return 0, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return 0, fmt.Errorf("materialized archive object %s is not retained: %w", digest, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return 0, fmt.Errorf("materialized archive object %s is not a regular file", digest)
	}
	if before.Size() != expectedBytes || before.Size() > maxMaterializedInputObjectBytes {
		return 0, fmt.Errorf("materialized archive object %s length %d does not match expected length %d", digest, before.Size(), expectedBytes)
	}
	input, err := os.Open(path) // #nosec G304 -- path is the validated digest under the archive root
	if err != nil {
		return 0, fmt.Errorf("open materialized archive object %s: %w", digest, err)
	}
	opened, err := input.Stat()
	if err != nil {
		_ = input.Close()
		return 0, fmt.Errorf("inspect opened materialized archive object %s: %w", digest, err)
	}
	if !sameStableFile(before, opened) {
		_ = input.Close()
		return 0, fmt.Errorf("materialized archive object %s changed while opening", digest)
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(destination, hash), io.LimitReader(input, maxMaterializedInputObjectBytes+1))
	closeErr := input.Close()
	if copyErr != nil || closeErr != nil {
		return 0, fmt.Errorf("stream materialized archive object %s", digest)
	}
	after, err := os.Lstat(path)
	if err != nil || !sameStableFile(before, after) || written != expectedBytes {
		return 0, fmt.Errorf("materialized archive object %s changed while reading", digest)
	}
	actual := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if actual != digest {
		return 0, fmt.Errorf("materialized archive object %s is corrupt: content hashes to %s", digest, actual)
	}
	return written, nil
}

// Get returns archived bytes and re-verifies them against the requested digest.
//
// Re-hashing on every read is deliberate. The whole purpose of the archive is to be trustworthy
// evidence after the origin stopped serving the pinned bytes, so a silently corrupted blob must fail
// rather than be scored as though it were the pinned artifact.
func (s *PinArchiveStore) Get(digest string) ([]byte, error) {
	path, err := s.blobPath(digest)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("archived pin %s is not retained: %w", digest, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("archived pin %s is not a regular file", digest)
	}
	if info.Size() > maxArchivedPinBytes {
		return nil, fmt.Errorf("archived pin %s exceeds %d bytes", digest, maxArchivedPinBytes)
	}
	file, err := os.Open(path) // #nosec G304 -- path is the validated digest under the archive root
	if err != nil {
		return nil, fmt.Errorf("open archived pin %s: %w", digest, err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxArchivedPinBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read archived pin %s: %w", digest, err)
	}
	sum := sha256.Sum256(data)
	if actual := "sha256:" + hex.EncodeToString(sum[:]); actual != digest {
		return nil, fmt.Errorf("archived pin %s is corrupt: content hashes to %s", digest, actual)
	}
	return data, nil
}

// VerifyArchive confirms every entry a manifest claims is present and intact.
//
// This is the check a recapture depends on: it answers "can this corpus still be reproduced" before
// a capture spends time scanning, so an incomplete archive is reported as missing evidence rather
// than surfacing later as an unexplained pin mismatch.
func VerifyArchive(store *PinArchiveStore, archive bench.PinArchive) error {
	if store == nil {
		return errors.New("pin archive store is required")
	}
	if err := archive.Validate(); err != nil {
		return err
	}
	for _, entry := range archive.Entries {
		data, err := store.Get(entry.Digest)
		if err != nil {
			return fmt.Errorf("verify archived pin %q: %w", entry.Reference, err)
		}
		if int64(len(data)) != entry.Bytes {
			return fmt.Errorf("archived pin %q length %d does not match manifest length %d", entry.Reference, len(data), entry.Bytes)
		}
	}
	return nil
}

func validArchiveDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}
