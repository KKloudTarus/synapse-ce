package scabench

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
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
	archiveCopyBufferBytes                = 64 << 10
)

// PinArchiveStore holds the exact bytes of pinned benchmark inputs, addressed by their content
// digest.
//
// Layout mirrors the project source-artifact store: one flat directory of digest-named files. A pin
// digest is already a uniformly distributed sha256 and the archive holds tens of entries rather than
// millions, so prefix sharding would add path arithmetic without relieving any real directory
// pressure.
type PinArchiveStore struct {
	root     string
	readOnly bool
}

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

// OpenPinArchiveStoreReadOnly opens an existing archive without creating or changing any path.
//
// Bundle restore must not turn a missing or malformed candidate CAS into a new empty archive: that
// would hide missing evidence and also changes the bundle being inspected.
func OpenPinArchiveStoreReadOnly(root string) (*PinArchiveStore, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("pin archive root must be an absolute path")
	}
	if err := requireRealDirectory(root); err != nil {
		return nil, fmt.Errorf("open pin archive root: %w", err)
	}
	if err := requireRealDirectory(filepath.Join(root, "blobs")); err != nil {
		return nil, fmt.Errorf("open pin archive blobs: %w", err)
	}
	return &PinArchiveStore{root: root, readOnly: true}, nil
}

func requireRealDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("must be a real directory")
	}
	return nil
}

// readPinnedBundleFile reads one regular file below root without following the final entry. It is
// for bundle metadata that is trusted only after the caller validates its bytes, not for arbitrary
// path input.
func readPinnedBundleFile(root, relative string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("pinned bundle root must be an absolute path")
	}
	if !validPinnedBundleRelativePath(relative) {
		return nil, errors.New("pinned bundle file must be a clean relative path")
	}
	if limit < 0 || limit == math.MaxInt64 {
		return nil, errors.New("pinned bundle file limit is invalid")
	}
	file, err := openPinnedBundleFile(root, relative)
	if err != nil {
		return nil, fmt.Errorf("open pinned bundle file %q: %w", relative, err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect pinned bundle file %q: %w", relative, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("pinned bundle file %q is not a regular file", relative)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("pinned bundle file %q exceeds %d bytes", relative, limit)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read pinned bundle file %q: %w", relative, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("pinned bundle file %q exceeds %d bytes", relative, limit)
	}
	return data, nil
}

func validPinnedBundleRelativePath(relative string) bool {
	if relative == "" || filepath.IsAbs(relative) || filepath.VolumeName(relative) != "" {
		return false
	}
	for _, part := range strings.Split(strings.ReplaceAll(relative, "\\", "/"), "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
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
	if s == nil {
		return errors.New("pin archive store is required")
	}
	if s.readOnly {
		return errors.New("pin archive store is read-only")
	}
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
	// A digest-named path may exist without holding the pinned bytes. Rehash it before treating a
	// repeated archive as complete, including its type and length.
	if _, err := os.Lstat(path); err == nil {
		if _, err := s.CopyTo(actual, int64(len(data)), io.Discard); err != nil {
			return fmt.Errorf("verify existing archived pin %s: %w", actual, err)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect archived pin %s: %w", actual, err)
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
	return s.StoreFileContext(context.Background(), source)
}

// StoreFileContext streams one materialized input file into the CAS while observing cancellation
// between bounded copy chunks. StoreFile remains available for callers without a request context.
func (s *PinArchiveStore) StoreFileContext(ctx context.Context, source string) (string, int64, error) {
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	if s == nil {
		return "", 0, errors.New("pin archive store is required")
	}
	if s.readOnly {
		return "", 0, errors.New("pin archive store is read-only")
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
	written, copyErr := copyWithContext(ctx, io.MultiWriter(temporary, hash), io.LimitReader(input, maxMaterializedInputObjectBytes+1))
	inputCloseErr := input.Close()
	if copyErr != nil {
		return "", 0, fmt.Errorf("stream materialized input file: %w", copyErr)
	}
	if inputCloseErr != nil {
		return "", 0, errors.New("stream materialized input file")
	}
	if err := ctx.Err(); err != nil {
		return "", 0, err
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
	if err := ctx.Err(); err != nil {
		return "", 0, err
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
		if _, err := s.CopyToContext(ctx, digest, written, io.Discard); err != nil {
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
	return s.CopyToContext(context.Background(), digest, expectedBytes, destination)
}

// CopyToContext rehashes a materialized archive object while streaming it to destination. It checks
// cancellation after at most 64 KiB of input so restoring a large archive responds to shutdown.
func (s *PinArchiveStore) CopyToContext(ctx context.Context, digest string, expectedBytes int64, destination io.Writer) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
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
	input, err := openPinnedBundleFile(s.root, filepath.Join("blobs", strings.TrimPrefix(digest, "sha256:")))
	if err != nil {
		return 0, fmt.Errorf("open materialized archive object %s: %w", digest, err)
	}
	opened, err := input.Stat()
	if err != nil {
		_ = input.Close()
		return 0, fmt.Errorf("inspect opened materialized archive object %s: %w", digest, err)
	}
	if !opened.Mode().IsRegular() {
		_ = input.Close()
		return 0, fmt.Errorf("materialized archive object %s is not a regular file", digest)
	}
	if opened.Size() != expectedBytes || opened.Size() > maxMaterializedInputObjectBytes {
		_ = input.Close()
		return 0, fmt.Errorf("materialized archive object %s length %d does not match expected length %d", digest, opened.Size(), expectedBytes)
	}
	before := opened
	hash := sha256.New()
	written, copyErr := copyWithContext(ctx, io.MultiWriter(destination, hash), io.LimitReader(input, maxMaterializedInputObjectBytes+1))
	closeErr := input.Close()
	if copyErr != nil {
		return written, fmt.Errorf("stream materialized archive object %s: %w", digest, copyErr)
	}
	if closeErr != nil {
		return 0, fmt.Errorf("stream materialized archive object %s", digest)
	}
	if err := ctx.Err(); err != nil {
		return written, err
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

// copyWithContext keeps archive streaming bounded and makes each transfer interruptible between
// chunks. Filesystem reads and writes are synchronous, so a single in-flight system call cannot be
// cancelled; limiting chunks bounds the normal cancellation latency without buffering whole inputs.
func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, archiveCopyBufferBytes)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			count, writeErr := destination.Write(buffer[:read])
			written += int64(count)
			if writeErr != nil {
				return written, writeErr
			}
			if count != read {
				return written, io.ErrShortWrite
			}
			if err := ctx.Err(); err != nil {
				return written, err
			}
		}
		if readErr == io.EOF {
			return written, ctx.Err()
		}
		if readErr != nil {
			return written, readErr
		}
	}
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
