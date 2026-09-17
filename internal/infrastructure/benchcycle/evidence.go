package benchcycle

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"sync"
)

const evidenceCopyBufferSize = 32 << 10

// EvidenceLimits bounds the disk consumed by one evidence store.
type EvidenceLimits struct {
	MaxArtifactBytes int64
	MaxTotalBytes    int64
	MaxFiles         int
}

// EvidenceReceipt identifies durable evidence without retaining its contents in memory.
type EvidenceReceipt struct {
	Reference string
	Size      int64
	Digest    string
}

// EvidenceStore streams attempt-scoped evidence beneath one trusted root.
type EvidenceStore struct {
	root   string
	limits EvidenceLimits

	mu    sync.Mutex
	bytes int64
	files int
}

// NewEvidenceStore creates an evidence store rooted at an existing trusted directory.
func NewEvidenceStore(root string, limits EvidenceLimits) (*EvidenceStore, error) {
	if limits.MaxArtifactBytes < 1 {
		return nil, errors.New("evidence artifact byte limit must be positive")
	}
	if limits.MaxTotalBytes < limits.MaxArtifactBytes {
		return nil, errors.New("evidence aggregate byte limit must cover one artifact")
	}
	if limits.MaxFiles < 1 {
		return nil, errors.New("evidence file limit must be positive")
	}
	trustedRoot, err := RealDirectory(root)
	if err != nil {
		return nil, fmt.Errorf("validate evidence root: %w", err)
	}
	return &EvidenceStore{root: trustedRoot, limits: limits}, nil
}

// Write streams one named evidence artifact into a safe attempt-scoped path.
func (store *EvidenceStore) Write(ctx context.Context, address AttemptAddress, name string, source io.Reader) (EvidenceReceipt, error) {
	if store == nil {
		return EvidenceReceipt{}, errors.New("evidence store is required")
	}
	if ctx == nil {
		return EvidenceReceipt{}, errors.New("evidence context is required")
	}
	if err := ctx.Err(); err != nil {
		return EvidenceReceipt{}, err
	}
	if err := ValidateAttemptAddress(address); err != nil {
		return EvidenceReceipt{}, err
	}
	if !PortableRunSegment(name) {
		return EvidenceReceipt{}, fmt.Errorf("evidence artifact name %q is unsafe", name)
	}
	if source == nil {
		return EvidenceReceipt{}, errors.New("evidence source is required")
	}

	reference := path.Join("attempts", evidenceCellDirectory(address.CellKey), "pass-"+strconv.Itoa(address.Repetition), name)
	directory, err := safeEvidenceDirectory(store.root, address)
	if err != nil {
		return EvidenceReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return EvidenceReceipt{}, err
	}
	if err := store.reserveFile(); err != nil {
		return EvidenceReceipt{}, err
	}

	artifactPath := filepath.Join(directory, name)
	file, err := os.OpenFile(artifactPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		store.release(0, true)
		return EvidenceReceipt{}, fmt.Errorf("create evidence artifact: %w", err)
	}
	closed := false
	reservedBytes := int64(0)
	success := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		if !success {
			_ = os.Remove(artifactPath)
			store.release(reservedBytes, true)
		}
	}()

	digest := sha256.New()
	buffer := make([]byte, evidenceCopyBufferSize)
	for {
		if err := ctx.Err(); err != nil {
			return EvidenceReceipt{}, err
		}
		read, readErr := source.Read(buffer)
		if read < 0 || read > len(buffer) {
			return EvidenceReceipt{}, errors.New("evidence source returned an invalid byte count")
		}
		if read > 0 {
			if err := ctx.Err(); err != nil {
				return EvidenceReceipt{}, err
			}
			bytesRead := int64(read)
			if bytesRead > store.limits.MaxArtifactBytes-reservedBytes {
				return EvidenceReceipt{}, fmt.Errorf("evidence artifact exceeds %d byte limit", store.limits.MaxArtifactBytes)
			}
			if err := store.reserveBytes(bytesRead); err != nil {
				return EvidenceReceipt{}, err
			}
			reservedBytes += bytesRead
			written, writeErr := file.Write(buffer[:read])
			if written > 0 {
				if _, err := digest.Write(buffer[:written]); err != nil {
					return EvidenceReceipt{}, fmt.Errorf("hash evidence artifact: %w", err)
				}
			}
			if writeErr != nil {
				return EvidenceReceipt{}, fmt.Errorf("write evidence artifact: %w", writeErr)
			}
			if written != read {
				return EvidenceReceipt{}, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return EvidenceReceipt{}, fmt.Errorf("read evidence source: %w", readErr)
		}
		if read == 0 {
			return EvidenceReceipt{}, io.ErrNoProgress
		}
	}
	if err := ctx.Err(); err != nil {
		return EvidenceReceipt{}, err
	}
	if err := file.Sync(); err != nil {
		return EvidenceReceipt{}, fmt.Errorf("sync evidence artifact: %w", err)
	}
	if err := file.Close(); err != nil {
		return EvidenceReceipt{}, fmt.Errorf("close evidence artifact: %w", err)
	}
	closed = true
	if err := SyncDirectory(directory); err != nil {
		return EvidenceReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return EvidenceReceipt{}, err
	}
	success = true
	return EvidenceReceipt{Reference: reference, Size: reservedBytes, Digest: fmt.Sprintf("%x", digest.Sum(nil))}, nil
}

// ValidateAttemptAddress verifies an address produced by the fixed two-pass executor.
func ValidateAttemptAddress(address AttemptAddress) error {
	if err := ValidateTwoPassCellKey(address.CellKey); err != nil {
		return err
	}
	if address.Repetition != 1 && address.Repetition != 2 {
		return errors.New("attempt repetition must be one or two")
	}
	return nil
}

func safeEvidenceDirectory(root string, address AttemptAddress) (string, error) {
	if err := requireRealDirectory(root); err != nil {
		return "", fmt.Errorf("validate evidence root: %w", err)
	}
	segments := []string{"attempts", evidenceCellDirectory(address.CellKey), "pass-" + strconv.Itoa(address.Repetition)}
	current := root
	for _, segment := range segments {
		current = filepath.Join(current, segment)
		if err := createRealDirectory(current); err != nil {
			return "", fmt.Errorf("create evidence directory: %w", err)
		}
	}
	return current, nil
}

func evidenceCellDirectory(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "cell-" + fmt.Sprintf("%x", sum[:])
}

func createRealDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if os.IsNotExist(err) {
		if err := os.Mkdir(directory, 0o700); err != nil && !os.IsExist(err) {
			return err
		}
		info, err = os.Lstat(directory)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("path must be a real directory")
	}
	return nil
}

func (store *EvidenceStore) reserveFile() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.files >= store.limits.MaxFiles {
		return fmt.Errorf("evidence exceeds %d file limit", store.limits.MaxFiles)
	}
	store.files++
	return nil
}

func (store *EvidenceStore) reserveBytes(size int64) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if size > store.limits.MaxTotalBytes-store.bytes {
		return fmt.Errorf("evidence exceeds %d aggregate byte limit", store.limits.MaxTotalBytes)
	}
	store.bytes += size
	return nil
}

func (store *EvidenceStore) release(size int64, file bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.bytes -= size
	if file {
		store.files--
	}
}
