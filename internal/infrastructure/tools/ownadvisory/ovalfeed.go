package ownadvisory

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// OVALDirFeed is an AdvisoryFeed over a complete local snapshot of vendor OVAL files. Every eligible file is
// read and parsed before any advisory is emitted, so malformed, unreadable, oversized, or partial input cannot
// be mistaken for an authoritative current snapshot. Plain XML and the vendor .bz2/.gz forms are supported.
type OVALDirFeed struct {
	dir string
}

// NewOVALDirFeed returns a feed over the given OVAL snapshot directory.
func NewOVALDirFeed(dir string) *OVALDirFeed { return &OVALDirFeed{dir: dir} }

var _ ports.AdvisoryFeed = (*OVALDirFeed)(nil)

// Each reduces the complete directory through ParseOVALSnapshot and emits the resulting current projection,
// including explicit empty advisories that retire stale source-local applicability. A successful snapshot has
// no skipped records; any in-scope file failure rejects the whole snapshot.
func (f *OVALDirFeed) Each(ctx context.Context, fn func(a advisory.Advisory) error) (int, error) {
	return f.eachWithLimits(ctx, defaultOVALSnapshotLimits(), fn)
}

// eachWithLimits keeps production limits in one place while allowing focused tests to exercise aggregate
// boundaries without allocating production-sized fixtures.
func (f *OVALDirFeed) eachWithLimits(ctx context.Context, limits ovalSnapshotLimits, fn func(a advisory.Advisory) error) (int, error) {
	documents, err := readOVALSnapshotWithLimits(ctx, f.dir, limits)
	if err != nil {
		return 0, err
	}
	advisories, err := parseOVALSnapshotWithLimits(documents, limits)
	if err != nil {
		return 0, fmt.Errorf("parse OVAL snapshot: %w", err)
	}
	for _, adv := range advisories {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if err := fn(adv); err != nil {
			return 0, err
		}
	}
	return 0, nil
}

func readOVALSnapshotWithLimits(ctx context.Context, dir string, limits ovalSnapshotLimits) ([][]byte, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat OVAL snapshot dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: OVAL snapshot path must be a directory, got %q", shared.ErrValidation, dir)
	}
	documents := make([][]byte, 0)
	files := 0
	rawBytes := int64(0)
	err = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() || !hasOVALSuffix(entry.Name()) {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%w: OVAL snapshot entry %q is not a regular file", shared.ErrValidation, path)
		}
		files++
		if files > maxAdvisoryFiles {
			return fmt.Errorf("%w: OVAL snapshot exceeds %d files", shared.ErrValidation, maxAdvisoryFiles)
		}
		fileInfo, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("lstat OVAL snapshot file %q: %w", path, err)
		}
		if !fileInfo.Mode().IsRegular() {
			return fmt.Errorf("%w: OVAL snapshot entry %q changed to a non-regular file", shared.ErrValidation, path)
		}
		if fileInfo.Size() > limits.fileBytes {
			return fmt.Errorf("%w: OVAL snapshot file %q exceeds %d bytes", shared.ErrValidation, path, limits.fileBytes)
		}
		remaining := limits.snapshotBytes - rawBytes
		if fileInfo.Size() > remaining {
			return fmt.Errorf("%w: OVAL snapshot exceeds %d raw bytes", shared.ErrValidation, limits.snapshotBytes)
		}
		readLimit := limits.fileBytes
		if remaining < readLimit {
			readLimit = remaining
		}
		content, err := readOVALSnapshotFile(path, readLimit)
		if err != nil {
			return fmt.Errorf("read OVAL snapshot file %q: %w", path, err)
		}
		contentBytes := int64(len(content))
		if contentBytes > limits.fileBytes {
			return fmt.Errorf("%w: OVAL snapshot file %q exceeds %d bytes", shared.ErrValidation, path, limits.fileBytes)
		}
		if contentBytes > remaining {
			return fmt.Errorf("%w: OVAL snapshot exceeds %d raw bytes", shared.ErrValidation, limits.snapshotBytes)
		}
		rawBytes += contentBytes
		documents = append(documents, content)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk OVAL snapshot dir: %w", err)
	}
	if len(documents) == 0 {
		return nil, fmt.Errorf("%w: OVAL snapshot contains no eligible files", shared.ErrValidation)
	}
	return documents, nil
}

func readOVALSnapshotFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- WalkDir path is beneath dir and Lstat re-verifies a regular file immediately before opening.
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: OVAL snapshot entry changed to a non-regular file", shared.ErrValidation)
	}
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	return content, nil
}
