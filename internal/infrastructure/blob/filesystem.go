package blob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Filesystem retains immutable uploaded objects on a volume shared by API and
// workers. Root-relative operations confine every object path, including symlinks.
type Filesystem struct{ root *os.Root }

var _ ports.ObjectStore = (*Filesystem)(nil)

func NewFilesystem(directory string) (*Filesystem, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) == string(filepath.Separator) {
		return nil, fmt.Errorf("object directory must be an absolute, non-root path")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create object directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("object directory must be a real directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open object directory: %w", err)
	}
	return &Filesystem{root: root}, nil
}

func (s *Filesystem) Close() error { return s.root.Close() }

func validateObjectKey(key string) error {
	if key == "" || len(key) > 1024 || path.IsAbs(key) || path.Clean(key) != key || key == "." || key == ".." || strings.HasPrefix(key, "../") || strings.ContainsAny(key, "\\\x00\r\n") {
		return fmt.Errorf("%w: invalid object key", shared.ErrValidation)
	}
	for _, part := range strings.Split(key, "/") {
		if strings.HasPrefix(part, ".") {
			return fmt.Errorf("%w: hidden object paths are reserved", shared.ErrValidation)
		}
	}
	return nil
}

type contextReader struct {
	ctx context.Context
	src io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.src.Read(p)
}

func (s *Filesystem) PutObject(ctx context.Context, key string, src io.Reader, size int64) error {
	if err := validateObjectKey(key); err != nil {
		return err
	}
	if src == nil || size < 0 || size == math.MaxInt64 {
		return fmt.Errorf("%w: invalid object stream size", shared.ErrValidation)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := path.Dir(key)
	if err := s.root.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create object path: %w", err)
	}
	staging := path.Join(dir, ".upload-"+idgen.RandomID{}.NewID().String())
	file, err := s.root.OpenFile(staging, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("stage object: %w", err)
	}
	defer func() { _ = s.root.Remove(staging) }()
	written, copyErr := io.Copy(file, io.LimitReader(contextReader{ctx: ctx, src: src}, size+1))
	if copyErr == nil && written != size {
		copyErr = fmt.Errorf("%w: object size mismatch", shared.ErrValidation)
	}
	if copyErr == nil {
		copyErr = ctx.Err()
	}
	if copyErr == nil {
		copyErr = file.Sync()
	}
	if err := errors.Join(copyErr, file.Close()); err != nil {
		return err
	}
	// Link is atomic and create-only: concurrent uploads never replace the
	// published bytes, and no reader can observe a partial staging file.
	if err := s.root.Link(staging, key); err != nil {
		if errors.Is(err, os.ErrExist) {
			return shared.ErrConflict
		}
		return fmt.Errorf("publish object: %w", err)
	}
	directory, err := s.root.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func (s *Filesystem) OpenObject(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := validateObjectKey(key); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := s.root.Lstat(key)
	if errors.Is(err, os.ErrNotExist) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: object is not a regular file", shared.ErrValidation)
	}
	return s.root.Open(key)
}

func (s *Filesystem) DeleteObject(ctx context.Context, key string) error {
	if err := validateObjectKey(key); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := s.root.Lstat(key)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: object is not a regular file", shared.ErrValidation)
	}
	return s.root.Remove(key)
}
