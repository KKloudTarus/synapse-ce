package file

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type ProjectArchiveStore struct {
	dir      string
	maxBytes int64
}

func NewProjectArchiveStore(dir string, maxBytes int64) *ProjectArchiveStore {
	return &ProjectArchiveStore{dir: dir, maxBytes: maxBytes}
}

var _ ports.ProjectArchiveStore = (*ProjectArchiveStore)(nil)

func archiveExtension(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, ext := range []string{".tar.gz", ".tgz", ".zip"} {
		if strings.HasSuffix(name, ext) {
			return ext
		}
	}
	return ""
}

func (s *ProjectArchiveStore) Save(ctx context.Context, projectID shared.ID, filename string, src io.Reader) (string, error) {
	ext := archiveExtension(filename)
	if projectID.IsZero() || ext == "" {
		return "", fmt.Errorf("%w: uploaded source must be .zip, .tar.gz, or .tgz", shared.ErrValidation)
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return "", fmt.Errorf("create project upload directory: %w", err)
	}
	final := filepath.Join(s.dir, projectID.String()+ext)
	tmp, err := os.CreateTemp(s.dir, projectID.String()+"-*.upload")
	if err != nil {
		return "", fmt.Errorf("create project upload: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	limit := s.maxBytes
	if limit <= 0 || limit > 512<<20 {
		limit = 512 << 20
	}
	written, copyErr := io.Copy(tmp, io.LimitReader(src, limit+1))
	closeErr := tmp.Close()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if copyErr != nil {
		return "", fmt.Errorf("store project upload: %w", copyErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close project upload: %w", closeErr)
	}
	if written > limit {
		return "", fmt.Errorf("%w: uploaded archive exceeds %d bytes", shared.ErrValidation, limit)
	}
	_ = os.Remove(final)
	if err := os.Rename(tmpName, final); err != nil {
		return "", fmt.Errorf("publish project upload: %w", err)
	}
	return filepath.Abs(final)
}

func (s *ProjectArchiveStore) Delete(_ context.Context, projectID shared.ID) error {
	for _, ext := range []string{".tar.gz", ".tgz", ".zip"} {
		if err := os.Remove(filepath.Join(s.dir, projectID.String()+ext)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("delete project upload: %w", err)
		}
	}
	return nil
}
