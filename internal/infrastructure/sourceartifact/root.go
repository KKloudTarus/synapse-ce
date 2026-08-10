package sourceartifact

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// validateWriteRoot fails closed before any source artifact write. In particular, a caller may not
// rely on the process working directory to turn an untrusted relative path into durable evidence.
func (s *Store) validateWriteRoot() error {
	if !filepath.IsAbs(s.root) {
		return fmt.Errorf("%w: source artifact root must be absolute", shared.ErrValidation)
	}
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return fmt.Errorf("create source artifact root: %w", err)
	}
	info, err := os.Lstat(s.root)
	if err != nil {
		return fmt.Errorf("inspect source artifact root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: source artifact root must be a configured directory, not a symlink", shared.ErrValidation)
	}
	return nil
}

// validateSourceIsolation runs before validateWriteRoot so a bad configuration cannot create even
// an empty artifact directory inside the tree being scanned. It resolves existing parent symlinks
// for a not-yet-created artifact path, preventing a lexically external path from aliasing the tree.
func (s *Store) validateSourceIsolation(sourceDir string) error {
	if !filepath.IsAbs(s.root) {
		return fmt.Errorf("%w: source artifact root must be absolute", shared.ErrValidation)
	}
	source, err := filepath.Abs(sourceDir)
	if err != nil {
		return fmt.Errorf("resolve scanned source root: %w", err)
	}
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		return fmt.Errorf("resolve scanned source root symlinks: %w", err)
	}
	root, err := resolveProspectivePath(s.root)
	if err != nil {
		return fmt.Errorf("resolve source artifact root: %w", err)
	}
	inside, err := pathWithin(source, root)
	if err != nil {
		return fmt.Errorf("compare source artifact root with scanned tree: %w", err)
	}
	if inside {
		return fmt.Errorf("%w: source artifact root must not resolve inside the scanned tree", shared.ErrValidation)
	}
	return nil
}

func resolveProspectivePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	current := absolute
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			parts := append([]string{resolved}, suffix...)
			return filepath.Clean(filepath.Join(parts...)), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		suffix = append([]string{filepath.Base(current)}, suffix...)
		current = parent
	}
}

func pathWithin(parent, candidate string) (bool, error) {
	parent = filepath.Clean(parent)
	candidate = filepath.Clean(candidate)
	if parent == candidate {
		return true, nil
	}
	if filepath.VolumeName(parent) != filepath.VolumeName(candidate) {
		return false, nil
	}
	rel, err := filepath.Rel(parent, candidate)
	if err != nil {
		return false, err
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)), nil
}
