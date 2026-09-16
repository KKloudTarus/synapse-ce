package benchcycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidateIdentity verifies the portable identity used to isolate a benchmark run.
func ValidateIdentity(implementationCommit, runKey string) error {
	if !FullSHA(implementationCommit) {
		return errors.New("implementation commit must be a 40-character lowercase SHA")
	}
	if err := ValidateRunKey(runKey); err != nil {
		return err
	}
	return nil
}

// ValidateRunKey verifies a two-segment portable benchmark run key.
func ValidateRunKey(runKey string) error {
	parts := strings.Split(runKey, "/")
	if len(parts) != 2 || !PortableRunSegment(parts[0]) || !PortableRunSegment(parts[1]) {
		return errors.New("run key must contain exactly two portable path segments")
	}
	return nil
}

// FullSHA reports whether value is a lowercase, full-length SHA-1 commit ID.
func FullSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

// PortableRunSegment reports whether value is safe to use as one portable path segment.
func PortableRunSegment(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

// ValidateAbsolutePath rejects empty and relative paths.
func ValidateAbsolutePath(name, path string) error {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("%s must be an absolute path", name)
	}
	return nil
}

// EnsureAbsent rejects an existing destination without following a final symlink.
func EnsureAbsent(path, label string) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%s already exists", label)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect %s: %w", label, err)
	}
	return nil
}

// RealDirectory returns an absolute real directory path without following a final symlink.
func RealDirectory(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("path must be a real directory")
	}
	return filepath.Abs(path)
}

// BelowRoot resolves locator beneath root and accepts only regular non-symlink files.
func BelowRoot(root, locator string) (string, error) {
	if filepath.IsAbs(locator) {
		return "", errors.New("asset locator must be relative")
	}
	path := filepath.Join(root, filepath.FromSlash(locator))
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("asset locator escapes trusted input root")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("asset must be a regular non-symlink file")
	}
	return path, nil
}

// Workspace contains the isolated work and raw-retention paths for one benchmark run.
type Workspace struct {
	workRoot   string
	rawRunRoot string
}

// WorkRoot returns the private work directory created for this workspace.
func (workspace Workspace) WorkRoot() string {
	return workspace.workRoot
}

// RawRunRoot returns the derived raw-retention path for this workspace.
func (workspace Workspace) RawRunRoot() string {
	return workspace.rawRunRoot
}

// PrepareWorkspace creates a private work directory and derives a raw-retention path.
func PrepareWorkspace(rawRetentionRoot, runKey string) (Workspace, error) {
	if err := ValidateAbsolutePath("raw retention root", rawRetentionRoot); err != nil {
		return Workspace{}, err
	}
	if err := ValidateRunKey(runKey); err != nil {
		return Workspace{}, err
	}
	workRoot, err := os.MkdirTemp("", "synapse-benchmark-cycle-")
	if err != nil {
		return Workspace{}, fmt.Errorf("create run workspace: %w", err)
	}
	rawRoot, err := RealDirectory(rawRetentionRoot)
	if err != nil {
		_ = os.RemoveAll(workRoot)
		return Workspace{}, fmt.Errorf("validate raw retention root: %w", err)
	}
	parts := strings.Split(runKey, "/")
	return Workspace{
		workRoot:   workRoot,
		rawRunRoot: filepath.Join(rawRoot, parts[0], parts[1]),
	}, nil
}

// RemoveWork removes only the private work directory created for this workspace.
func (workspace Workspace) RemoveWork() error {
	return removeDirectory(workspace.workRoot)
}

// Cleanup removes raw and work state before running the injected runtime cleanup.
func (workspace Workspace) Cleanup(ctx context.Context, runtimeCleanup func(context.Context) error) error {
	if err := removeDirectory(workspace.rawRunRoot); err != nil {
		return fmt.Errorf("remove raw run state: %w", err)
	}
	if err := workspace.RemoveWork(); err != nil {
		return fmt.Errorf("remove run workspace: %w", err)
	}
	if runtimeCleanup != nil {
		if err := runtimeCleanup(ctx); err != nil {
			return err
		}
	}
	return nil
}

func removeDirectory(path string) error {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return errors.New("cleanup path must be an absolute path")
	}
	cleaned := filepath.Clean(path)
	if cleaned == filepath.VolumeName(cleaned)+string(filepath.Separator) {
		return errors.New("refusing to remove filesystem root")
	}
	if err := os.RemoveAll(cleaned); err != nil {
		return err
	}
	if _, err := os.Lstat(cleaned); err == nil {
		return errors.New("cleanup path remains")
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}
