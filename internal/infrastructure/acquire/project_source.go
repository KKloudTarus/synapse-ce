package acquire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// maxProjectSourceEntries keeps a tiny, selected subtree from consuming an
// unbounded amount of metadata work even when its byte size is small.
const maxProjectSourceEntries = 100_000

const projectSourceReadBatch = 128

func acquireProjectSource(ctx context.Context, req ports.AcquireRequest, maxBytes int64) (*ports.Workspace, error) {
	selection, relative, err := validateProjectSourceRequest(req)
	if err != nil {
		return nil, err
	}
	if maxBytes <= 0 {
		maxBytes = MaxWorkspaceBytes
	}
	rootInfo, err := os.Lstat(selection.Root)
	if err != nil {
		return nil, fmt.Errorf("stat project source root: %w", err)
	}
	if rootInfo.Mode()&fs.ModeSymlink != 0 || !rootInfo.IsDir() {
		return nil, fmt.Errorf("%w: project source root must be a non-symlink directory", shared.ErrValidation)
	}

	root, err := os.OpenRoot(selection.Root)
	if err != nil {
		return nil, fmt.Errorf("open project source root: %w", err)
	}
	defer func() { _ = root.Close() }()
	if err := rejectProjectSourceSymlinkComponents(root, relative); err != nil {
		return nil, err
	}
	selectedInfo, err := root.Lstat(relative)
	if err != nil {
		return nil, fmt.Errorf("inspect project source selection: %w", err)
	}
	subtree, err := root.OpenRoot(relative)
	if err != nil {
		return nil, fmt.Errorf("open project source selection: %w", err)
	}
	defer func() { _ = subtree.Close() }()
	selected, err := subtree.Open(".")
	if err != nil {
		return nil, fmt.Errorf("inspect opened project source selection: %w", err)
	}
	openedSelection, statErr := selected.Stat()
	closeErr := selected.Close()
	if statErr != nil {
		return nil, fmt.Errorf("inspect opened project source selection: %w", statErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close project source selection: %w", closeErr)
	}
	if !openedSelection.IsDir() || !os.SameFile(selectedInfo, openedSelection) {
		return nil, fmt.Errorf("%w: project source selection changed while opening", shared.ErrValidation)
	}

	dir, err := os.MkdirTemp("", "synapse-project-source-*")
	if err != nil {
		return nil, fmt.Errorf("create project source snapshot: %w", err)
	}
	cleanup := func() error { return os.RemoveAll(dir) }
	if err := copyProjectSourceSnapshot(ctx, subtree, dir, maxBytes); err != nil {
		_ = cleanup()
		return nil, err
	}
	lockfiles, localModules, unresolved, err := inspectWorkspace(dir, maxBytes)
	if err != nil {
		_ = cleanup()
		return nil, err
	}
	return &ports.Workspace{Dir: dir, Lockfiles: lockfiles, LocalModules: localModules, UnresolvedEcosystems: unresolved, Cleanup: cleanup}, nil
}

func validateProjectSourceRequest(req ports.AcquireRequest) (*ports.ProjectSourceSelection, string, error) {
	selection := req.ProjectSource
	if selection == nil || selection.ProjectID.IsZero() || strings.TrimSpace(selection.Root) == "" {
		return nil, "", fmt.Errorf("%w: project source selection is required", shared.ErrValidation)
	}
	if req.Kind != ports.TargetLocal || strings.ContainsRune(selection.Root, '\x00') || !filepath.IsAbs(selection.Root) || filepath.Clean(selection.Root) != selection.Root {
		return nil, "", fmt.Errorf("%w: invalid project source root", shared.ErrValidation)
	}
	if strings.ContainsRune(selection.Subdirectory, '\x00') || strings.Contains(selection.Subdirectory, `\`) || strings.TrimSpace(selection.Subdirectory) != selection.Subdirectory {
		return nil, "", fmt.Errorf("%w: invalid project source subdirectory", shared.ErrValidation)
	}
	clean := path.Clean(selection.Subdirectory)
	if selection.Subdirectory == "" || clean == "." || clean != selection.Subdirectory || strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "../") || clean == ".." {
		return nil, "", fmt.Errorf("%w: project source subdirectory must be a canonical relative child", shared.ErrValidation)
	}
	relative := filepath.FromSlash(clean)
	if req.Value != filepath.Join(selection.Root, relative) {
		return nil, "", fmt.Errorf("%w: project source target does not match its selection", shared.ErrValidation)
	}
	return selection, relative, nil
}

func rejectProjectSourceSymlinkComponents(root *os.Root, relative string) error {
	current := ""
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := root.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect project source component: %w", err)
		}
		if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: project source selection contains a symlink or non-directory component", shared.ErrValidation)
		}
	}
	return nil
}

func copyProjectSourceSnapshot(ctx context.Context, root *os.Root, destination string, maxBytes int64) error {
	var total int64
	entries := 0
	pending := []string{"."}
	for len(pending) > 0 {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("snapshot project source: %w", err)
		}
		directory := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		dir, err := openProjectSourceDirectory(root, directory)
		if err != nil {
			return fmt.Errorf("snapshot project source: %w", err)
		}
		readErr := func() error {
			for {
				if err := ctx.Err(); err != nil {
					return err
				}
				batch, err := dir.ReadDir(projectSourceReadBatch)
				for _, entry := range batch {
					if err := ctx.Err(); err != nil {
						return err
					}
					entries++
					if entries > maxProjectSourceEntries {
						return fmt.Errorf("%w: project source exceeds the %d-entry cap", shared.ErrValidation, maxProjectSourceEntries)
					}
					name := entry.Name()
					if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
						return fmt.Errorf("%w: project source contains an invalid directory entry", shared.ErrValidation)
					}
					relative := name
					if directory != "." {
						relative = filepath.Join(directory, name)
					}
					info, err := root.Lstat(relative)
					if err != nil {
						return fmt.Errorf("inspect project source entry: %w", err)
					}
					if info.Mode()&fs.ModeSymlink != 0 {
						return fmt.Errorf("%w: project source contains a symlink", shared.ErrValidation)
					}
					destinationPath := filepath.Join(destination, relative)
					switch {
					case info.IsDir():
						if err := confirmProjectSourceDirectory(root, relative, info); err != nil {
							return err
						}
						if err := os.MkdirAll(destinationPath, 0o700); err != nil {
							return err
						}
						pending = append(pending, relative)
					case info.Mode().IsRegular():
						if total > maxBytes-info.Size() {
							return fmt.Errorf("%w: project source exceeds the %d-byte workspace cap", shared.ErrValidation, maxBytes)
						}
						copied, err := copyProjectSourceFile(ctx, root, relative, info, destinationPath)
						if err != nil {
							return err
						}
						total += copied
					default:
						return fmt.Errorf("%w: project source contains a special file", shared.ErrValidation)
					}
				}
				if err == io.EOF {
					return nil
				}
				if err != nil {
					return err
				}
			}
		}()
		closeErr := dir.Close()
		if readErr != nil {
			if closeErr != nil {
				return fmt.Errorf("snapshot project source: %w", errors.Join(readErr, closeErr))
			}
			return fmt.Errorf("snapshot project source: %w", readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("snapshot project source: close source directory: %w", closeErr)
		}
	}
	return nil
}

func openProjectSourceDirectory(root *os.Root, name string) (*os.File, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("inspect project source directory: %w", err)
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open project source directory: %w", err)
	}
	opened, statErr := file.Stat()
	if statErr != nil || info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() || !opened.IsDir() || !os.SameFile(info, opened) {
		closeErr := file.Close()
		if statErr != nil {
			return nil, errors.Join(statErr, closeErr)
		}
		return nil, errors.Join(fmt.Errorf("%w: project source directory changed while snapshotting", shared.ErrValidation), closeErr)
	}
	return file, nil
}

func confirmProjectSourceDirectory(root *os.Root, name string, expected fs.FileInfo) error {
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open project source directory: %w", err)
	}
	opened, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil {
		return errors.Join(statErr, closeErr)
	}
	if !opened.IsDir() || !os.SameFile(expected, opened) {
		return errors.Join(fmt.Errorf("%w: project source directory changed while snapshotting", shared.ErrValidation), closeErr)
	}
	return closeErr
}

func copyProjectSourceFile(ctx context.Context, root *os.Root, name string, expected fs.FileInfo, destination string) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	in, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, fmt.Errorf("open project source file: %w", err)
	}
	opened, statErr := in.Stat()
	if statErr != nil || !opened.Mode().IsRegular() || opened.Size() != expected.Size() || !os.SameFile(expected, opened) {
		closeErr := in.Close()
		if statErr != nil {
			return 0, errors.Join(statErr, closeErr)
		}
		return 0, errors.Join(fmt.Errorf("%w: project source changed while snapshotting", shared.ErrValidation), closeErr)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		_ = in.Close()
		return 0, err
	}
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = in.Close()
		return 0, err
	}
	copied, copyErr := copyProjectSourceFileContents(ctx, out, io.LimitReader(in, expected.Size()+1))
	closeErr := errors.Join(out.Close(), in.Close())
	if copyErr != nil {
		return 0, errors.Join(copyErr, closeErr)
	}
	if closeErr != nil {
		return 0, closeErr
	}
	if copied != expected.Size() {
		return 0, fmt.Errorf("%w: project source changed while snapshotting", shared.ErrValidation)
	}
	return copied, nil
}

func copyProjectSourceFileContents(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 32*1024)
	var copied int64
	for {
		if err := ctx.Err(); err != nil {
			return copied, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			if err := ctx.Err(); err != nil {
				return copied, err
			}
			written, writeErr := destination.Write(buffer[:read])
			copied += int64(written)
			if writeErr != nil {
				return copied, writeErr
			}
			if written != read {
				return copied, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			return copied, nil
		}
		if readErr != nil {
			return copied, readErr
		}
		if read == 0 {
			return copied, io.ErrNoProgress
		}
	}
}
