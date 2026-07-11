package acquire

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Archive extraction is hardened against the classic untrusted-archive attacks:
// path traversal / "zip-slip": every entry is constrained to stay within the
// workspace (safeJoin), so `../../etc/cron.d/x` cannot escape;
// symlink/hardlink/device escape: only regular files + directories are written,
// link + special entries are skipped (a symlink could later redirect a read/write
// outside the workspace);
// decompression bombs: a per-file cap, the workspace total cap, and an entry-count
// cap bound how much an archive can expand to.
const (
	maxArchiveEntries   = 200_000   // entry-count cap (bomb guard)
	maxArchiveFileBytes = 512 << 20 // per-file extracted-size cap
)

// acquireArchive extracts a local.zip/.tar.gz/.tgz/.tar into an isolated, cleaned-up
// workspace, with the hardening above. The archive itself is only read, never executed.
func acquireArchive(value string, maxBytes int64) (*ports.Workspace, error) {
	if maxBytes <= 0 {
		maxBytes = MaxWorkspaceBytes
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("%w: target value is required", shared.ErrValidation)
	}
	fi, err := os.Lstat(value) // do not follow a symlinked archive path
	if err != nil {
		return nil, fmt.Errorf("stat archive: %w", err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: archive path is a symlink", shared.ErrValidation)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: archive is not a regular file", shared.ErrValidation)
	}

	dir, err := os.MkdirTemp("", "synapse-ws-*")
	if err != nil {
		return nil, fmt.Errorf("create workspace: %w", err)
	}
	cleanup := func() error { return os.RemoveAll(dir) }

	low := strings.ToLower(value)
	switch {
	case strings.HasSuffix(low, ".zip"):
		err = extractZip(value, dir, maxBytes)
	case strings.HasSuffix(low, ".tar.gz"), strings.HasSuffix(low, ".tgz"):
		err = extractTarGz(value, dir, maxBytes)
	case strings.HasSuffix(low, ".tar"):
		err = extractTar(value, dir, maxBytes)
	default:
		err = fmt.Errorf("%w: unsupported archive type (want .zip, .tar.gz, .tgz, or .tar)", shared.ErrValidation)
	}
	if err != nil {
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

// safeJoin resolves an archive entry name against dest and rejects any path that would
// escape it (the zip-slip guard). Absolute paths and `..` traversal both fail.
func safeJoin(dest, name string) (string, error) {
	target := filepath.Join(dest, name)
	rel, err := filepath.Rel(dest, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: archive entry %q escapes the workspace (path traversal)", shared.ErrValidation, name)
	}
	return target, nil
}

// copyCapped writes r to target, failing if it exceeds max bytes (bomb guard). Returns
// the bytes written.
func copyCapped(target string, r io.Reader, max int64) (int64, error) {
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, fmt.Errorf("create file: %w", err)
	}
	defer func() { _ = out.Close() }()
	n, err := io.Copy(out, io.LimitReader(r, max+1))
	if err != nil {
		return n, fmt.Errorf("extract file: %w", err)
	}
	if n > max {
		return n, fmt.Errorf("%w: archive entry exceeds the %d-byte per-file cap", shared.ErrValidation, max)
	}
	return n, nil
}

func extractZip(src, dest string, maxBytes int64) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("%w: open zip: %v", shared.ErrValidation, err)
	}
	defer func() { _ = zr.Close() }()

	var total int64
	for i, f := range zr.File {
		if i+1 > maxArchiveEntries {
			return fmt.Errorf("%w: archive has too many entries (>%d)", shared.ErrValidation, maxArchiveEntries)
		}
		target, err := safeJoin(dest, f.Name)
		if err != nil {
			return err
		}
		info := f.FileInfo()
		switch {
		case info.IsDir():
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("mkdir: %w", err)
			}
		case info.Mode().IsRegular(): // skip symlinks + special files by omission
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("mkdir: %w", err)
			}
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("open entry: %w", err)
			}
			n, err := copyCapped(target, rc, maxArchiveFileBytes)
			_ = rc.Close()
			if err != nil {
				return err
			}
			total += n
			if total > maxBytes {
				return fmt.Errorf("%w: archive exceeds the %d-byte workspace cap", shared.ErrValidation, maxBytes)
			}
		}
	}
	return nil
}

func extractTarGz(src, dest string, maxBytes int64) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("%w: gzip: %v", shared.ErrValidation, err)
	}
	defer func() { _ = gz.Close() }()
	return extractTarStream(gz, dest, maxBytes)
}

func extractTar(src, dest string, maxBytes int64) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer func() { _ = f.Close() }()
	return extractTarStream(f, dest, maxBytes)
}

// extractTarStream extracts a tar stream with the same hardening as zip. Only directory
// + regular-file entries are written; symlink/hardlink/device entries are skipped.
func extractTarStream(r io.Reader, dest string, maxBytes int64) error {
	tr := tar.NewReader(r)
	var total int64
	entries := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: tar: %v", shared.ErrValidation, err)
		}
		entries++
		if entries > maxArchiveEntries {
			return fmt.Errorf("%w: archive has too many entries (>%d)", shared.ErrValidation, maxArchiveEntries)
		}
		target, err := safeJoin(dest, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("mkdir: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("mkdir: %w", err)
			}
			n, err := copyCapped(target, tr, maxArchiveFileBytes)
			if err != nil {
				return err
			}
			total += n
			if total > maxBytes {
				return fmt.Errorf("%w: archive exceeds the %d-byte workspace cap", shared.ErrValidation, maxBytes)
			}
		default:
			// Symlinks (TypeSymlink/TypeLink), devices, fifos: skipped – a link could
			// redirect a later read/write outside the workspace.
		}
	}
	return nil
}
