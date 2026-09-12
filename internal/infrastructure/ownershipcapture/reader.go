// Package ownershipcapture retains CODEOWNERS and validates application paths
// while an acquired workspace still exists. It never contacts an SCM service.
package ownershipcapture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const maxContent = 3_000_000

var selectionPaths = []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"}

type Reader struct{ git ports.ToolRunner }

func New(git ports.ToolRunner) *Reader { return &Reader{git: git} }

var _ ports.OwnershipSourceReader = (*Reader)(nil)

func (r *Reader) ReadOwnershipSource(ctx context.Context, request ports.AcquireRequest, ws *ports.Workspace) (out ports.OwnershipCapture, err error) {
	if ws == nil || ws.Dir == "" {
		return out, shared.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	switch {
	case request.Kind == ports.TargetGit && ownership.PinnedRevision("git:"+ws.Commit):
		out.Revision = "git:" + ws.Commit
	case request.Kind == ports.TargetUpload && request.SourcePackage != nil:
		out.Revision = "sha256:" + request.SourcePackage.SHA256
	default:
		out.Reason = "unpinned_source"
		return out, nil
	}
	if !ownership.PinnedRevision(out.Revision) {
		return out, shared.ErrValidation
	}
	var head ports.OwnershipFile
	if request.Kind == ports.TargetGit {
		if r.git == nil {
			return out, fmt.Errorf("%w: ownership git reader is not configured", shared.ErrValidation)
		}
		head, err = r.readGit(ctx, ws.Dir, ws.Commit)
	} else {
		head, err = readWorkspace(ctx, ws.Dir)
	}
	if err != nil {
		return out, err
	}
	if head.Path != "" {
		head.Revision = out.Revision
		out.Files = append(out.Files, head)
	}
	if request.BaseRef != "" || request.BaseCommit != "" {
		if !ownership.PinnedRevision("git:"+ws.BaseCommit) || r.git == nil {
			out.Reason = "missing_base_snapshot"
			return out, nil
		}
		out.BaseRevision = "git:" + ws.BaseCommit
		base, err := r.readGit(ctx, ws.Dir, ws.BaseCommit)
		if err != nil {
			return out, err
		}
		if base.Path != "" {
			base.Revision, base.Base = out.BaseRevision, true
			out.Files = append(out.Files, base)
		} else {
			out.Reason = "missing_base_snapshot"
		}
	}
	return out, nil
}

func openRegular(root *os.Root, path string) (*os.File, error) {
	// Root confines traversal even if a hostile symlink is swapped after Lstat.
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := range parts {
		entry, err := root.Lstat(strings.Join(parts[:i+1], "/"))
		if err != nil {
			return nil, err
		}
		if entry.Mode()&os.ModeSymlink != 0 || i < len(parts)-1 && !entry.IsDir() || i == len(parts)-1 && !entry.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: unsafe ownership source path", shared.ErrValidation)
		}
	}
	return root.Open(path)
}

func readWorkspace(ctx context.Context, directory string) (out ports.OwnershipFile, err error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return out, err
	}
	defer root.Close()
	for _, path := range selectionPaths {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		file, err := openRegular(root, path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return out, err
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxContent+1))
		_ = file.Close()
		if readErr != nil {
			return out, readErr
		}
		if len(data) > maxContent || !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
			return out, fmt.Errorf("%w: CODEOWNERS exceeds capture limit", shared.ErrValidation)
		}
		return ports.OwnershipFile{Path: path, Content: string(data)}, nil
	}
	return out, nil
}

func (r *Reader) gitRead(ctx context.Context, root string, limit int, args ...string) ([]byte, error) {
	// No credentials, shell, hooks, filters or network. The supplied runner is the
	// same sandbox/exec runner selected by the scan composition root.
	argv := append([]string{"-C", root, "--no-replace-objects", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "credential.helper="}, args...)
	result, err := r.git.Run(ctx, ports.ToolSpec{Name: "git", Args: argv, Workdir: root, Env: []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS="}, Timeout: 15 * time.Second, MaxOutputBytes: limit})
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 || result.TimedOut || result.Truncated || len(result.Stdout) > limit {
		return nil, fmt.Errorf("%w: bounded ownership git %s failed (exit %d, timeout %t, truncated %t)", shared.ErrValidation, args[0], result.ExitCode, result.TimedOut, result.Truncated)
	}
	return result.Stdout, nil
}

func (r *Reader) readGit(ctx context.Context, root, commit string) (out ports.OwnershipFile, err error) {
	for _, path := range selectionPaths {
		entry, err := r.gitRead(ctx, root, 4096, "ls-tree", "-z", commit, "--", path)
		if err != nil {
			return out, err
		}
		if len(entry) == 0 {
			continue
		}
		metadata, name, ok := strings.Cut(strings.TrimSuffix(string(entry), "\x00"), "\t")
		fields := strings.Fields(metadata)
		if !ok || name != path || len(fields) != 3 || fields[1] != "blob" || fields[0] != "100644" && fields[0] != "100755" || !ownership.PinnedRevision("git:"+fields[2]) {
			return out, fmt.Errorf("%w: CODEOWNERS must be a regular git blob", shared.ErrValidation)
		}
		sizeText, err := r.gitRead(ctx, root, 128, "cat-file", "-s", fields[2])
		if err != nil {
			return out, err
		}
		size, err := strconv.Atoi(strings.TrimSpace(string(sizeText)))
		if err != nil || size < 0 || size > maxContent {
			return out, fmt.Errorf("%w: CODEOWNERS exceeds capture limit", shared.ErrValidation)
		}
		data, err := r.gitRead(ctx, root, maxContent+1, "cat-file", "blob", fields[2])
		if err != nil {
			return out, err
		}
		if len(data) != size || !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
			return out, fmt.Errorf("%w: truncated CODEOWNERS blob", shared.ErrValidation)
		}
		return ports.OwnershipFile{Path: path, Content: string(data)}, nil
	}
	return out, nil
}

// OwnershipPath accepts only a real regular file within the scanned workspace.
// Third-party dependency directories never become application manifest evidence.
func (r *Reader) OwnershipPath(directory, raw string, manifest bool) (string, error) {
	if manifest && !applicationManifest(filepath.ToSlash(raw)) {
		return "", ports.ErrOwnershipNonManifest
	}
	rootPath, err := filepath.Abs(directory)
	if err != nil {
		return "", err
	}
	path := raw
	if filepath.IsAbs(path) {
		path, err = filepath.Rel(rootPath, path)
		if err != nil {
			return "", shared.ErrValidation
		}
	}
	path, err = ownership.NormalizePath(filepath.ToSlash(path))
	if err != nil {
		return "", err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return "", err
	}
	defer root.Close()
	file, err := openRegular(root, path)
	if err != nil {
		return "", err
	}
	_ = file.Close()
	return path, nil
}

func applicationManifest(path string) bool {
	for _, part := range strings.Split(strings.ToLower(path), "/") {
		switch part {
		case "node_modules", "vendor", ".git", ".venv", "venv", "site-packages", ".m2", ".gradle", ".cache":
			return false
		}
	}
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "go.mod", "go.sum", "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "cargo.toml", "cargo.lock", "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile", "gemfile", "gemfile.lock", "pyproject.toml", "poetry.lock", "pipfile", "pipfile.lock", "uv.lock", "composer.json", "composer.lock", "packages.lock.json", "packages.config":
		return true
	}
	return strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") || strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".fsproj")
}
