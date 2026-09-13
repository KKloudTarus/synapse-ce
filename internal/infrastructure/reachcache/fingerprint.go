// Package reachcache holds the infrastructure adapters for the reachability cache (EPIC #1042, 0.7): a
// filesystem source-tree fingerprinter that feeds the coordinator's verdict-complete cache key. The
// in-memory cache store itself lives with the coordinator (usecase); a persistent (postgres/file) store is
// the follow-on and implements the same reachproof.ReachabilityCache interface.
package reachcache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/sync/errgroup"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TreeFingerprinter implements ports.ReachabilitySourceFingerprinter by content-hashing every regular file
// under a target directory into a Merkle root. It is the source-tree half of the cache key: any file added,
// removed, renamed, re-permissioned, or edited changes the root, so a changed tree can never reuse a cached
// graph. It never fabricates a hash: whenever it cannot see all the source a verdict depends on, it returns
// an error, and the coordinator then disables the cache for that run (recompute) rather than serve a
// stale-key negative.
//
// It excludes VCS metadata (.git) because those bytes do not affect a reachability build, and excluding them
// avoids invalidating the cache on every commit. Everything else under the tree is hashed, including
// dependency manifests and lockfiles (go.mod/go.sum, package-lock.json, composer.lock, ...), so a changed
// dependency graph committed to the tree is already covered by the source hash.
//
// SOUNDNESS boundaries this adapter enforces so a stale-key negative is never served:
//   - The tree is resolved to its real path first, so a symlinked target ROOT is walked into (not hashed as
//     a bare link) and its content drift is seen.
//   - An in-tree symlink hashes its link string only when the file it points at is itself walked and hashed
//     (a covered path). A symlink whose target is OUTSIDE the tree, or under an excluded directory (so it is
//     never hashed), is an error: content behind it could change without changing the root.
//   - A non-regular file (FIFO, device, socket) is NEVER opened (that could block forever on a FIFO or
//     stream endlessly on a device); its identity (path + mode) is bound but no body is read.
//   - A Go module that pulls source from OUTSIDE the tree via a local `replace` directive or a `go.work`
//     `use`/`replace` is an error: the build reads bytes the fingerprint cannot see, so caching is unsafe.
//
// The environment half (envFingerprint) binds only this process's GOOS/GOARCH/toolchain. That is sound for
// the process-local in-memory cache (those are constant per process, and the cache is wiped on restart) but
// is NOT sufficient for a cross-process persistent cache: a persistent adapter must also fold the target's
// build toolchain, build tags/GOFLAGS, entrypoint policy, resolver config, and sandbox mode before it is safe
// to reuse a graph across restarts.
type TreeFingerprinter struct {
	excludeDirs map[string]bool
}

var _ ports.ReachabilitySourceFingerprinter = (*TreeFingerprinter)(nil)

// NewTreeFingerprinter returns a fingerprinter that skips VCS metadata directories (.git) and hashes the
// rest of the tree.
func NewTreeFingerprinter() *TreeFingerprinter {
	return &TreeFingerprinter{excludeDirs: map[string]bool{".git": true}}
}

// fileJob is one walked entry to hash. Collected single-threaded in the walk (lstat only), hashed in
// parallel afterwards; the root sort makes hashing order irrelevant.
type fileJob struct {
	rel  string
	path string
	mode os.FileMode
}

// FingerprintSource returns a Merkle root over the target tree (sourceHash) and a fingerprint of the
// process build environment (envFingerprint: GOOS, GOARCH, and the toolchain version). Both are hex sha256.
// Any condition under which the fingerprint would not see all verdict-affecting source returns an error,
// which disables the cache for the run.
func (f *TreeFingerprinter) FingerprintSource(ctx context.Context, targetRef string) (string, string, error) {
	if strings.TrimSpace(targetRef) == "" {
		return "", "", fmt.Errorf("reachcache: empty target ref")
	}
	// Resolve the root to a real absolute path so a symlinked target root is walked into (not hashed as a
	// bare link) and so out-of-tree checks compare real paths.
	absRef, err := filepath.Abs(targetRef)
	if err != nil {
		return "", "", fmt.Errorf("reachcache: abs target %q: %w", targetRef, err)
	}
	realRoot, err := filepath.EvalSymlinks(absRef)
	if err != nil {
		return "", "", fmt.Errorf("reachcache: resolve target %q: %w", targetRef, err)
	}
	info, err := os.Stat(realRoot)
	if err != nil {
		return "", "", fmt.Errorf("reachcache: stat target %q: %w", realRoot, err)
	}
	if !info.IsDir() {
		return "", "", fmt.Errorf("reachcache: target %q is not a directory", realRoot)
	}

	// Phase 1: walk (single-threaded) collecting jobs and any Go module/workspace files. Cheap: this reads
	// directory entries and lstat, no file bodies, so the expensive content hashing is deferred.
	var jobs []fileJob
	var goModPaths, goWorkPaths []string
	walkErr := filepath.WalkDir(realRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if d.IsDir() {
			if f.excludeDirs[d.Name()] && path != realRoot {
				return filepath.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(realRoot, path)
		if rerr != nil {
			return fmt.Errorf("reachcache: rel path for %q: %w", path, rerr)
		}
		fi, ierr := d.Info()
		if ierr != nil {
			return fmt.Errorf("reachcache: stat %q: %w", filepath.ToSlash(rel), ierr)
		}
		switch d.Name() { // collected regardless of lstat mode; checkExternalGoSource stat-follows and skips non-regular
		case "go.mod":
			goModPaths = append(goModPaths, path)
		case "go.work":
			goWorkPaths = append(goWorkPaths, path)
		}
		jobs = append(jobs, fileJob{rel: filepath.ToSlash(rel), path: path, mode: fi.Mode()})
		return nil
	})
	if walkErr != nil {
		return "", "", fmt.Errorf("reachcache: walk %q: %w", realRoot, walkErr)
	}

	// Fail closed if the Go build would read source outside the fingerprinted tree (a change there would not
	// change the root). Runs before the expensive hashing so it fails fast.
	if err := f.checkExternalGoSource(realRoot, goModPaths, goWorkPaths); err != nil {
		return "", "", err
	}

	// Phase 2: hash each file's identity + content in parallel, bounded to GOMAXPROCS.
	digests := make([][32]byte, len(jobs))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(runtime.GOMAXPROCS(0))
	for i := range jobs {
		i := i
		g.Go(func() error {
			if cerr := gctx.Err(); cerr != nil {
				return cerr
			}
			d, herr := f.hashFile(realRoot, jobs[i])
			if herr != nil {
				return herr
			}
			digests[i] = d
			return nil
		})
	}
	if werr := g.Wait(); werr != nil {
		return "", "", fmt.Errorf("reachcache: fingerprint %q: %w", realRoot, werr)
	}

	slices.SortFunc(digests, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	root := sha256.New()
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(digests)))
	root.Write(count[:]) // bind the file count so an empty tree differs from a single empty file
	for i := range digests {
		root.Write(digests[i][:])
	}
	sourceHash := hex.EncodeToString(root.Sum(nil))

	env := sha256.New()
	env.Write([]byte("reachcache-env-v1\x00"))
	env.Write([]byte(runtime.GOOS))
	env.Write([]byte{0})
	env.Write([]byte(runtime.GOARCH))
	env.Write([]byte{0})
	env.Write([]byte(runtime.Version()))
	env.Write([]byte{0})
	// Fold the ambient Go build knobs that can change source selection. In production the call-graph builder
	// runs sandboxed with a clean env (these do not pass through), so they are empty; on the unsandboxed dev
	// path they are inherited, and folding their VALUES misses the cache when they change across scans.
	env.Write([]byte(os.Getenv("GOFLAGS")))
	env.Write([]byte{0})
	env.Write([]byte(os.Getenv("GOWORK")))
	env.Write([]byte{0})
	env.Write([]byte(os.Getenv("GO111MODULE")))
	envFingerprint := hex.EncodeToString(env.Sum(nil))

	return sourceHash, envFingerprint, nil
}

// hashFile computes sha256(rel \0 mode \0 body) for one entry. rel and the decimal mode contain no NUL on a
// POSIX filesystem, so the two delimiters are unambiguous. A symlink hashes its link string only when its
// target is a covered in-tree path (walked and hashed separately); an out-of-tree or excluded-path target is
// an error. A non-regular file (FIFO/device/socket) is never opened; only its identity is bound.
func (f *TreeFingerprinter) hashFile(realRoot string, j fileJob) ([32]byte, error) {
	var zero [32]byte
	h := sha256.New()
	h.Write([]byte(j.rel))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatUint(uint64(j.mode), 10)))
	h.Write([]byte{0})
	switch {
	case j.mode&os.ModeSymlink != 0:
		target, lerr := os.Readlink(j.path)
		if lerr != nil {
			return zero, fmt.Errorf("readlink %q: %w", j.rel, lerr)
		}
		covered, werr := f.symlinkTargetCovered(realRoot, j.path, target)
		if werr != nil {
			return zero, fmt.Errorf("resolve symlink %q: %w", j.rel, werr)
		}
		if !covered {
			// The target's content is not hashed anywhere (outside the tree, or under an excluded dir), so it
			// could change without changing the root, which would let a stale not_reachable be served. Fail so
			// the coordinator recomputes.
			return zero, fmt.Errorf("uncovered symlink %q -> %q (cache disabled for a sound verdict)", j.rel, target)
		}
		h.Write([]byte(target))
	case j.mode.IsRegular():
		file, oerr := os.Open(j.path)
		if oerr != nil {
			return zero, fmt.Errorf("open %q: %w", j.rel, oerr)
		}
		if _, cerr := io.Copy(h, file); cerr != nil {
			file.Close()
			return zero, fmt.Errorf("read %q: %w", j.rel, cerr)
		}
		file.Close()
	default:
		// Non-regular, non-symlink (FIFO, device, socket): identity only, never opened.
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// symlinkTargetCovered reports whether a symlink's target content is already hashed by the walk: it must
// resolve to a real path INSIDE realRoot and NOT under an excluded directory (which the walk skips). A
// relative target is resolved against the link's directory. A broken/dangling target is covered (there is no
// readable content behind it, so hashing the link string is sound). Anything else is not covered, and the
// caller turns that into an error.
func (f *TreeFingerprinter) symlinkTargetCovered(realRoot, linkPath, target string) (bool, error) {
	abs := target
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(filepath.Dir(linkPath), target)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return true, nil // broken/dangling: no reachable content behind it
	}
	return f.withinCoveredTree(realRoot, resolved), nil
}

// withinCoveredTree reports whether an already-resolved real path is inside realRoot AND not under any
// excluded directory, so the walk actually hashes its content. A path outside the tree, or one under an
// excluded dir (e.g. .git, which the walk skips), is NOT covered: its content can change without changing
// the root. Both the symlink check and the Go external-source check gate on this so neither can admit
// verdict-affecting bytes the fingerprint never sees.
func (f *TreeFingerprinter) withinCoveredTree(realRoot, resolved string) bool {
	rel, err := filepath.Rel(realRoot, resolved)
	if err != nil {
		return false // different volumes / not relatable: treat as out-of-tree
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false // outside the tree
	}
	for _, seg := range strings.Split(filepath.ToSlash(rel), "/") {
		if f.excludeDirs[seg] {
			return false // under an excluded dir, so its content is never hashed
		}
	}
	return true
}

// checkExternalGoSource returns an error when a Go module or workspace pulls source from OUTSIDE realRoot via
// a local filesystem `replace` directive or a `go.work` `use`/`replace`. The call-graph build reads that
// external source, so a change there would not change the tree hash: caching must be disabled (fail closed).
// A go.mod/go.work it cannot read or parse is also treated as an error, since it cannot rule out an external
// reference. Internal replaces (targets inside realRoot) are fine: their content is already hashed.
func (f *TreeFingerprinter) checkExternalGoSource(realRoot string, goModPaths, goWorkPaths []string) error {
	if err := f.checkAmbientGoEnv(realRoot); err != nil {
		return err
	}
	for _, gm := range goModPaths {
		if fi, err := os.Stat(gm); err != nil || !fi.Mode().IsRegular() {
			continue // a FIFO/device/dangling manifest is not read (would block); its bytes are handled by hashFile
		}
		data, err := os.ReadFile(gm)
		if err != nil {
			return fmt.Errorf("reachcache: read %q: %w", gm, err)
		}
		mf, err := modfile.Parse(gm, data, nil)
		if err != nil {
			return fmt.Errorf("reachcache: parse %q (cache disabled): %w", gm, err)
		}
		for _, r := range mf.Replace {
			if r.New.Version != "" { // a versioned module replace, not a local filesystem path
				continue
			}
			if f.targetNotCovered(realRoot, filepath.Dir(gm), r.New.Path) {
				return fmt.Errorf("reachcache: go.mod %q replaces %q with out-of-tree %q (cache disabled)", gm, r.Old.Path, r.New.Path)
			}
		}
	}
	for _, gw := range goWorkPaths {
		if err := f.checkWorkspaceExternal(realRoot, gw); err != nil {
			return err
		}
	}
	return nil
}

// targetNotCovered reports whether a local path target's content is NOT covered by the walk. Both the
// UNRESOLVED literal path and the fully RESOLVED path must be in-tree and clear of an excluded dir: the
// literal check catches a target that traverses .git (whose contents, including any symlink, the walk never
// hashes), and the resolved check catches a link that lands outside the tree. Unresolvable -> not covered.
func (f *TreeFingerprinter) targetNotCovered(realRoot, baseDir, p string) bool {
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(baseDir, p)
	}
	if !f.withinCoveredTree(realRoot, filepath.Clean(abs)) {
		return true // literal path escapes the tree or traverses an excluded dir
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return true // an unresolvable local target: cannot verify it is covered -> fail closed
	}
	return !f.withinCoveredTree(realRoot, resolved)
}

// checkWorkspaceExternal parses one go.work (skipping a non-regular file, which is not read) and errors when
// any use/replace resolves to source outside the covered tree. It is shared by the in-tree go.work walk and
// the explicit-GOWORK check so both apply the same coverage rule.
func (f *TreeFingerprinter) checkWorkspaceExternal(realRoot, gw string) error {
	if fi, err := os.Stat(gw); err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	data, err := os.ReadFile(gw)
	if err != nil {
		return fmt.Errorf("reachcache: read %q: %w", gw, err)
	}
	wf, err := modfile.ParseWork(gw, data, nil)
	if err != nil {
		return fmt.Errorf("reachcache: parse %q (cache disabled): %w", gw, err)
	}
	for _, u := range wf.Use {
		if f.targetNotCovered(realRoot, filepath.Dir(gw), u.Path) {
			return fmt.Errorf("reachcache: go.work %q uses out-of-tree module %q (cache disabled)", gw, u.Path)
		}
	}
	for _, r := range wf.Replace {
		if r.New.Version != "" {
			continue
		}
		if f.targetNotCovered(realRoot, filepath.Dir(gw), r.New.Path) {
			return fmt.Errorf("reachcache: go.work %q replaces %q with out-of-tree %q (cache disabled)", gw, r.Old.Path, r.New.Path)
		}
	}
	return nil
}

// checkAmbientGoEnv fails closed when an ambient Go build knob can redirect the build to source the walk does
// not hash. In production the builder runs sandboxed with a clean env, so these are empty and this is a no-op;
// on the unsandboxed dev path (where the go command inherits this process's env) it closes the holes:
//   - GO111MODULE=off drops to GOPATH mode, resolving imports from GOPATH/src outside the tree.
//   - GOWORK set to an explicit path outside the tree, or GOWORK=auto/empty with a go.work in an ANCESTOR of
//     the tree (Go discovers it by searching upward), activates an out-of-tree workspace.
//   - GOFLAGS -overlay / -modfile (either single- or double-dash; Go normalizes both) remaps or replaces
//     source paths to files the fingerprint never sees.
func (f *TreeFingerprinter) checkAmbientGoEnv(realRoot string) error {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("GO111MODULE")), "off") {
		return fmt.Errorf("reachcache: GO111MODULE=off resolves source from GOPATH outside the tree (cache disabled)")
	}
	gw := strings.TrimSpace(os.Getenv("GOWORK"))
	switch {
	case strings.EqualFold(gw, "off"):
		// no workspace: fine
	case gw == "" || strings.EqualFold(gw, "auto"):
		if anc := ancestorGoWork(realRoot); anc != "" {
			return fmt.Errorf("reachcache: a go.work above the tree (%q) would be auto-discovered (cache disabled)", anc)
		}
	default:
		// An explicit workspace file. Its literal path AND its resolved path must be in-tree (so retargeting an
		// out-of-tree GOWORK symlink cannot slip through), and its own use/replace directives must stay in-tree.
		resolved, err := filepath.EvalSymlinks(gw)
		if err != nil || !f.withinCoveredTree(realRoot, filepath.Clean(gw)) || !f.withinCoveredTree(realRoot, resolved) {
			return fmt.Errorf("reachcache: GOWORK %q is not a covered in-tree workspace (cache disabled)", gw)
		}
		if werr := f.checkWorkspaceExternal(realRoot, resolved); werr != nil {
			return werr
		}
	}
	for _, tok := range strings.Fields(os.Getenv("GOFLAGS")) {
		norm := strings.TrimLeft(tok, "-") // Go treats -flag and --flag alike
		if strings.HasPrefix(norm, "overlay") || strings.HasPrefix(norm, "modfile") {
			return fmt.Errorf("reachcache: GOFLAGS %q remaps source (cache disabled)", tok)
		}
	}
	return nil
}

// ancestorGoWork returns the path of a go.work found in a STRICT ancestor of realRoot (Go's auto workspace
// search walks upward from the module dir), or "" if none. It stops at the filesystem root. A go.work inside
// realRoot is walked and hashed, so it is not an ancestor concern.
func ancestorGoWork(realRoot string) string {
	dir := filepath.Dir(realRoot)
	for {
		if dir == realRoot { // filepath.Dir is idempotent at the root
			return ""
		}
		candidate := filepath.Join(dir, "go.work")
		if fi, err := os.Stat(candidate); err == nil && fi.Mode().IsRegular() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}
