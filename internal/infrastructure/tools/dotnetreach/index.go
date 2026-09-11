package dotnetreach

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxAssetsFiles  = 4096   // project.assets.json files under one target (a large solution)
	maxWalkEntries  = 500000 // directory entries the assets-file walk visits before stopping
	maxAssembliesLU = 4096   // assemblies read across all requested packages in one Load
)

// Loader reads build-aware NuGet reachability data for a scanned directory: it maps the requested packages
// to the real namespaces their restored assemblies export. It reads bytes only and runs nothing.
type Loader struct{}

var _ ports.NuGetReachabilityData = Loader{}

// LoadReachabilityData walks dir for project.assets.json restore graphs, resolves the requested packages
// (lowercased ids) to their on-disk assemblies, and reads the namespaces those assemblies export. present is
// false when NO restore graph is found, so build-aware reachability is impossible and the caller must fail
// closed (never conclude a package unreachable from source alone). A package absent from the result map is
// unknown (not in the restore graph); one present with Complete=false has an incompletely known namespace
// set. It returns an error only when the target itself is unusable.
func (Loader) LoadReachabilityData(ctx context.Context, dir string, packages []string) (map[string]ports.NuGetPackageNamespaces, bool, error) {
	if ctx == nil {
		return nil, false, shared.ErrValidation
	}
	assetsBlobs, assetsComplete, err := readAssetsFiles(ctx, dir)
	if err != nil {
		return nil, false, err
	}
	if len(assetsBlobs) == 0 {
		return map[string]ports.NuGetPackageNamespaces{}, false, nil // no restore graph: fail closed upstream
	}

	fallbacks := cacheFallbackRoots()
	// Merge the package->assemblies map across every project's restore graph (union of assemblies; a package
	// is Complete only if every graph that names it resolved all of its assemblies). A restore graph that
	// could not be parsed degrades coverage for the WHOLE scan: it might have named a package (or a different
	// version of one) that another graph resolves cleanly, so trusting the survivor could hide namespaces.
	merged := map[string]PackageAssemblies{}
	for _, blob := range assetsBlobs {
		resolved, _, err := ResolveAssembliesFromAssets(blob, fallbacks...)
		if err != nil {
			assetsComplete = false
			continue // a malformed assets file contributes nothing; a package it would have named stays unknown
		}
		for id, pa := range resolved {
			prev, ok := merged[id]
			if !ok {
				merged[id] = pa
				continue
			}
			paths := map[string]bool{}
			for _, p := range prev.Paths {
				paths[p] = true
			}
			for _, p := range pa.Paths {
				paths[p] = true
			}
			prev.Paths = sortedKeys(paths)
			prev.Complete = prev.Complete && pa.Complete
			merged[id] = prev
		}
	}

	out := map[string]ports.NuGetPackageNamespaces{}
	assembliesRead := 0
	for _, pkg := range packages {
		id := strings.ToLower(strings.TrimSpace(pkg))
		if id == "" {
			continue
		}
		if _, done := out[id]; done {
			continue
		}
		pa, ok := merged[id]
		if !ok {
			continue // unknown: not in any restore graph
		}
		// A degraded assets walk means a graph we could not read might carry more of this package's
		// namespaces, so its set cannot be treated as complete.
		pn := ports.NuGetPackageNamespaces{Complete: pa.Complete && assetsComplete}
		set := map[string]bool{}
		for _, path := range pa.Paths {
			if assembliesRead >= maxAssembliesLU {
				pn.Complete = false
				break
			}
			assembliesRead++
			names, complete, err := readAssemblyNamespaces(path)
			if err != nil || !complete {
				pn.Complete = false // fail closed: an unreadable or forwarder-bearing assembly hides namespaces
			}
			for _, ns := range names {
				set[ns] = true
			}
		}
		pn.Namespaces = sortedKeys(set)
		out[id] = pn
	}
	return out, true, nil
}

// readAssemblyNamespaces reads one assembly file (bounded) and returns its exported namespaces.
func readAssemblyNamespaces(path string) ([]string, bool, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxAssemblyBytes {
		return nil, false, os.ErrInvalid
	}
	data, err := os.ReadFile(path) //nolint:gosec // path validated within the package cache root by resolveInCache
	if err != nil {
		return nil, false, err
	}
	return ExportedNamespaces(data)
}

// readAssetsFiles walks dir (confined) collecting the bytes of every project.assets.json under it, bounded.
// complete is false when the walk could not read every restore graph (a budget was exhausted, the walk was
// cancelled, or a project.assets.json was unreadable or oversized), so the caller degrades coverage rather
// than trust a possibly-partial set of graphs.
func readAssetsFiles(ctx context.Context, dir string) (blobs [][]byte, complete bool, err error) {
	trimmed := strings.TrimSpace(dir)
	if trimmed == "" {
		return nil, false, shared.ErrValidation
	}
	rootDir, err := os.OpenRoot(trimmed)
	if err != nil {
		return nil, true, nil // an unopenable target simply yields no restore graph (nothing to miss)
	}
	defer func() { _ = rootDir.Close() }()

	complete = true
	entries := 0
	_ = fs.WalkDir(rootDir.FS(), ".", func(p string, d fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			complete = false
			return fs.SkipAll
		}
		if walkErr != nil {
			complete = false // a directory we could not read might hold a restore graph
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		entries++
		if entries > maxWalkEntries || len(blobs) >= maxAssetsFiles {
			complete = false
			return fs.SkipAll
		}
		if d.IsDir() {
			if name := d.Name(); p != "." && (name == ".git" || name == "node_modules" || name == "bin") {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 || d.Name() != "project.assets.json" {
			return nil
		}
		content, ok := readThroughRoot(rootDir, p, maxAssetsBytes)
		if !ok {
			complete = false // an unreadable or oversized restore graph we cannot account for
			return nil
		}
		blobs = append(blobs, content)
		return nil
	})
	return blobs, complete, nil
}

// readThroughRoot reads a file through a confined root handle, bounded by maxBytes.
func readThroughRoot(rootDir *os.Root, rel string, maxBytes int64) ([]byte, bool) {
	f, err := rootDir.Open(rel)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBytes {
		return nil, false
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, false
	}
	return data, true
}

// cacheFallbackRoots returns the package-cache roots to try when a restore graph's own packageFolders do not
// resolve a path: NUGET_PACKAGES then the default ~/.nuget/packages.
func cacheFallbackRoots() []string {
	var roots []string
	if env := strings.TrimSpace(os.Getenv("NUGET_PACKAGES")); env != "" {
		roots = append(roots, env)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		roots = append(roots, filepath.Join(home, ".nuget", "packages"))
	}
	return roots
}
