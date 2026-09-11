// Package dotnetreach implements build-aware .NET (NuGet) reachability: it maps a resolved NuGet package to
// the assemblies it actually ships (via project.assets.json and the package cache) and to the namespaces
// those assemblies export (via a PE/ECMA-335 metadata reader), so reachability is decided against a
// package's REAL namespaces rather than a guess from its ID. It never mints a negative conclusion on
// incomplete data: any unresolved assembly, missing cache path, or malformed input degrades coverage, and
// the caller fails closed to "unknown".
package dotnetreach

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// maxAssetsBytes bounds the project.assets.json we will parse (a hostile or generated file can be enormous).
const maxAssetsBytes = 64 << 20

// PackageAssemblies is a resolved NuGet package and the on-disk assemblies it ships across every target
// framework in the restore graph. Complete is false when any of its compile/runtime assemblies could not be
// resolved to a readable file in the package cache, so the caller must fail closed (never conclude a package
// with incomplete assembly coverage is unreachable).
type PackageAssemblies struct {
	Name     string   // canonical package id, as the assets file spells it
	Version  string   // resolved version
	Paths    []string // absolute .dll paths (compile + runtime, deduped, sorted); placeholders excluded
	Complete bool
}

// assetsFile is the subset of project.assets.json build-aware reachability needs: the per-framework resolved
// packages with their compile/runtime assembly relative paths, the libraries table (each package's cache
// sub-path and file list), and the package-folder cache roots.
type assetsFile struct {
	Version        int                                `json:"version"`
	Targets        map[string]map[string]assetsTarget `json:"targets"`
	Libraries      map[string]assetsLibrary           `json:"libraries"`
	PackageFolders map[string]json.RawMessage         `json:"packageFolders"`
}

type assetsTarget struct {
	Type           string                     `json:"type"` // package | project | ...
	Compile        map[string]json.RawMessage `json:"compile"`
	Runtime        map[string]json.RawMessage `json:"runtime"`
	RuntimeTargets map[string]json.RawMessage `json:"runtimeTargets"` // RID-specific managed assemblies
}

type assetsLibrary struct {
	Type  string   `json:"type"`  // package | project
	Path  string   `json:"path"`  // cache sub-path, e.g. "serilog/3.1.1"
	Files []string `json:"files"` // relative files the package ships
}

// ResolveAssembliesFromAssets parses project.assets.json and resolves every resolved NuGet package to the
// absolute assembly paths it ships. cacheFallbacks are additional package-cache roots (NUGET_PACKAGES, the
// default ~/.nuget/packages) tried when the file's own packageFolders do not resolve a path; a package whose
// assemblies cannot all be resolved to a readable file under a cache root is marked Complete=false. It
// returns the packages keyed by lowercased id, the coverage reasons that degrade the observation, and an
// error only when the input itself is unusable.
func ResolveAssembliesFromAssets(content []byte, cacheFallbacks ...string) (map[string]PackageAssemblies, []string, error) {
	if len(content) == 0 {
		return nil, nil, fmt.Errorf("%w: empty project.assets.json", shared.ErrValidation)
	}
	if len(content) > maxAssetsBytes {
		return nil, nil, fmt.Errorf("%w: project.assets.json exceeds %d bytes", shared.ErrValidation, maxAssetsBytes)
	}
	var assets assetsFile
	if err := json.Unmarshal(content, &assets); err != nil {
		return nil, nil, fmt.Errorf("parse project.assets.json: %w", err)
	}

	roots := cacheRoots(assets.PackageFolders, cacheFallbacks)
	if len(roots) == 0 {
		// With no cache root, no assembly can be resolved, so nothing can be concluded unreachable.
		return map[string]PackageAssemblies{}, []string{"no NuGet package-folder cache root is known, so package assemblies cannot be located"}, nil
	}

	// Collect, per package key "Name/Version", the union of compile+runtime relative assembly paths across
	// every target framework. Unioning across frameworks is conservative: more assemblies means more
	// namespaces observed, which only reduces the chance of a (false) unreachable conclusion.
	rel := map[string]map[string]bool{} // "Name/Version" -> set of relative assembly paths
	order := []string{}
	for _, packages := range assets.Targets {
		for key, entry := range packages {
			if !strings.EqualFold(entry.Type, "package") {
				continue // project references and framework entries ship no NuGet assembly
			}
			if _, seen := rel[key]; !seen {
				rel[key] = map[string]bool{}
				order = append(order, key)
			}
			for _, group := range []map[string]json.RawMessage{entry.Compile, entry.Runtime, entry.RuntimeTargets} {
				for path := range group {
					if isRealAssembly(path) {
						rel[key][path] = true
					}
				}
			}
		}
	}

	out := map[string]PackageAssemblies{}
	var reasons []string
	sort.Strings(order)
	for _, key := range order {
		name, version, ok := splitAssetKey(key)
		if !ok {
			reasons = append(reasons, "a project.assets.json target key is malformed ("+key+")")
			continue
		}
		pa := PackageAssemblies{Name: name, Version: version, Complete: true}
		lib, hasLib := assets.Libraries[key]
		if !hasLib || strings.TrimSpace(lib.Path) == "" {
			// Without the library entry we cannot find the package folder, so its coverage is incomplete.
			pa.Complete = false
			reasons = append(reasons, "project.assets.json has no library path for "+key)
			mergePackage(out, name, pa)
			continue
		}
		paths := map[string]bool{}
		for relPath := range rel[key] {
			abs, ok := resolveInCache(roots, lib.Path, relPath)
			if !ok {
				pa.Complete = false
				reasons = append(reasons, "an assembly of "+key+" could not be located in the package cache ("+relPath+")")
				continue
			}
			paths[abs] = true
		}
		pa.Paths = sortedKeys(paths)
		mergePackage(out, name, pa)
	}
	return out, reasons, nil
}

// mergePackage records pa under its lowercased id, unioning assemblies when the same id resolved at more
// than one version (a multi-target restore can), so a version-specific assembly set is never silently
// dropped; Complete is the AND of every contributing version.
func mergePackage(out map[string]PackageAssemblies, name string, pa PackageAssemblies) {
	id := strings.ToLower(name)
	prev, ok := out[id]
	if !ok {
		out[id] = pa
		return
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
	out[id] = prev
}

// cacheRoots returns the package-cache roots to search, the file's own packageFolders first (they are the
// authoritative restore roots) then any fallbacks, cleaned and deduped in order.
func cacheRoots(folders map[string]json.RawMessage, fallbacks []string) []string {
	seen := map[string]bool{}
	var roots []string
	add := func(r string) {
		r = strings.TrimSpace(r)
		if r == "" {
			return
		}
		clean := filepath.Clean(r)
		if !seen[clean] {
			seen[clean] = true
			roots = append(roots, clean)
		}
	}
	for folder := range folders {
		add(folder)
	}
	sort.Strings(roots) // deterministic order among packageFolders (usually one)
	for _, f := range fallbacks {
		add(f)
	}
	return roots
}

// resolveInCache joins a cache root, a library cache sub-path, and a relative assembly path into an absolute
// path, and returns it only when it stays within the root and names a readable regular file. The containment
// check defends against a hostile assets.json using "../" in a library path or file entry to escape the cache.
func resolveInCache(roots []string, libPath, relPath string) (string, bool) {
	libPath = filepath.FromSlash(strings.TrimSpace(libPath))
	relPath = filepath.FromSlash(strings.TrimSpace(relPath))
	if libPath == "" || relPath == "" {
		return "", false
	}
	for _, root := range roots {
		candidate := filepath.Clean(filepath.Join(root, libPath, relPath))
		if !withinRoot(root, candidate) {
			continue // lexical rejection of "../" escapes before touching the filesystem
		}
		info, err := os.Lstat(candidate)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		// Defend against an intermediate parent symlink escaping the cache: resolve every symlink and
		// re-check containment against the resolved root before accepting the path.
		realPath, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		realRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			realRoot = root
		}
		if withinRoot(realRoot, realPath) {
			return realPath, true
		}
	}
	return "", false
}

// withinRoot reports whether path is root or lies beneath it, comparing cleaned paths so "cache/../etc" can
// never masquerade as being under "cache".
func withinRoot(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	if path == root {
		return true
	}
	return strings.HasPrefix(path, root+string(filepath.Separator))
}

// isRealAssembly reports whether a compile/runtime entry names a shipped assembly rather than the "_._"
// placeholder (which marks a framework that ships no assembly for a metapackage).
func isRealAssembly(path string) bool {
	base := path
	if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
		base = base[i+1:]
	}
	if base == "_._" {
		return false
	}
	lower := strings.ToLower(base)
	return strings.HasSuffix(lower, ".dll") || strings.HasSuffix(lower, ".exe")
}

// splitAssetKey splits a "Name/Version" target/library key into its parts. The version is the segment after
// the LAST slash, because a package id never contains a slash but the key is a single Cut in the SDK.
func splitAssetKey(key string) (name, version string, ok bool) {
	i := strings.LastIndex(key, "/")
	if i <= 0 || i == len(key)-1 {
		return "", "", false
	}
	return key[:i], key[i+1:], true
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
