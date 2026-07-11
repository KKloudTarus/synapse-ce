// Package ownsbom is Synapse's OWNED SBOM producer: a per-ecosystem parser registry
// that reads dependency manifests/lockfiles directly and emits a normalized sbom.SBOM, WITHOUT shelling
// out to a third-party scanner. It is the detection-independence path – an alternative implementation of
// the ports.SBOMGenerator producer port, swappable with the Syft adapter behind the same port
// (the moat: "not dependent on any one scanner"). Each ecosystem is owned by an EcosystemParser; the
// Registry walks the target tree, dispatches each recognized manifest to its parser, and merges the
// fragments. Vendor-neutral by construction – it imports no scanner library, only domain types.
package ownsbom

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	// ownsbomVersion identifies this producer in SBOM provenance. Bump when parser behavior changes.
	ownsbomVersion = "ownsbom/0.3.0"
	// maxManifestBytes caps a single manifest read so a hostile/corrupt repo cannot OOM the scan with an
	// absurd file. Real manifests are KB–low-MB; exceeding this is malicious or wrong, so it fails loud.
	maxManifestBytes = 64 << 20
	// maxManifests bounds the total manifests parsed in one scan, so a repo with a pathological NUMBER of
	// manifests (millions of tiny go.mod) fails loud rather than accumulating unbounded memory/time.
	maxManifests = 50_000
)

// ParseInput is everything an EcosystemParser needs to parse one matched manifest: its full path +
// content, plus the containing directory so a parser can read a COMPANION lockfile – many ecosystems
// pin versions in a lockfile separate from the dependency-declaring manifest (poetry.lock beside
// pyproject.toml, package-lock.json beside package.json, the pom.xml parent/BOM chain). Carried as a
// struct so the contract can grow fields without breaking the parsers that implement it.
type ParseInput struct {
	Dir     string // directory containing the manifest (for a parser's companion-file reads)
	Path    string // full path of the matched manifest (scope/glob decisions + Component.Location)
	Content []byte // the matched manifest's bytes
}

// EcosystemParser owns one package ecosystem: it claims a set of manifest filenames (markers) and parses
// one (with its directory context) into normalized SBOM fragments (components + dependency edges).
// Implementations are PURE w.r.t. the registry's contract and return domain types only, so a vendor
// parser type never crosses this boundary; a parser that reads a companion file does its own bounded I/O.
type EcosystemParser interface {
	Ecosystem() string // "go", "npm",...
	Markers() []string // manifest basenames it parses, e.g. "go.mod" (matched case-insensitively)
	Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error)
}

// Registry is an owned SBOM producer: it dispatches each recognized manifest to its EcosystemParser and
// merges the result into one normalized sbom.SBOM. It satisfies ports.SBOMGenerator.
type Registry struct {
	byMarker map[string]EcosystemParser // lower-cased manifest basename -> parser
	ecos     []string                   // distinct ecosystems present, sorted
}

var _ ports.SBOMGenerator = (*Registry)(nil)

// New builds a registry from the given parsers. Two parsers claiming the same marker is a configuration
// error (ambiguous dispatch), not a silent last-wins. Markers are matched case-insensitively (a Gemfile
// vs gemfile, and case-insensitive filesystems), matching the existing manifest enricher's convention.
func New(parsers ...EcosystemParser) (*Registry, error) {
	r := &Registry{byMarker: make(map[string]EcosystemParser)}
	ecoset := map[string]bool{}
	for _, p := range parsers {
		if p == nil {
			return nil, fmt.Errorf("%w: nil ecosystem parser", shared.ErrValidation)
		}
		for _, m := range p.Markers() {
			lm := strings.ToLower(m)
			if _, dup := r.byMarker[lm]; dup {
				return nil, fmt.Errorf("%w: two parsers claim marker %q", shared.ErrValidation, lm)
			}
			r.byMarker[lm] = p
		}
		if !ecoset[p.Ecosystem()] {
			ecoset[p.Ecosystem()] = true
			r.ecos = append(r.ecos, p.Ecosystem())
		}
	}
	sort.Strings(r.ecos)
	return r, nil
}

// DefaultRegistry assembles the owned parsers into the detection-independent SBOM producer, covering Go,
// JS (npm/yarn/pnpm), Python (PyPI/Poetry/Pipfile/Conda), Rust, Java (Maven + Gradle), Ruby, PHP,.NET,
// Swift, Dart, Elixir, R (renv), Julia, and Conan. The parsers claim distinct markers, so New does not
// error here in practice.
func DefaultRegistry() (*Registry, error) {
	return New(GoMod{}, NPM{}, Yarn{}, Pnpm{}, PyPI{}, Poetry{}, Pipfile{}, Cargo{}, Maven{}, Gradle{}, Gem{}, Composer{}, NuGet{}, Swift{}, Dart{}, Elixir{}, Conda{}, Renv{}, Julia{}, Conan{})
}

// Generate walks the target directory, parses every recognized manifest with its EcosystemParser, and
// merges the fragments into a normalized SBOM. Manifests are matched by basename (case-insensitive);
// unknown files and dependency-cache/VCS directories (node_modules, vendor,.git, …) are skipped. A
// manifest that fails to parse fails the whole scan with its path (fail-loud – a silently-dropped
// manifest is undercounted risk). Components are de-duplicated by identity (PURL, else name@version);
// edges are concatenated. Hardened against a hostile tree: non-regular files are skipped (no symlink
// escape), each manifest is size-capped, and the total manifest count is bounded.
func (r *Registry) Generate(ctx context.Context, targetRef string) (*sbom.SBOM, error) {
	info, err := os.Stat(targetRef)
	if err != nil {
		return nil, fmt.Errorf("stat target: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: ownsbom target must be a directory, got %q", shared.ErrValidation, targetRef)
	}
	var comps []sbom.Component
	var deps []sbom.Dependency
	seen := map[string]bool{}
	manifests := 0
	walkErr := filepath.WalkDir(targetRef, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if path != targetRef && skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // cheap pre-filter from the cached dir entry (symlink/device/etc.)
		}
		parser, ok := r.byMarker[strings.ToLower(d.Name())]
		if !ok {
			return nil
		}
		// Re-stat via Lstat right before the read (parity with the SAST adapter): narrows the TOCTOU
		// window where a regular manifest is swapped for a symlink after WalkDir cached its type, and
		// yields the authoritative size for the cap – never follow a symlinked manifest out of the tree.
		fi, lerr := os.Lstat(path)
		if lerr != nil {
			return fmt.Errorf("lstat %s: %w", path, lerr)
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		if fi.Size() > maxManifestBytes {
			return fmt.Errorf("%w: manifest %s is %d bytes (> %d cap)", shared.ErrValidation, path, fi.Size(), maxManifestBytes)
		}
		if manifests++; manifests > maxManifests {
			return fmt.Errorf("%w: target exceeds %d manifests; refusing to scan", shared.ErrValidation, maxManifests)
		}
		content, rerr := os.ReadFile(path) // #nosec G304 -- WalkDir entry under the target root, re-verified regular (non-symlink) via Lstat immediately above
		if rerr != nil {
			return fmt.Errorf("read %s: %w", path, rerr)
		}
		pcomps, pdeps, perr := parser.Parse(ctx, ParseInput{Dir: filepath.Dir(path), Path: path, Content: content})
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		for _, c := range pcomps {
			id := sbom.ComponentID(c.Name, c.Version, c.PURL)
			if seen[id] {
				continue
			}
			seen[id] = true
			c.Supplier, c.SupplierSource = sbom.SupplierWithSource(c.Supplier, c.PURL) // lockfiles carry no supplier; derive from the PURL namespace
			comps = append(comps, c)
		}
		deps = append(deps, pdeps...)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return &sbom.SBOM{
		TargetRef:        targetRef,
		Source:           "ownsbom",
		GeneratorVersion: ownsbomVersion,
		Components:       comps,
		Dependencies:     deps,
	}, nil
}

// skipDir prunes dependency-cache + VCS directories so the registry parses only top-level manifests, not
// a vendored copy's nested manifests (which would double-count or mis-scope).
func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", ".idea", ".vscode", ".hg", ".svn":
		return true
	}
	return false
}

// readManifestFile safely reads a COMPANION manifest beside a matched lockfile (e.g. Cargo.toml next to
// Cargo.lock): it must be a regular file (Lstat – never follow a symlink out of the tree) under the size
// cap. ok=false on any miss (missing, irregular, oversized) – a companion read is best-effort, never
// fatal. Parsers whose scope/version data lives in a sibling file use this rather than a raw os.ReadFile,
// so the registry's file-safety posture (no symlink escape, bounded size) extends to companion reads.
//
// CALLER CONTRACT: pass a fixed basename joined to a registry-derived directory – filepath.Join(in.Dir,
// "<name>") – NEVER a path derived from manifest CONTENT. The Lstat/size guards block symlinks + oversize
// but not an in-tree-relative `..`; a future content-derived companion path (e.g. a Maven module ref)
// must add explicit root containment (filepath.Rel/Clean) before calling this.
func readManifestFile(path string) ([]byte, bool) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxManifestBytes {
		return nil, false
	}
	content, err := os.ReadFile(path) // #nosec G304 -- regular file, size-capped via Lstat above, under the target tree
	if err != nil {
		return nil, false
	}
	return content, true
}
