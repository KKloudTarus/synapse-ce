// Package bincat catalogs installed language packages from a materialized image root filesystem that a
// lockfile would miss: Go module dependencies embedded in compiled Go binaries (via stdlib debug/buildinfo)
// and Python distributions installed on disk (*.dist-info / *.egg-info metadata). It is the OWNED
// (detection-independent) counterpart to the generator for a SHIPPED artifact – a Go image is frequently just
// a scratch/distroless base plus one static binary with no go.mod present, so the binary's embedded build
// info is the only inventory. Emitted components carry the language PURL (pkg:golang / pkg:pypi) so the
// existing OSV advisory source matches them. It only READS the rootfs (assembled + symlink-free within the
// workspace); the walk is bounded (file + component caps) and cancellable, and package identifiers are
// validated before entering a PURL.
package bincat

import (
	"bufio"
	"context"
	"debug/buildinfo"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxFilesWalked = 300_000 // rootfs entries examined (bound the walk of a large image)
	maxComponents  = 200_000 // emitted-component cap
	maxMetaBytes   = 1 << 20 // a dist-info METADATA / egg-info PKG-INFO read cap
	maxModulePath  = 512     // clip an over-long module/name before it enters a PURL
)

// Cataloger implements ports.InstalledPackageCataloger over a materialized image rootfs.
type Cataloger struct{}

// New returns an installed-package cataloger.
func New() *Cataloger { return &Cataloger{} }

var _ ports.InstalledPackageCataloger = (*Cataloger)(nil)

// CatalogInstalled walks rootfsDir once, cataloging Go binaries + Python installed metadata. Best-effort: an
// unreadable file contributes nothing; returns an error only on context cancellation.
func (Cataloger) CatalogInstalled(ctx context.Context, rootfsDir string) ([]sbom.Component, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(rootfsDir) == "" {
		return nil, nil
	}
	var out []sbom.Component
	seen := map[string]bool{} // dedup within this catalog by PURL
	add := func(c sbom.Component, ok bool) {
		if !ok || seen[c.PURL] || len(out) >= maxComponents {
			return
		}
		seen[c.PURL] = true
		out = append(out, c)
	}
	files := 0
	walkErr := filepath.WalkDir(rootfsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip
		}
		if err := ctx.Err(); err != nil {
			return err // stop + propagate cancellation (never report a partial catalog as success)
		}
		if d.IsDir() || !d.Type().IsRegular() { // skip dirs + symlinks/specials (rootfs is symlink-free)
			return nil
		}
		files++
		if files > maxFilesWalked || len(out) >= maxComponents {
			return fs.SkipAll
		}
		switch {
		case isPythonMetadata(path):
			add(pythonComponent(path))
		case looksLikeBinary(path):
			for _, c := range goBinaryComponents(path) {
				add(c, true)
			}
		}
		return nil
	})
	if walkErr != nil { // the only non-nil walk error is context cancellation (entry errors are skipped)
		return out, walkErr
	}
	return out, nil
}

// isPythonMetadata reports whether path is an installed-distribution metadata file
// (<pkg>.dist-info/METADATA or <pkg>.egg-info/PKG-INFO).
func isPythonMetadata(path string) bool {
	base, dir := filepath.Base(path), filepath.Dir(path)
	return (base == "METADATA" && strings.HasSuffix(dir, ".dist-info")) ||
		(base == "PKG-INFO" && strings.HasSuffix(dir, ".egg-info"))
}

// pythonComponent parses an installed Python distribution's metadata into a pkg:pypi component.
func pythonComponent(path string) (sbom.Component, bool) {
	data := readBounded(path, maxMetaBytes)
	if data == nil {
		return sbom.Component{}, false
	}
	var name, version string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" { // metadata headers end at the first blank line (the long description follows)
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "Name":
			if name == "" {
				name = normalizePyPI(strings.TrimSpace(v))
			}
		case "Version":
			if version == "" {
				version = strings.TrimSpace(v)
			}
		}
	}
	if !validIdent(name) || !validIdent(version) {
		return sbom.Component{}, false
	}
	return sbom.Component{Name: name, Version: version, PURL: "pkg:pypi/" + name + "@" + version, Scope: sbom.ScopeProduction}, true
}

// goBinaryComponents reads a Go binary's embedded build info into pkg:golang components: the main module (when
// it carries a resolved version) and every dependency (following a replacement). A non-Go / unreadable file
// yields nothing.
func goBinaryComponents(path string) (comps []sbom.Component) {
	// A crafted ELF/PE/Mach-O can PANIC the stdlib debug/* parsers (malformed header counts/offsets turn into
	// index/slice-bounds panics, not errors). Recover so one poisoned binary in an untrusted image contributes
	// nothing – preserving the best-effort contract – rather than unwinding out of the walk and crashing the
	// scan worker.
	defer func() {
		if recover() != nil {
			comps = nil
		}
	}()
	bi, err := buildinfo.ReadFile(path)
	if err != nil || bi == nil {
		return nil
	}
	return buildInfoComponents(bi)
}

// buildInfoComponents maps a Go binary's build info to pkg:golang components: the main module (when it carries
// a resolved version – a source build records "(devel)", which is filtered) and every dependency, following a
// replacement. Pure, so it is unit-tested with a synthetic BuildInfo (a go-test binary omits its dep graph).
func buildInfoComponents(bi *debug.BuildInfo) []sbom.Component {
	var out []sbom.Component
	addMod := func(modPath, version string) {
		if !validGoModule(modPath) || !resolvedGoVersion(version) {
			return
		}
		out = append(out, sbom.Component{
			Name: modPath, Version: version,
			PURL:  "pkg:golang/" + modPath + "@" + version,
			Scope: sbom.ScopeProduction,
		})
	}
	addMod(bi.Main.Path, bi.Main.Version)
	for _, dep := range bi.Deps {
		if dep == nil {
			continue
		}
		mod := dep
		if dep.Replace != nil { // a replaced dependency ships as its replacement
			mod = dep.Replace
		}
		addMod(mod.Path, mod.Version)
	}
	return out
}

// looksLikeBinary cheaply pre-checks the executable magic (ELF / PE / Mach-O) so the buildinfo read is
// attempted only on plausible binaries, not every text file in the rootfs.
func looksLikeBinary(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var m [4]byte
	if _, err := io.ReadFull(f, m[:]); err != nil {
		return false
	}
	switch {
	case m[0] == 0x7f && m[1] == 'E' && m[2] == 'L' && m[3] == 'F': // ELF
		return true
	case m[0] == 'M' && m[1] == 'Z': // PE
		return true
	case m[0] == 0xfe && m[1] == 0xed && m[2] == 0xfa && (m[3] == 0xce || m[3] == 0xcf): // Mach-O (big-endian magic)
		return true
	case (m[0] == 0xce || m[0] == 0xcf) && m[1] == 0xfa && m[2] == 0xed && m[3] == 0xfe: // Mach-O (little-endian)
		return true
	}
	return false
}

// normalizePyPI applies PEP 503 name normalization: lowercase, and any run of "-_." becomes a single "-".
func normalizePyPI(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	prevSep := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('-')
				prevSep = true
			}
			continue
		}
		b.WriteRune(r)
		prevSep = false
	}
	return strings.Trim(b.String(), "-")
}

// resolvedGoVersion reports whether a module version is concrete + matchable (not a source-build placeholder).
func resolvedGoVersion(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && v != "(devel)" && validIdent(v)
}

// validGoModule reports whether a module path is a safe, plausible PURL segment: non-empty, bounded, and free
// of characters that would break the PURL grammar (a real Go module path has none of them).
func validGoModule(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" || len(p) > maxModulePath {
		return false
	}
	return !strings.ContainsAny(p, "?#@ \t\r\n%\\") && !hasControl(p)
}

// validIdent reports whether a name/version token is a safe, bounded PURL segment (no grammar-breaking or
// control characters). Slashes are rejected too (a PyPI name / version never contains one).
func validIdent(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxModulePath {
		return false
	}
	return !strings.ContainsAny(s, "?#@/ \t\r\n%\\") && !hasControl(s)
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// readBounded reads a regular file up to max bytes; a missing/irregular/symlink path or error → nil.
func readBounded(path string, max int64) []byte {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(bufio.NewReader(f), max))
	if err != nil {
		return nil
	}
	return data
}
