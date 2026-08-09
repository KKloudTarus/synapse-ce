package srcimports

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Bounds cap worst-case work on a hostile or simply enormous repository. Exceeding one is recorded as a
// coverage reason, so a truncated scan can never look like a complete observation.
const (
	defaultMaxFiles     = 50000
	defaultMaxFileBytes = 2 << 20
	defaultMaxEntries   = 500000
)

type scanLimits struct {
	maxFiles     int
	maxFileBytes int64
	maxEntries   int
}

func defaultScanLimits() scanLimits {
	return scanLimits{maxFiles: defaultMaxFiles, maxFileBytes: defaultMaxFileBytes, maxEntries: defaultMaxEntries}
}

// dynamicConstruct is a textual marker for a construct under which a dependency can be referenced
// without a visible import statement.
type dynamicConstruct struct {
	marker string
	reason string
}

// scanAccumulator collects one scan's observations.
type scanAccumulator struct {
	packages    map[string]bool
	entrypoints []string
	reasons     map[string]bool
	files       int
}

func newScanAccumulator() *scanAccumulator {
	return &scanAccumulator{packages: map[string]bool{}, reasons: map[string]bool{}}
}

func (a *scanAccumulator) addPackage(name string) {
	if trimmed := strings.ToLower(strings.TrimSpace(name)); trimmed != "" {
		a.packages[trimmed] = true
	}
}

func (a *scanAccumulator) addReason(reason string) {
	if trimmed := strings.TrimSpace(reason); trimmed != "" {
		a.reasons[trimmed] = true
	}
}

// noteDynamic records every dynamic construct present in a file body. The recorded reason names the
// CONSTRUCT and the file, never the surrounding source, because these strings are sealed into evidence.
func (a *scanAccumulator) noteDynamic(body string, constructs []dynamicConstruct, path string) {
	for _, construct := range constructs {
		if strings.Contains(body, construct.marker) {
			a.addReason(construct.reason + " (" + path + ")")
		}
	}
}

// graph renders the accumulator as the port's observation type, deterministically ordered.
func (a *scanAccumulator) graph() ports.SourceImportGraph {
	packages := make([]string, 0, len(a.packages))
	for name := range a.packages {
		packages = append(packages, name)
	}
	sort.Strings(packages)

	reasons := make([]string, 0, len(a.reasons))
	for reason := range a.reasons {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)

	// A scan that read source but observed NO import at all is the shape of a parser that did not
	// understand the language, not of a project with no dependencies. Accepting it as authoritative
	// would answer every subject "not referenced" off an empty observation, so it refuses instead.
	if len(packages) == 0 && a.files > 0 {
		reasons = append(reasons, "no import, require or use statement was observed in any scanned source file")
		sort.Strings(reasons)
	}

	entrypoints := normalizeNames(a.entrypoints)
	return ports.SourceImportGraph{
		ImportedPackages: packages,
		Entrypoints:      entrypoints,
		CoverageReasons:  reasons,
		FilesScanned:     a.files,
	}
}

// sourceWalker performs a bounded, confined traversal collecting one language's source files.
type sourceWalker struct {
	limits     scanLimits
	extensions []string
	skipDir    map[string]bool
	// extraFiles are extension-less files that are nonetheless source (Rakefile, config.ru).
	extraFiles []string
}

func newSourceWalker(limits scanLimits, extensions []string, skipDir map[string]bool) *sourceWalker {
	return &sourceWalker{limits: limits, extensions: extensions, skipDir: skipDir}
}

// walk visits every supported source file under dir, calling visit with its content.
//
// Symlinks are never followed and every skipped or unreadable file becomes a coverage reason, because a
// file this scan did not read could reference a dependency.
func (w *sourceWalker) walk(ctx context.Context, dir string, visit func(path string, content []byte, out *scanAccumulator)) (*scanAccumulator, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: source scan requires a context", shared.ErrValidation)
	}
	trimmed := strings.TrimSpace(dir)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: source scan requires a target directory", shared.ErrValidation)
	}
	info, err := os.Lstat(trimmed)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: source scan root does not exist", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: source scan root is not readable", shared.ErrValidation)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("%w: source scan root must be a real directory", shared.ErrValidation)
	}

	rootDir, err := os.OpenRoot(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w: source scan root could not be opened", shared.ErrValidation)
	}
	defer func() { _ = rootDir.Close() }()

	out := newScanAccumulator()
	entries := 0
	walkErr := fs.WalkDir(rootDir.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			out.addReason("a directory entry could not be read")
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		entries++
		if entries > w.limits.maxEntries {
			out.addReason("directory entry budget exceeded; traversal stopped")
			return fs.SkipAll
		}
		if d.IsDir() {
			if p == "." {
				return nil
			}
			name := d.Name()
			if w.skipDir[name] || strings.HasPrefix(name, ".") {
				// Excluding a directory is a policy choice, but source inside it is UNOBSERVED. Only
				// dependency and VCS directories are exempt; anything else that actually holds source
				// degrades coverage so its references are never read as absent.
				if !exemptFromCoverage[name] && w.directoryHasSource(rootDir, p) {
					out.addReason("an excluded directory contains unscanned source (" + p + ")")
				}
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			out.addReason("a symlink was not followed (" + p + ")")
			return nil
		}
		if !d.Type().IsRegular() || !w.supported(p) {
			return nil
		}
		if out.files >= w.limits.maxFiles {
			out.addReason("source file budget exceeded; some files were not scanned")
			return nil
		}
		content, ok := readThroughRoot(rootDir, p, w.limits.maxFileBytes)
		if !ok {
			out.addReason("a source file could not be read (" + p + ")")
			return nil
		}
		if !utf8.Valid(content) {
			out.addReason("a source file is not valid UTF-8 (" + p + ")")
			return nil
		}
		out.files++
		visit(p, content, out)
		return nil
	})
	if walkErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("source scan cancelled: %w", ctxErr)
		}
		return nil, fmt.Errorf("%w: source scan could not walk the target", shared.ErrValidation)
	}
	if out.files == 0 {
		return nil, fmt.Errorf("%w: no supported source under the target (no coverage)", shared.ErrNotFound)
	}
	return out, nil
}

func (w *sourceWalker) supported(p string) bool {
	lower := strings.ToLower(p)
	for _, ext := range w.extensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	base := p
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	for _, name := range w.extraFiles {
		if base == name {
			return true
		}
	}
	return false
}

// exemptFromCoverage names excluded directories whose contents are legitimately outside first-party
// source, so excluding them is not a coverage limitation.
var exemptFromCoverage = map[string]bool{
	"vendor": true, "node_modules": true, "target": true,
	".git": true, ".hg": true, ".svn": true,
	"tmp": true, "log": true, "cache": true, "var": true, "coverage": true,
}

// directoryHasSource reports whether an excluded directory holds at least one supported file. The probe
// is bounded, and exhausting the budget assumes source is present rather than claiming none.
func (w *sourceWalker) directoryHasSource(rootDir *os.Root, dir string) bool {
	const probeBudget = 512
	seen := 0
	found := false
	_ = fs.WalkDir(rootDir.FS(), dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fs.SkipDir
		}
		seen++
		if seen > probeBudget {
			found = true
			return fs.SkipAll
		}
		if d != nil && d.IsDir() {
			return nil
		}
		if w.supported(p) {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}

// readThroughRoot reads a file through the confined root handle, bounded by the per-file budget.
func readThroughRoot(rootDir *os.Root, rel string, maxBytes int64) ([]byte, bool) {
	f, err := rootDir.Open(rel)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	// Read one byte past the budget so growth during the read is detectable rather than silently
	// truncating the tail of a file.
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil || int64(len(data)) > maxBytes {
		return nil, false
	}
	return data, true
}

// readBoundedFile reads one named file directly under dir, used for manifests.
func readBoundedFile(ctx context.Context, dir, name string, maxBytes int64) ([]byte, bool) {
	if ctx == nil || ctx.Err() != nil {
		return nil, false
	}
	rootDir, err := os.OpenRoot(strings.TrimSpace(dir))
	if err != nil {
		return nil, false
	}
	defer func() { _ = rootDir.Close() }()
	info, err := rootDir.Lstat(name)
	if err != nil || info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, false
	}
	return readThroughRoot(rootDir, name, maxBytes)
}

// stripLineComments removes single-line comments so a commented-out import cannot become a false
// reference. Block comments are left alone: including one would risk removing real code on a mismatch,
// and an extra reference is the safe direction.
func stripLineComments(body, marker string) string {
	var sb strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if i := strings.Index(line, marker); i >= 0 {
			// Only strip when the marker is not inside a quoted string on that line.
			if strings.Count(line[:i], "\"")%2 == 0 && strings.Count(line[:i], "'")%2 == 0 {
				line = line[:i]
			}
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// normalizeNames lowercases, trims, sorts and deduplicates a name list.
func normalizeNames(in []string) []string {
	out := make([]string, 0, len(in))
	for _, name := range in {
		if trimmed := strings.ToLower(strings.TrimSpace(name)); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	result := out[:1]
	for _, name := range out[1:] {
		if name != result[len(result)-1] {
			result = append(result, name)
		}
	}
	return result
}

// DirectDependencies returns the dependency names a first-party manifest declares, and whether a
// manifest was found at all.
//
// This is the guard that keeps a TRANSITIVE package out of a Tier-1 answer. A lockfile-derived SBOM is a
// fully resolved graph, so most components are transitive — and first-party source never writes an
// import for a package it receives through a parent. Reporting those as unreferenced would suppress the
// majority of real findings, so a subject that is not a declared direct dependency must not be answered.
func DirectDependencies(ctx context.Context, dir, purlType string) (map[string]bool, bool) {
	limits := defaultScanLimits()
	switch purlType {
	case "cargo":
		content, ok := readBoundedFile(ctx, dir, "Cargo.toml", limits.maxFileBytes)
		if !ok {
			return nil, false
		}
		return cargoDirectDependencies(string(content)), true
	case "composer":
		content, ok := readBoundedFile(ctx, dir, "composer.json", limits.maxFileBytes)
		if !ok {
			return nil, false
		}
		return composerDirectDependencies(content), true
	case "gem":
		content, ok := readBoundedFile(ctx, dir, "Gemfile", limits.maxFileBytes)
		if !ok {
			return nil, false
		}
		return gemfileDirectDependencies(string(content)), true
	}
	return nil, false
}

// cargoDirectDependencies reads the [dependencies] style tables of a Cargo manifest.
func cargoDirectDependencies(body string) map[string]bool {
	out := map[string]bool{}
	section := ""
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			section = strings.Trim(trimmed, "[]")
			continue
		}
		if !strings.HasSuffix(section, "dependencies") {
			continue
		}
		name, _, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		if key := strings.TrimSpace(name); key != "" {
			out[strings.ToLower(key)] = true
		}
	}
	return out
}

// composerDirectDependencies reads require and require-dev.
func composerDirectDependencies(content []byte) map[string]bool {
	var manifest struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	out := map[string]bool{}
	if jsonUnmarshal(content, &manifest) != nil {
		return out
	}
	for _, group := range []map[string]string{manifest.Require, manifest.RequireDev} {
		for name := range group {
			out[strings.ToLower(name)] = true
		}
	}
	return out
}

// gemfileDirectDependencies reads the `gem "name"` declarations of a Gemfile.
func gemfileDirectDependencies(body string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(stripLineComments(body, "#"), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "gem ") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "gem"))
		if rest == "" {
			continue
		}
		quote := rest[0]
		if quote != '\'' && quote != '"' {
			continue
		}
		rest = rest[1:]
		if end := strings.IndexByte(rest, quote); end > 0 {
			out[strings.ToLower(rest[:end])] = true
		}
	}
	return out
}

// jsonUnmarshal is a thin alias so the manifest readers above stay easy to read.
func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }
