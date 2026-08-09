// Package jsimports implements the deterministic, source-only JavaScript and TypeScript module-import
// scanner behind ports.JSImportScanner (epic #378 phase R1).
//
// It reads source bytes and nothing else: it never executes project code, package managers, bundlers or
// lifecycle scripts, never resolves through a registry, and never touches the network. Because it only
// lexes text it runs in-process like the Python import scanner, rather than inside the sandbox that
// confines toolchains which compile untrusted source.
//
// The load-bearing rule is that an unobservable module load must degrade COVERAGE rather than vanish: a
// later analyzer may treat "no edge" as proof of absence only when the graph reports no coverage issues.
// Every bound, unreadable file, dynamic loader and unresolved specifier therefore emits a structured
// modulegraph.CoverageIssue.
package jsimports

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Default bounds. They cap worst-case work on a hostile or simply enormous repository; exceeding one is
// recorded as a coverage issue so the caller learns the graph is partial instead of silently truncated.
const (
	defaultMaxFiles      = 50000
	defaultMaxFileBytes  = 2 << 20   // 2 MiB per source file
	defaultMaxTotalBytes = 512 << 20 // 512 MiB across the scan
	defaultMaxEntries    = 500000    // directory entries visited
	defaultMaxEdges      = 250000    // import edges retained
	defaultMaxCoverage   = 4096
)

// scannerLimits are the tunable bounds; tests inject small values to exercise every budget path.
type scannerLimits struct {
	maxFiles      int
	maxFileBytes  int64
	maxTotalBytes int64
	maxEntries    int
	maxEdges      int
	maxCoverage   int
}

func defaultLimits() scannerLimits {
	return scannerLimits{
		maxFiles:      defaultMaxFiles,
		maxFileBytes:  defaultMaxFileBytes,
		maxTotalBytes: defaultMaxTotalBytes,
		maxEntries:    defaultMaxEntries,
		maxEdges:      defaultMaxEdges,
		maxCoverage:   defaultMaxCoverage,
	}
}

func (l scannerLimits) validate() error {
	if l.maxFiles <= 0 || l.maxFileBytes <= 0 || l.maxTotalBytes <= 0 || l.maxEntries <= 0 || l.maxEdges <= 0 || l.maxCoverage <= 0 {
		return fmt.Errorf("%w: jsimports limits must be positive", shared.ErrValidation)
	}
	return nil
}

// Scanner builds a first-party JavaScript and TypeScript module graph for a repository root.
type Scanner struct {
	limits scannerLimits
}

var _ ports.JSImportScanner = (*Scanner)(nil)

// New returns a Scanner with production bounds.
func New() *Scanner { return &Scanner{limits: defaultLimits()} }

// newWithLimits is the test seam for exercising the budget paths.
func newWithLimits(l scannerLimits) (*Scanner, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}
	return &Scanner{limits: l}, nil
}

// skipDir names directories that never hold first-party source. node_modules is excluded because the
// graph is first-party only: a dependency's own imports are not evidence that FIRST-PARTY code uses it.
var skipDir = map[string]bool{
	"node_modules": true,
	".git":         true, ".hg": true, ".svn": true,
	"dist": true, "build": true, "out": true, "coverage": true,
	".next": true, ".nuxt": true, ".svelte-kit": true, ".turbo": true, ".cache": true,
	"bower_components": true, "jspm_packages": true, "vendor": true,
}

// exemptFromCoverage names the excluded directories whose contents are legitimately outside the
// first-party graph, so excluding them is not a coverage limitation. Everything else in skipDir is a
// policy exclusion: build output, tool config and vendored code CAN contain first-party imports, so a
// skipped directory holding source degrades coverage.
var exemptFromCoverage = map[string]bool{
	"node_modules": true, "bower_components": true, "jspm_packages": true,
	".git": true, ".hg": true, ".svn": true,
}

// assetExtensions are non-executable imports (data and styling). A relative import of one of these
// cannot hide a JavaScript package import, so it resolves to "not a module" without degrading coverage.
var assetExtensions = map[string]bool{
	".css": true, ".scss": true, ".sass": true, ".less": true, ".styl": true,
	".json": true, ".json5": true, ".jsonc": true, ".yaml": true, ".yml": true, ".toml": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".webp": true, ".avif": true, ".ico": true, ".bmp": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".mp3": true, ".mp4": true, ".webm": true, ".wav": true, ".ogg": true,
	".txt":  true,
	".wasm": true, ".graphql": true, ".gql": true, ".proto": true, ".csv": true, ".xml": true,
	".sql": true, ".sh": true, ".pdf": true, ".zip": true,
}

// codeCarryingExtensions are single-file component formats whose bodies contain JavaScript or TypeScript
// this scanner cannot parse. Importing one hides real imports, so it degrades coverage explicitly.
var codeCarryingExtensions = map[string]bool{
	".vue": true, ".svelte": true, ".astro": true, ".marko": true, ".riot": true,
	".coffee": true, ".litcoffee": true, ".res": true, ".re": true, ".elm": true,
	// MDX compiles to JavaScript and routinely carries real ESM imports; HTML carries
	// <script type="module">. Treating either as an inert asset would let a package imported only
	// from documentation or a Storybook page look unused.
	".mdx": true, ".md": true, ".html": true, ".htm": true,
}

// Scan walks root and returns the normalized first-party module graph.
//
// It returns an error only for a hard no-coverage condition: an unusable root, a cancelled context, a
// budget so small it invalidates the walk, or no supported source at all. Every partial observation is
// reported in Graph.Coverage instead.
func (s *Scanner) Scan(ctx context.Context, root string) (modulegraph.Graph, error) {
	if ctx == nil {
		return modulegraph.Graph{}, fmt.Errorf("%w: jsimports scan requires a context", shared.ErrValidation)
	}
	if err := s.limits.validate(); err != nil {
		return modulegraph.Graph{}, err
	}
	trimmed := strings.TrimSpace(root)
	if trimmed == "" {
		return modulegraph.Graph{}, fmt.Errorf("%w: jsimports scan root is required", shared.ErrValidation)
	}

	// Reject a symlinked or non-directory root outright: os.OpenRoot below confines traversal, but the
	// root itself must be a real directory for repository-relative paths to mean anything.
	// The OS error carries the ABSOLUTE host path, which must never reach a log, a judgment or the
	// audit trail (golden rule 3): classify it and drop the original.
	info, err := os.Lstat(trimmed)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return modulegraph.Graph{}, fmt.Errorf("%w: jsimports scan root does not exist", shared.ErrNotFound)
		}
		return modulegraph.Graph{}, fmt.Errorf("%w: jsimports scan root is not readable", shared.ErrValidation)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return modulegraph.Graph{}, fmt.Errorf("%w: jsimports scan root is a symlink", shared.ErrValidation)
	}
	if !info.IsDir() {
		return modulegraph.Graph{}, fmt.Errorf("%w: jsimports scan root is not a directory", shared.ErrValidation)
	}

	rootDir, err := os.OpenRoot(trimmed)
	if err != nil {
		return modulegraph.Graph{}, fmt.Errorf("%w: jsimports scan root could not be opened", shared.ErrValidation)
	}
	defer func() { _ = rootDir.Close() }()

	sc := &scanState{
		limits:   s.limits,
		rootDir:  rootDir,
		coverage: newCoverageSink(s.limits.maxCoverage),
	}
	if err := sc.walk(ctx); err != nil {
		return modulegraph.Graph{}, err
	}
	if len(sc.sources) == 0 {
		// No supported source at all is a no-coverage condition, not an empty proof: the target simply
		// is not a JavaScript or TypeScript project.
		return modulegraph.Graph{}, fmt.Errorf("%w: no javascript or typescript source under scan root (no coverage)", shared.ErrNotFound)
	}
	if err := sc.parseAll(ctx); err != nil {
		return modulegraph.Graph{}, err
	}

	graph := modulegraph.Graph{
		Modules: sc.modules,
		Edges:   sc.edges,
		SymbolEvidence: &modulegraph.SymbolEvidence{
			Uses:       sc.localUses,
			JSXModules: sc.jsxModules,
			Coverage:   sc.symbolCoverage,
		},
		Coverage:     sc.coverage.issues(),
		FilesScanned: sc.filesScanned,
		BytesScanned: sc.bytesScanned,
	}
	normalized, err := modulegraph.Normalize(graph)
	if err != nil {
		return modulegraph.Graph{}, fmt.Errorf("jsimports: normalize graph: %w", err)
	}
	return normalized, nil
}

// sourceFile is a discovered first-party module awaiting parse.
type sourceFile struct {
	// relPath is the normalized repository-relative slash path.
	relPath string
	size    int64
}

// scanState carries one scan's mutable state.
type scanState struct {
	limits  scannerLimits
	rootDir *os.Root

	sources []sourceFile
	// moduleSet indexes discovered modules by repository-relative path for relative resolution.
	moduleSet map[string]bool
	// lowerIndex maps the lowercased path to its real casing, so a case-only mismatch is reported as
	// ambiguous instead of silently resolving on a case-insensitive filesystem.
	lowerIndex map[string][]string
	// assetSet and codeCarryingSet index non-JS files that a relative import may target.
	assetSet        map[string]bool
	codeCarryingSet map[string]bool

	modules []modulegraph.Module
	edges   []modulegraph.Edge
	// Tier-2 symbol evidence: what each module does with the locals its imports bind, which modules
	// actually contain JSX, and any limitation of that evidence (kept apart from the graph's own
	// coverage so a Tier-2 budget cannot refuse a Tier-1 answer).
	localUses      []modulegraph.LocalUse
	jsxModules     []string
	symbolCoverage []modulegraph.CoverageIssue

	coverage     *coverageSink
	filesScanned int
	bytesScanned int64
	entriesSeen  int

	filesBudgetHit bool
	bytesBudgetHit bool
	edgesBudgetHit bool
}

// walk discovers every candidate file under the root without following symlinks.
func (sc *scanState) walk(ctx context.Context) error {
	sc.moduleSet = map[string]bool{}
	sc.lowerIndex = map[string][]string{}
	sc.assetSet = map[string]bool{}
	sc.codeCarryingSet = map[string]bool{}

	walkErr := fs.WalkDir(sc.rootDir.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			// An unreadable directory is a coverage limitation, not a scan failure.
			sc.coverage.add(modulegraph.CoverageIssue{
				Kind:   modulegraph.CoverageUnreadableFile,
				Path:   normalizeOrEmpty(p),
				Detail: "directory entry could not be read",
			})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		sc.entriesSeen++
		if sc.entriesSeen > sc.limits.maxEntries {
			sc.coverage.add(modulegraph.CoverageIssue{
				Kind:   modulegraph.CoverageEntryBudgetExceeded,
				Detail: "directory entry budget exceeded; traversal stopped",
			})
			return fs.SkipAll
		}

		name := d.Name()
		if d.IsDir() {
			if p == "." {
				return nil
			}
			if skipDir[name] || strings.HasPrefix(name, ".") {
				// Excluding a directory is a policy choice, but modules inside it are UNOBSERVED. Only
				// dependency and VCS directories are exempt (a dependency's own imports are not
				// evidence that first-party code uses it); anything else that actually contains source
				// degrades coverage so its imports are never read as absent.
				if !exemptFromCoverage[name] && sc.directoryHasSource(p) {
					sc.coverage.add(modulegraph.CoverageIssue{
						Kind:   modulegraph.CoverageSkippedDirectory,
						Path:   normalizeOrEmpty(p),
						Detail: "excluded directory contains unscanned source",
					})
				}
				return fs.SkipDir
			}
			return nil
		}

		// Symlinks are never followed: a link can point outside the repository or create a cycle. It is
		// recorded so a later analyzer knows a module may be unobserved.
		if d.Type()&fs.ModeSymlink != 0 {
			sc.coverage.add(modulegraph.CoverageIssue{
				Kind:   modulegraph.CoverageSymlink,
				Path:   normalizeOrEmpty(p),
				Detail: "symlink not followed",
			})
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}

		ext := strings.ToLower(path.Ext(p))
		switch {
		case assetExtensions[ext]:
			sc.assetSet[p] = true
			return nil
		case codeCarryingExtensions[ext]:
			// A single-file component carries JavaScript this scanner cannot parse. Recording it only
			// when some scanned module imports it would leave a component-only project silently
			// unobserved, so the file itself degrades coverage on discovery.
			sc.codeCarryingSet[p] = true
			sc.coverage.add(modulegraph.CoverageIssue{
				Kind:   modulegraph.CoverageUnsupportedSyntax,
				Path:   normalizeOrEmpty(p),
				Detail: "single-file component source is not parsed",
			})
			return nil
		}
		if _, ok := modulegraph.DialectForPath(p); !ok {
			// An extension-less executable script (the package.json "bin" shape) holds real imports and
			// would otherwise be dropped without a trace.
			if ext == "" && sc.hasShebang(p) {
				sc.coverage.add(modulegraph.CoverageIssue{
					Kind:   modulegraph.CoverageUnsupportedSyntax,
					Path:   normalizeOrEmpty(p),
					Detail: "extension-less executable script is not parsed",
				})
			}
			return nil
		}

		if len(sc.sources) >= sc.limits.maxFiles {
			if !sc.filesBudgetHit {
				sc.filesBudgetHit = true
				sc.coverage.add(modulegraph.CoverageIssue{
					Kind:   modulegraph.CoverageFileCountBudgetExceeded,
					Detail: "source file budget exceeded; some modules were not scanned",
				})
			}
			return nil
		}

		info, ierr := d.Info()
		if ierr != nil {
			sc.coverage.add(modulegraph.CoverageIssue{
				Kind:   modulegraph.CoverageUnreadableFile,
				Path:   normalizeOrEmpty(p),
				Detail: "file metadata could not be read",
			})
			return nil
		}
		if info.Size() > sc.limits.maxFileBytes {
			sc.coverage.add(modulegraph.CoverageIssue{
				Kind:   modulegraph.CoverageFileTooLarge,
				Path:   normalizeOrEmpty(p),
				Detail: "source file exceeds the per-file byte budget",
			})
			return nil
		}

		normalized, nerr := modulegraph.NormalizeRepositoryPath(p)
		if nerr != nil {
			sc.coverage.add(modulegraph.CoverageIssue{
				Kind:   modulegraph.CoverageUnreadableFile,
				Path:   "",
				Detail: "source path could not be normalized",
			})
			return nil
		}
		sc.sources = append(sc.sources, sourceFile{relPath: normalized, size: info.Size()})
		sc.moduleSet[normalized] = true
		lower := strings.ToLower(normalized)
		sc.lowerIndex[lower] = append(sc.lowerIndex[lower], normalized)
		return nil
	})
	if walkErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("jsimports: scan cancelled: %w", ctxErr)
		}
		// Drop the OS error: it embeds absolute host paths.
		return fmt.Errorf("%w: jsimports could not walk the scan root", shared.ErrValidation)
	}

	// Deterministic parse order regardless of filesystem ordering.
	sort.Slice(sc.sources, func(i, j int) bool { return sc.sources[i].relPath < sc.sources[j].relPath })
	return nil
}

// parseAll lexes every discovered source file and records its edges and hazards.
func (sc *scanState) parseAll(ctx context.Context) error {
	sc.modules = make([]modulegraph.Module, 0, len(sc.sources))
	for _, src := range sc.sources {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("jsimports: scan cancelled: %w", err)
		}

		dialect, ok := modulegraph.DialectForPath(src.relPath)
		if !ok {
			continue
		}
		module := modulegraph.Module{
			Path:            src.relPath,
			Dialect:         dialect,
			DeclarationOnly: modulegraph.IsDeclarationPath(src.relPath),
		}
		sc.modules = append(sc.modules, module)

		if sc.bytesBudgetHit {
			// Past the total-byte budget the module is known to exist but its imports are unobserved.
			continue
		}
		if sc.bytesScanned+src.size > sc.limits.maxTotalBytes {
			sc.bytesBudgetHit = true
			sc.coverage.add(modulegraph.CoverageIssue{
				Kind:   modulegraph.CoverageTotalByteBudgetExceeded,
				Detail: "total byte budget exceeded; remaining modules were not parsed",
			})
			continue
		}

		data, rerr := sc.readSource(src)
		if rerr != nil {
			sc.coverage.add(modulegraph.CoverageIssue{
				Kind:   modulegraph.CoverageUnreadableFile,
				Path:   src.relPath,
				Detail: "source file could not be read",
			})
			continue
		}
		sc.filesScanned++
		sc.bytesScanned += int64(len(data))

		if !utf8.Valid(data) {
			// A non-UTF-8 module cannot be lexed reliably; its imports are unobserved.
			sc.coverage.add(modulegraph.CoverageIssue{
				Kind:   modulegraph.CoverageInvalidUTF8,
				Path:   src.relPath,
				Detail: "source is not valid UTF-8",
			})
			continue
		}

		// JSX appears in .js/.mjs/.cjs as well (Babel, CRA and Next projects), and missing it there
		// re-opens the apostrophe-swallowing silent miss. Only plain TypeScript is scanned non-JSX,
		// because there `<Foo>x` is a type assertion rather than an element.
		result := newExtractor(data, dialect != modulegraph.DialectTypeScript).run()
		sc.recordHazards(src.relPath, result.hazards)
		for _, imp := range result.imports {
			sc.recordImport(src.relPath, imp)
		}
		sc.recordLocalUses(src.relPath, result)
	}
	return nil
}

// readSource reads one file through the confined root handle, bounded by the per-file budget.
func (sc *scanState) readSource(src sourceFile) ([]byte, error) {
	f, err := sc.rootDir.Open(src.relPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	// Re-stat through the open handle: the entry could have changed between walk and read, and a
	// non-regular file must never be read as source.
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("jsimports: %q is not a regular file", src.relPath)
	}
	if info.Size() > sc.limits.maxFileBytes {
		return nil, fmt.Errorf("jsimports: %q exceeds the per-file byte budget", src.relPath)
	}
	// Read one byte PAST the budget so growth between the stat and the read is detectable: silently
	// parsing a truncated prefix would drop the imports after the cut with no coverage issue.
	data, err := io.ReadAll(io.LimitReader(f, sc.limits.maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > sc.limits.maxFileBytes {
		return nil, fmt.Errorf("jsimports: %q grew past the per-file byte budget during the read", src.relPath)
	}
	return data, nil
}

// hazardCoverageKind maps a lexical hazard to its coverage kind.
func hazardCoverageKind(k hazardKind) modulegraph.CoverageIssueKind {
	switch k {
	case hazardDynamicRequire:
		return modulegraph.CoverageDynamicRequire
	case hazardDynamicImport:
		return modulegraph.CoverageDynamicImport
	case hazardEval:
		return modulegraph.CoverageEval
	case hazardNewFunction:
		return modulegraph.CoverageNewFunction
	case hazardRequireContext:
		return modulegraph.CoverageRequireContext
	case hazardImportMetaGlob:
		return modulegraph.CoverageImportMetaGlob
	case hazardModuleCreateRequire:
		return modulegraph.CoverageModuleCreateRequire
	case hazardMalformedSource:
		return modulegraph.CoverageMalformedSource
	default:
		return modulegraph.CoverageUnsupportedLoader
	}
}

func (sc *scanState) recordHazards(modulePath string, hazards []hazard) {
	for _, h := range hazards {
		line := h.line
		if line < 0 {
			line = 0
		}
		sc.coverage.add(modulegraph.CoverageIssue{
			Kind:   hazardCoverageKind(h.kind),
			Path:   modulePath,
			Line:   line,
			Detail: h.detail,
		})
	}
}

// recordImport turns one extracted import site into a graph edge, resolving relative specifiers to
// first-party modules. External specifiers deliberately leave Edge.To empty: package identity is the
// resolver's job, not the scanner's.
func (sc *scanState) recordImport(from string, imp rawImport) {
	// Bound the retained edge set: this scanner runs in-process, and a hostile repository of
	// `require("a");` lines would otherwise exhaust memory here and again inside Normalize.
	if len(sc.edges) >= sc.limits.maxEdges {
		if !sc.edgesBudgetHit {
			sc.edgesBudgetHit = true
			sc.coverage.add(modulegraph.CoverageIssue{
				Kind:   modulegraph.CoverageEdgeBudgetExceeded,
				Detail: "import edge budget exceeded; further imports were not recorded",
			})
		}
		return
	}

	specifier := strings.TrimSpace(imp.specifier)
	if specifier == "" {
		sc.coverage.add(modulegraph.CoverageIssue{
			Kind:   modulegraph.CoverageUnsupportedLoader,
			Path:   from,
			Line:   imp.position.Line,
			Detail: "empty module specifier",
		})
		return
	}

	edge := modulegraph.Edge{
		From:      from,
		Specifier: specifier,
		Kind:      imp.kind,
		Bindings:  imp.bindings,
		TypeOnly:  imp.typeOnly,
		Position:  imp.position,
	}

	// The domain classifier is the single source of truth: if the scanner called a specifier relative
	// while the resolver did not, it would set Edge.To on an edge the resolver rejects, and the resolver
	// hard-errors on the WHOLE graph. One divergent specifier would abort every scan.
	if jsresolution.ClassifySpecifier(specifier).Kind == jsresolution.SpecifierRelative {
		target, outcome := sc.resolveRelative(from, specifier)
		switch outcome {
		case relativeResolved:
			edge.To = target
		case relativeAsset:
			// A data or styling import carries no JavaScript, so it cannot hide a package import.
			// The edge is kept for provenance with no target and no coverage penalty.
		case relativeCodeCarrying:
			sc.coverage.add(modulegraph.CoverageIssue{
				Kind:   modulegraph.CoverageUnsupportedSyntax,
				Path:   from,
				Line:   imp.position.Line,
				Detail: "relative import of an unparsed single-file component",
			})
		case relativeAmbiguous:
			sc.coverage.add(modulegraph.CoverageIssue{
				Kind:   modulegraph.CoverageAmbiguousRelativeImport,
				Path:   from,
				Line:   imp.position.Line,
				Detail: "relative specifier matches more than one module",
			})
		case relativeEscapesRoot:
			sc.coverage.add(modulegraph.CoverageIssue{
				Kind:   modulegraph.CoverageRelativeImportEscapesRoot,
				Path:   from,
				Line:   imp.position.Line,
				Detail: "relative specifier escapes the scan root",
			})
		default:
			sc.coverage.add(modulegraph.CoverageIssue{
				Kind:   modulegraph.CoverageUnresolvedRelativeImport,
				Path:   from,
				Line:   imp.position.Line,
				Detail: "relative specifier did not resolve to a scanned module",
			})
		}
	}

	sc.edges = append(sc.edges, edge)
}

type relativeOutcome uint8

const (
	relativeUnresolved relativeOutcome = iota
	relativeResolved
	relativeAsset
	relativeCodeCarrying
	relativeAmbiguous
	relativeEscapesRoot
)

// resolveRelative resolves a relative specifier against the discovered file set. It is a deterministic
// subset of Node and TypeScript resolution: ordered extension candidates then directory indexes, with a
// case-only match reported as ambiguous because it resolves on a case-insensitive filesystem only.
func (sc *scanState) resolveRelative(from, specifier string) (string, relativeOutcome) {
	// Bundler-specific suffixes (`./x?raw`, `./x#frag`) are not part of the module path.
	clean := specifier
	if i := strings.IndexAny(clean, "?#"); i >= 0 {
		clean = clean[:i]
	}
	clean = strings.ReplaceAll(clean, "\\", "/")
	if clean == "" {
		return "", relativeUnresolved
	}

	base := path.Join(path.Dir(from), clean)
	if base == ".." || strings.HasPrefix(base, "../") {
		return "", relativeEscapesRoot
	}
	base = strings.TrimPrefix(path.Clean(base), "./")
	if base == "." {
		base = ""
	}

	// A specifier with an explicit asset or component extension is classified by that extension, so a
	// missing stylesheet does not look like a missing module.
	ext := strings.ToLower(path.Ext(base))
	if assetExtensions[ext] {
		return "", relativeAsset
	}
	if codeCarryingExtensions[ext] {
		return "", relativeCodeCarrying
	}

	// The candidate order is owned by the domain so this scanner and the package resolver can never
	// resolve the same specifier to different modules. Build the list once and use it for both passes.
	candidates := jsresolution.ModuleFileCandidates(base)
	for _, candidate := range candidates {
		if sc.moduleSet[candidate] {
			return candidate, relativeResolved
		}
	}

	// Exact-case resolution failed. A case-insensitive hit means the build may resolve this import on a
	// case-insensitive filesystem but not on Linux — genuinely ambiguous, never a clean negative.
	for _, candidate := range candidates {
		if _, ok := sc.lowerIndex[strings.ToLower(candidate)]; ok {
			return "", relativeAmbiguous
		}
	}

	// A directory import with no index file, or a path that exists only as an asset/component.
	if sc.assetSet[base] {
		return "", relativeAsset
	}
	if sc.codeCarryingSet[base] {
		return "", relativeCodeCarrying
	}
	return "", relativeUnresolved
}

// hasShebang reports whether a file begins with "#!", read through the confined root handle. It is a
// two-byte peek: the file is never parsed, only classified.
func (sc *scanState) hasShebang(rel string) bool {
	f, err := sc.rootDir.Open(rel)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var head [2]byte
	n, _ := io.ReadFull(f, head[:])
	return n == 2 && head[0] == '#' && head[1] == '!'
}

// directoryHasSource reports whether an excluded directory contains at least one supported source file,
// so only a directory that actually hides modules degrades coverage. The probe is bounded: an excluded
// tree may be enormous, and exhausting the budget assumes source is present rather than claiming none.
func (sc *scanState) directoryHasSource(dir string) bool {
	const probeBudget = 512
	seen := 0
	found := false
	_ = fs.WalkDir(sc.rootDir.FS(), dir, func(p string, d fs.DirEntry, err error) error {
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
		if _, ok := modulegraph.DialectForPath(p); ok {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}

// coverageSink collects coverage issues under a hard cap, reserving the last slot to report that the cap
// itself was reached — a truncated coverage list must never look like a clean scan.
type coverageSink struct {
	max       int
	collected []modulegraph.CoverageIssue
	truncated bool
}

func newCoverageSink(max int) *coverageSink {
	return &coverageSink{max: max}
}

func (c *coverageSink) add(issue modulegraph.CoverageIssue) {
	if c.truncated {
		return
	}
	if len(c.collected) >= c.max-1 {
		c.truncated = true
		c.collected = append(c.collected, modulegraph.CoverageIssue{
			Kind:   modulegraph.CoverageIssueBudgetExceeded,
			Detail: "coverage issue budget exceeded; additional issues were not recorded",
		})
		return
	}
	c.collected = append(c.collected, issue)
}

func (c *coverageSink) issues() []modulegraph.CoverageIssue {
	return append([]modulegraph.CoverageIssue(nil), c.collected...)
}

// normalizeOrEmpty normalizes a path for coverage attribution, returning "" when it cannot be
// represented as a repository-relative path (the issue is then recorded without a path).
func normalizeOrEmpty(p string) string {
	normalized, err := modulegraph.NormalizeRepositoryPath(p)
	if err != nil {
		return ""
	}
	return normalized
}
