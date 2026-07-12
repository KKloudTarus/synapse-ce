// Package pyimports is a SOURCE-ONLY Python import scanner: it reads a target's first-party .py files and
// extracts the top-level modules they import, plus whether the code uses dynamic imports. It never compiles
// or executes the target (unlike the sandboxed go/ssa call-graph builder), so — like the pure-Go lockfile
// parsers — it runs in-process. It is the evidence source for Tier-1 Python import-reachability
// (dead-dependency detection): a declared PyPI package that first-party code never imports is not reachable.
//
// SAFETY BIAS: a missed import would wrongly conclude "not imported" (which can suppress a real vuln via
// OpenVEX), so the scanner ERRS TOWARD OVER-COUNTING imports — an occasional false import only yields a
// (safe) "reachable". Dynamic imports (importlib/__import__) are reported so the analyzer can refuse a
// not-reachable conclusion entirely. The walk is bounded and skips vendored/virtualenv trees so installed
// third-party source never pollutes the first-party import set.
package pyimports

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Scanner implements ports.PyImportScanner.
type Scanner struct {
	maxFiles   int
	maxFileLen int64
}

var _ ports.PyImportScanner = (*Scanner)(nil)

// New returns a scanner with bounded limits (a hostile/huge tree cannot exhaust memory or time).
func New() *Scanner { return &Scanner{maxFiles: 20000, maxFileLen: 1 << 20} }

// skipDir names directory trees that hold vendored / installed / generated code, NOT first-party source.
// Scanning them would pollute the first-party import set (masking a dead dependency) and waste the budget.
var skipDir = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true, "__pycache__": true,
	"venv": true, ".venv": true, "env": true, ".env": true, "virtualenv": true,
	"site-packages": true, ".tox": true, ".nox": true, "build": true, "dist": true,
	".mypy_cache": true, ".pytest_cache": true, ".eggs": true, "eggs": true,
}

// importRE matches an `import a.b, c as d` statement, capturing the module list after `import`.
var importRE = regexp.MustCompile(`^\s*import\s+(.+)$`)

// fromRE matches a `from a.b.c import ...` statement, capturing the (possibly dotted/relative) module.
var fromRE = regexp.MustCompile(`^\s*from\s+(\.*[A-Za-z0-9_.]*)\s+import\b`)

// dynamicRE matches dynamic-import mechanisms under which a package can be loaded with NO static import
// statement — making a "not imported" conclusion unsafe. It fails SAFE by over-matching: any hit makes the
// analyzer refuse a verdict (the prior tier stands), which is always the correct bias. It therefore matches
// the mechanisms broadly, not just three literal spellings: __import__, importlib (incl. a bare
// `import_module(` call after `from importlib import import_module`), imp.load*, runpy, pkgutil, and
// exec()/eval() of code (which can carry imports).
var dynamicRE = regexp.MustCompile(`__import__|\bimportlib\b|\bimport_module\s*\(|\bimp\.load|\brunpy\b|\bpkgutil\b|\bexec\s*\(|\beval\s*\(`)

// ScanImports walks dir's first-party .py files and returns the import surface. Returns a no-coverage error
// when the target has no Python source (so a caller never treats a non-Python project as "nothing imported").
func (s *Scanner) ScanImports(ctx context.Context, dir string) (ports.PyImportGraph, error) {
	if strings.TrimSpace(dir) == "" {
		return ports.PyImportGraph{}, fmt.Errorf("%w: scan dir is required", shared.ErrValidation)
	}
	imported := map[string]bool{}
	firstParty := map[string]bool{}
	dynamic := false
	files := 0

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable entries; never abort the whole walk
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if path != dir && (skipDir[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 || !strings.HasSuffix(d.Name(), ".py") {
			return nil // don't follow symlinks (escape guard); only .py
		}
		if files >= s.maxFiles {
			return fs.SkipAll
		}
		files++
		// The file's own module path (pkg/sub/mod.py → top-level "pkg") marks first-party roots.
		if rel, rerr := filepath.Rel(dir, path); rerr == nil {
			if top := topLevelOfPath(rel); top != "" {
				firstParty[top] = true
			}
		}
		scanFile(path, s.maxFileLen, imported, &dynamic)
		return nil
	})
	if err != nil {
		return ports.PyImportGraph{}, fmt.Errorf("scan python imports: %w", err)
	}
	if files == 0 {
		return ports.PyImportGraph{}, fmt.Errorf("%w: no python source under target (no coverage)", shared.ErrNotFound)
	}
	return ports.PyImportGraph{
		ImportedModules:   sortedKeys(imported),
		FirstPartyModules: sortedKeys(firstParty),
		DynamicImports:    dynamic,
		FilesScanned:      files,
	}, nil
}

// scanFile line-scans one .py file, adding top-level imported module names to imported and flipping dynamic
// when a dynamic-import mechanism appears. It JOINS backslash line-continuations and SPLITS compound
// statements on ";" so `import a, \<newline> b` and `import a; import b` are both fully counted — a MISSED
// import is the dangerous direction (it can yield a false "not imported"). Best-effort: an unreadable file
// is skipped (never a hard error).
func scanFile(path string, maxLen int64, imported map[string]bool, dynamic *bool) {
	f, err := os.Open(path) //nolint:gosec // path from a bounded first-party walk under the scan root
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var read int64
	var cont string // accumulates a backslash-continued logical line
	process := func(logical string) {
		for _, stmt := range strings.Split(logical, ";") { // compound statements: import a; import b
			scanStmt(stmt, imported, dynamic)
		}
	}
	for sc.Scan() {
		line := sc.Text()
		read += int64(len(line)) + 1
		if read > maxLen {
			break // bound per-file work
		}
		joined := cont + line
		if t := strings.TrimRight(joined, " \t"); strings.HasSuffix(t, "\\") {
			cont = strings.TrimSuffix(t, "\\") + " " // continuation → accumulate, defer processing
			continue
		}
		cont = ""
		process(joined)
	}
	if cont != "" {
		process(cont) // a trailing dangling continuation
	}
}

// scanStmt extracts the top-level imported modules from ONE statement (already split off a logical line)
// and flips dynamic on a dynamic-import mechanism. Comment content is stripped first so a `# importlib`
// note doesn't force a (safe but noisy) refusal and an inline `# comment` never pollutes a module name.
func scanStmt(stmt string, imported map[string]bool, dynamic *bool) {
	stmt = stripComment(stmt)
	trimmed := strings.TrimSpace(stmt)
	if trimmed == "" {
		return
	}
	if dynamicRE.MatchString(stmt) {
		*dynamic = true
	}
	if m := fromRE.FindStringSubmatch(stmt); m != nil {
		if top := topLevelOfModule(m[1]); top != "" {
			imported[top] = true
		}
		return
	}
	if m := importRE.FindStringSubmatch(stmt); m != nil {
		for _, part := range strings.Split(m[1], ",") {
			part = strings.TrimSpace(part)
			if i := strings.Index(part, " as "); i >= 0 {
				part = part[:i] // drop an `as alias`
			}
			if top := topLevelOfModule(strings.TrimSpace(part)); top != "" {
				imported[top] = true
			}
		}
	}
}

// stripComment removes a trailing `# ...` comment. Heuristic (a "#" inside a string literal cuts early),
// but that only ever REMOVES text from an import/dynamic check, and import statements never carry a
// meaningful "#" before the module list, so it cannot cause a missed import.
func stripComment(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		return s[:i]
	}
	return s
}

// topLevelOfModule returns the top-level package of a (possibly dotted) module name, or "" for a relative
// import (leading dot — first-party, not a distribution) or an empty/invalid token.
func topLevelOfModule(mod string) string {
	mod = strings.TrimSpace(mod)
	if mod == "" || strings.HasPrefix(mod, ".") {
		return "" // relative import → first-party, never a third-party distribution
	}
	top := mod
	if i := strings.IndexByte(top, '.'); i >= 0 {
		top = top[:i]
	}
	if !isIdent(top) {
		return ""
	}
	return top
}

// topLevelOfPath returns the top-level package/module name a first-party .py file's relative path implies.
func topLevelOfPath(rel string) string {
	rel = filepath.ToSlash(rel)
	first := rel
	if i := strings.IndexByte(first, '/'); i >= 0 {
		first = first[:i] // package dir
	} else {
		first = strings.TrimSuffix(first, ".py") // top-level module file
	}
	if !isIdent(first) {
		return ""
	}
	return first
}

// isIdent reports whether s is a plausible Python identifier (defensive against parse noise).
func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
