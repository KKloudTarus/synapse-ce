package srcimports

import (
	"context"
	"regexp"
)

// C/C++ curated symbol-reference scanner (EPIC #1042 4.1), the SOURCE track of C/C++ reachability. It
// observes FULLY-QUALIFIED (namespace/class-scoped) symbol references in first-party C/C++ source and returns
// them for symreach's raise-only tail-match against the curated affected symbols. It is source-only (no
// build, no DWARF) and captures only what it can prove a qualified reference to (a `ns::Class::method(` call
// or a `new ns::Class(` instantiation), omitting macros, function pointers, dlopen/dlsym, and unqualified or
// member (`.`/`->`) calls rather than guessing. That is sound because the consumer is RAISE-ONLY: a missed
// reference forgoes an urgency raise, it never hides a finding, and the C/C++ proof actors are excluded from
// the deterministic-reachability set so a verdict here can never become a VEX not_affected.
var (
	// A scope-qualified call `ns::Class::method(` or `ns::func(` (>=2 `::` segments), tolerating an optional
	// template argument list before the paren (`ns::func<int>(`). The template args are bounded by
	// [^;{}()] so a `<` comparison operator cannot be swallowed across a statement.
	cppQualifiedCallRE = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+)\s*(?:<[^;{}()]*>)?\s*\(`)
	// A scope-qualified instantiation `new ns::Class` (paren- or brace-initialized), captured by name.
	cppNewRE = regexp.MustCompile(`\bnew\s+([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+)`)
)

// cppSkipDir are build-output, dependency, and tooling directories that hold no first-party source.
var cppSkipDir = map[string]bool{
	"build": true, "_build": true, "out": true, "cmake-build-debug": true, "cmake-build-release": true,
	"CMakeFiles": true, ".deps": true, "third_party": true, "3rdparty": true, "extern": true,
	"vendor": true, "node_modules": true, ".git": true, ".idea": true, ".vs": true,
}

// CppSymbolScanner observes qualified C/C++ symbol references for raise-only reachability.
type CppSymbolScanner struct{ limits scanLimits }

// NewCppSymbolScanner returns a C/C++ symbol-reference scanner with the default source-walk limits.
func NewCppSymbolScanner() *CppSymbolScanner { return &CppSymbolScanner{limits: defaultScanLimits()} }

// ScanSymbolRefs walks dir and returns the scope-qualified C/C++ symbol references it observed.
func (s *CppSymbolScanner) ScanSymbolRefs(ctx context.Context, dir string) ([]string, error) {
	exts := []string{".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".h++", ".ipp", ".inl", ".tcc"}
	return scanQualifiedRefs(ctx, dir, s.limits, exts, cppSkipDir, stripCppComments, func(body string, add func(string)) {
		for _, m := range cppQualifiedCallRE.FindAllStringSubmatch(body, -1) {
			add(m[1])
		}
		for _, m := range cppNewRE.FindAllStringSubmatch(body, -1) {
			add(m[1])
		}
	})
}

// stripCppComments removes C/C++ `//` line and `/* */` block comments (identical grammar to .NET/C#).
func stripCppComments(body string) string {
	return stripRustBlockComments(stripLineComments(body, "//"))
}
