package srcimports

import (
	"context"
	"regexp"
	"sort"
	"strings"
)

// Curated symbol-reference scanners for PHP / Ruby / .NET (EPIC #1042 3.3). Each observes FULLY-QUALIFIED
// symbol references in first-party source and returns them for symreach's raise-only tail-match against the
// curated affected symbols. They are source-only (never run composer/bundler/dotnet) and capture only what
// they can prove a qualified reference to (a namespaced static call or instantiation), omitting dynamic,
// dispatch-resolved, or unqualified references rather than guessing, which is sound because the consumer is
// raise-only (a missed reference forgoes an urgency raise; it never hides a finding).

var (
	// PHP: a namespaced static call `Vendor\Pkg\Class::method(` -> "Vendor\Pkg\Class::method"; and a
	// namespaced instantiation `new Vendor\Pkg\Class(` -> "Vendor\Pkg\Class". A leading "\" is optional.
	phpStaticCallRE = regexp.MustCompile(`\\?([A-Za-z_][A-Za-z0-9_]*(?:\\[A-Za-z_][A-Za-z0-9_]*)+)::([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	phpNewRE        = regexp.MustCompile(`\bnew\s+\\?([A-Za-z_][A-Za-z0-9_]*(?:\\[A-Za-z_][A-Za-z0-9_]*)+)\s*\(`)
	// Ruby: a qualified constant method call `Foo::Bar.method(` -> the canonical "Foo::Bar#method"
	// (symbolcanon treats "#" as the Ruby member separator, so the observed "." call is emitted in "#" form
	// to compare symmetrically with an advisory "Module::Class#method").
	rubyQualifiedCallRE = regexp.MustCompile(`([A-Z][A-Za-z0-9_]*(?:::[A-Z][A-Za-z0-9_]*)+)\.([A-Za-z_][A-Za-z0-9_]*[?!]?)`)
	// .NET: a dotted qualified call `Namespace.Type.Member(` -> "Namespace.Type.Member", and a qualified
	// instantiation `new Namespace.Type(` -> "Namespace.Type".
	dotnetQualifiedRE = regexp.MustCompile(`\b([A-Z][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){2,})\s*\(`)
	dotnetNewRE       = regexp.MustCompile(`\bnew\s+([A-Z][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\s*\(`)
)

// PHPSymbolScanner observes qualified PHP symbol references for raise-only reachability.
type PHPSymbolScanner struct{ limits scanLimits }

// NewPHPSymbolScanner returns a PHP symbol-reference scanner with the default source-walk limits.
func NewPHPSymbolScanner() *PHPSymbolScanner { return &PHPSymbolScanner{limits: defaultScanLimits()} }

// ScanSymbolRefs walks dir and returns the qualified PHP symbol references it observed.
func (s *PHPSymbolScanner) ScanSymbolRefs(ctx context.Context, dir string) ([]string, error) {
	return scanQualifiedRefs(ctx, dir, s.limits, []string{".php", ".phtml", ".inc", ".module", ".install"}, phpSkipDir, stripPHPComments, func(body string, add func(string)) {
		for _, m := range phpStaticCallRE.FindAllStringSubmatch(body, -1) {
			add(m[1] + "::" + m[2])
		}
		for _, m := range phpNewRE.FindAllStringSubmatch(body, -1) {
			add(m[1])
		}
	})
}

// RubySymbolScanner observes qualified Ruby symbol references for raise-only reachability.
type RubySymbolScanner struct{ limits scanLimits }

// NewRubySymbolScanner returns a Ruby symbol-reference scanner with the default source-walk limits.
func NewRubySymbolScanner() *RubySymbolScanner {
	return &RubySymbolScanner{limits: defaultScanLimits()}
}

// ScanSymbolRefs walks dir and returns the qualified Ruby symbol references it observed, in "#" member form.
func (s *RubySymbolScanner) ScanSymbolRefs(ctx context.Context, dir string) ([]string, error) {
	return scanRubyRefs(ctx, dir, s.limits, func(body string, add func(string)) {
		for _, m := range rubyQualifiedCallRE.FindAllStringSubmatch(body, -1) {
			if m[2] == "new" {
				add(m[1]) // Foo::Bar.new -> reference to the class Foo::Bar
				continue
			}
			add(m[1] + "#" + m[2])
		}
	})
}

// DotNetSymbolScanner observes qualified .NET symbol references for raise-only reachability.
type DotNetSymbolScanner struct{ limits scanLimits }

// NewDotNetSymbolScanner returns a .NET symbol-reference scanner with the default source-walk limits.
func NewDotNetSymbolScanner() *DotNetSymbolScanner {
	return &DotNetSymbolScanner{limits: defaultScanLimits()}
}

// ScanSymbolRefs walks dir and returns the dotted qualified .NET symbol references it observed.
func (s *DotNetSymbolScanner) ScanSymbolRefs(ctx context.Context, dir string) ([]string, error) {
	return scanQualifiedRefs(ctx, dir, s.limits, []string{".cs", ".vb", ".cshtml", ".razor"}, dotnetSkipDir, stripDotNetComments, func(body string, add func(string)) {
		for _, m := range dotnetQualifiedRE.FindAllStringSubmatch(body, -1) {
			add(m[1])
		}
		for _, m := range dotnetNewRE.FindAllStringSubmatch(body, -1) {
			add(m[1])
		}
	})
}

// scanQualifiedRefs walks source, strips comments with the supplied language stripper, and collects each
// match the emit callback adds, de-duplicated and sorted for deterministic output.
func scanQualifiedRefs(ctx context.Context, dir string, limits scanLimits, exts []string, skip map[string]bool, strip func(string) string, emit func(body string, add func(string))) ([]string, error) {
	seen := map[string]bool{}
	walker := newSourceWalker(limits, exts, skip)
	_, err := walker.walk(ctx, dir, func(_ string, content []byte, _ *scanAccumulator) {
		emit(strip(string(content)), func(ref string) {
			if ref = strings.TrimSpace(ref); ref != "" {
				seen[ref] = true
			}
		})
	})
	if err != nil {
		return nil, err
	}
	return sortedKeys(seen), nil
}

// scanRubyRefs is scanQualifiedRefs for Ruby, whose comments are "#" lines and "=begin"/"=end" blocks.
func scanRubyRefs(ctx context.Context, dir string, limits scanLimits, emit func(body string, add func(string))) ([]string, error) {
	return scanQualifiedRefs(ctx, dir, limits, []string{".rb", ".rake", ".gemspec", ".ru"}, rubySkipDir, stripRubyComments, emit)
}

// stripDotNetComments removes C-style // line and /* */ block comments.
func stripDotNetComments(body string) string {
	return stripRustBlockComments(stripLineComments(body, "//"))
}

// stripPHPComments removes PHP's // and # line comments and /* */ block comments. A # to end-of-line is a
// PHP comment; a PHP 8 attribute "#[" is preserved (it is not a comment and may name a referenced class).
func stripPHPComments(body string) string {
	body = stripRustBlockComments(stripLineComments(body, "//"))
	var b strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 && !strings.HasPrefix(line[i:], "#[") {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// stripRubyComments removes Ruby "#" line comments and "=begin"/"=end" block comments (each anchored at the
// start of a line). It runs the block strip first so a "#" inside a =begin block is not mis-handled.
func stripRubyComments(body string) string {
	var b strings.Builder
	inBlock := false
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if inBlock {
			if strings.HasPrefix(trimmed, "=end") {
				inBlock = false
			}
			b.WriteByte('\n')
			continue
		}
		if strings.HasPrefix(trimmed, "=begin") {
			inBlock = true
			b.WriteByte('\n')
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return stripLineComments(b.String(), "#")
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
