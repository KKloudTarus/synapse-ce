package srcimports

import (
	"context"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// RubyScanner observes gem references in first-party Ruby source.
type RubyScanner struct{ limits scanLimits }

var _ ports.SourceImportScanner = (*RubyScanner)(nil)

// NewRubyScanner returns a scanner with production bounds.
func NewRubyScanner() *RubyScanner { return &RubyScanner{limits: defaultScanLimits()} }

// Lang reports the package-URL type this scanner observes.
func (RubyScanner) Lang() string { return "gem" }

// rubyDynamic are constructs under which a gem can be reached without a visible `require`: Ruby resolves
// constants and methods from strings and rewrites itself at runtime.
var rubyDynamic = []dynamicConstruct{
	{marker: "const_get", reason: "const_get resolves a constant from a runtime value"},
	{marker: ".send(", reason: "send dispatches a method named by a runtime value"},
	{marker: "public_send", reason: "public_send dispatches a method named by a runtime value"},
	{marker: "method_missing", reason: "method_missing handles calls this scan cannot observe"},
	{marker: "define_method", reason: "define_method creates methods at runtime"},
	{marker: "instance_eval", reason: "instance_eval executes code this scan cannot observe"},
	{marker: "class_eval", reason: "class_eval executes code this scan cannot observe"},
	{marker: "eval(", reason: "eval executes code this scan cannot observe"},
	{marker: "autoload", reason: "autoload defers loading to a runtime constant reference"},
	{marker: "Kernel.load", reason: "load reads a path resolved at runtime"},
}

// ScanImports walks dir and returns the gem references it can observe.
func (s *RubyScanner) ScanImports(ctx context.Context, dir string) (ports.SourceImportGraph, error) {
	walker := newSourceWalker(s.limits, []string{".rb", ".rake", ".gemspec"}, rubySkipDir)
	scan, err := walker.walk(ctx, dir, func(path string, content []byte, out *scanAccumulator) {
		body := stripLineComments(string(content), "#")
		for _, name := range rubyRequireRoots(body) {
			out.addPackage(name)
		}
		if rubyHasComputedRequire(body) {
			out.addReason("a require path is computed at runtime (" + path + ")")
		}
		out.noteDynamic(body, rubyDynamic, path)
	})
	if err != nil {
		return ports.SourceImportGraph{}, err
	}
	scan.entrypoints = append(scan.entrypoints, rubyEntrypoints(ctx, dir, s.limits)...)
	return scan.graph(), nil
}

var rubySkipDir = map[string]bool{
	"vendor": true, "node_modules": true, ".git": true, ".hg": true, ".svn": true,
	"tmp": true, "log": true, "coverage": true,
}

// rubyRequireRoots extracts the first path segment of each literal `require`.
//
// `require_relative` is deliberately excluded: it always names a first-party file, never a gem. A gem's
// require path often differs from its gem name ("rest-client" is required as "rest_client"), so the
// candidate namer expands both forms.
func rubyRequireRoots(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "require ") && !strings.HasPrefix(trimmed, "require(") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(trimmed, "require"), "("))
		if rest == "" {
			continue
		}
		quote := rest[0]
		if quote != '\'' && quote != '"' {
			continue // computed; recorded separately as a coverage reason
		}
		rest = rest[1:]
		end := strings.IndexByte(rest, quote)
		if end < 0 {
			continue
		}
		requirePath := rest[:end]
		root := requirePath
		if i := strings.IndexByte(root, '/'); i >= 0 {
			root = root[:i]
		}
		if root != "" {
			out = append(out, root)
		}
	}
	return out
}

// rubyHasComputedRequire reports a `require` whose argument is not a string literal.
func rubyHasComputedRequire(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "require ") && !strings.HasPrefix(trimmed, "require(") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(trimmed, "require"), "("))
		if rest == "" {
			continue
		}
		if rest[0] != '\'' && rest[0] != '"' {
			return true
		}
		// String interpolation makes the path dynamic even inside quotes.
		if rest[0] == '"' && strings.Contains(rest, "#{") {
			return true
		}
	}
	return false
}

// rubyEntrypoints records the conventional load points a reader can check a proof against.
func rubyEntrypoints(ctx context.Context, dir string, limits scanLimits) []string {
	var out []string
	for _, name := range []string{"Gemfile", "config.ru", "Rakefile"} {
		if _, ok := readBoundedFile(ctx, dir, name, limits.maxFileBytes); ok {
			out = append(out, name)
		}
	}
	return out
}

// RubyCandidates expands a gem name into the forms a `require` may use: a gem's require path commonly
// replaces hyphens with underscores, and a namespaced gem is required by its first segment.
func RubyCandidates(packageName string) []string {
	name := strings.ToLower(strings.TrimSpace(packageName))
	candidates := []string{
		name,
		strings.ReplaceAll(name, "-", "_"),
		strings.ReplaceAll(name, "_", "-"),
		strings.ReplaceAll(name, "-", "/"),
	}
	if head, _, ok := strings.Cut(name, "-"); ok {
		candidates = append(candidates, head)
	}
	return normalizeNames(candidates)
}
