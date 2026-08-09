package srcimports

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// PHPScanner observes namespace and file references in first-party PHP source.
type PHPScanner struct{ limits scanLimits }

var _ ports.SourceImportScanner = (*PHPScanner)(nil)

// NewPHPScanner returns a scanner with production bounds.
func NewPHPScanner() *PHPScanner { return &PHPScanner{limits: defaultScanLimits()} }

// Lang reports the package-URL type this scanner observes.
func (PHPScanner) Lang() string { return "composer" }

// phpDynamic are constructs under which a package can be reached without a visible `use`: PHP resolves
// class and function names at runtime from strings, and an include path can be computed.
var phpDynamic = []dynamicConstruct{
	{marker: "eval(", reason: "eval executes code this scan cannot observe"},
	{marker: "call_user_func", reason: "call_user_func resolves a callable from a runtime value"},
	{marker: "class_exists(", reason: "class_exists resolves a class name from a runtime value"},
	{marker: "new $", reason: "a variable class name is resolved at runtime"},
	{marker: "$$", reason: "a variable variable is resolved at runtime"},
	{marker: "spl_autoload_register", reason: "a custom autoloader can load unobserved classes"},
	{marker: "ReflectionClass", reason: "reflection resolves a class name from a runtime value"},
}

// ScanImports walks dir and returns the package references it can observe.
func (s *PHPScanner) ScanImports(ctx context.Context, dir string) (ports.SourceImportGraph, error) {
	walker := newSourceWalker(s.limits, []string{".php"}, phpSkipDir)
	scan, err := walker.walk(ctx, dir, func(path string, content []byte, out *scanAccumulator) {
		body := stripLineComments(stripLineComments(string(content), "//"), "#")
		for _, name := range phpNamespaceRoots(body) {
			out.addPackage(name)
		}
		// A computed include path can pull in any file, so it hides references.
		if phpHasComputedInclude(body) {
			out.addReason("an include or require path is computed at runtime (" + path + ")")
		}
		out.noteDynamic(body, phpDynamic, path)
	})
	if err != nil {
		return ports.SourceImportGraph{}, err
	}
	scan.entrypoints = append(scan.entrypoints, composerEntrypoints(ctx, dir, s.limits)...)
	return scan.graph(), nil
}

var phpSkipDir = map[string]bool{
	"vendor": true, "node_modules": true, ".git": true, ".hg": true, ".svn": true,
	"var": true, "cache": true,
}

// phpNamespaceRoots extracts the vendor segment of each `use` statement.
//
// A Composer package's name ("monolog/monolog") is not its namespace ("Monolog"), so this returns the
// namespace ROOT and the candidate namer expands a package name into the forms that may match it.
func phpNamespaceRoots(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "use ") {
			continue
		}
		rest := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(trimmed, "use ")), ";")
		// `use function Foo\bar;` and `use const Foo\BAR;` still name the same root namespace.
		rest = strings.TrimPrefix(rest, "function ")
		rest = strings.TrimPrefix(rest, "const ")
		rest = strings.TrimPrefix(strings.TrimSpace(rest), "\\")
		if i := strings.Index(rest, " as "); i >= 0 {
			rest = rest[:i]
		}
		root := rest
		if i := strings.Index(root, "\\"); i >= 0 {
			root = root[:i]
		}
		root = strings.TrimSpace(strings.Trim(root, "{},"))
		if root != "" {
			out = append(out, root)
		}
	}
	return out
}

// phpHasComputedInclude reports an include/require whose argument is not a literal.
func phpHasComputedInclude(body string) bool {
	for _, keyword := range []string{"include", "include_once", "require", "require_once"} {
		idx := 0
		for {
			i := strings.Index(body[idx:], keyword)
			if i < 0 {
				break
			}
			pos := idx + i + len(keyword)
			idx = pos
			rest := strings.TrimLeft(body[pos:], " \t(")
			if rest == "" {
				continue
			}
			// A literal path starts with a quote; anything else is computed.
			if rest[0] != '\'' && rest[0] != '"' {
				return true
			}
		}
	}
	return false
}

// composerEntrypoints reads the autoload roots a composer.json declares, which are the entrypoints a
// reader can check a proof against.
func composerEntrypoints(ctx context.Context, dir string, limits scanLimits) []string {
	content, ok := readBoundedFile(ctx, dir, "composer.json", limits.maxFileBytes)
	if !ok {
		return nil
	}
	var manifest struct {
		Autoload struct {
			PSR4  map[string]json.RawMessage `json:"psr-4"`
			PSR0  map[string]json.RawMessage `json:"psr-0"`
			Files []string                   `json:"files"`
		} `json:"autoload"`
	}
	if json.Unmarshal(content, &manifest) != nil {
		return nil
	}
	var out []string
	for namespace := range manifest.Autoload.PSR4 {
		out = append(out, strings.TrimSuffix(namespace, "\\"))
	}
	for namespace := range manifest.Autoload.PSR0 {
		out = append(out, strings.TrimSuffix(namespace, "\\"))
	}
	out = append(out, manifest.Autoload.Files...)
	return out
}

// PHPCandidates expands a Composer package name into the namespace forms PHP source may reference it by.
// "monolog/monolog" is commonly used as `Monolog\...`, and a vendor prefix such as "symfony/console"
// appears as `Symfony\Component\Console`, so both the vendor and the package segment are candidates.
func PHPCandidates(packageName string) []string {
	name := strings.ToLower(strings.TrimSpace(packageName))
	candidates := []string{name}
	if vendor, pkg, ok := strings.Cut(name, "/"); ok {
		candidates = append(candidates, vendor, pkg,
			strings.ReplaceAll(pkg, "-", ""), strings.ReplaceAll(vendor, "-", ""),
			strings.ReplaceAll(pkg, "-", "_"))
	}
	return normalizeNames(candidates)
}
