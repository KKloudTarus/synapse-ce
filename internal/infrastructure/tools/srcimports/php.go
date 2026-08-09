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
	{marker: "eval", reason: "eval executes code this scan cannot observe"},
	{marker: "call_user_func", reason: "call_user_func resolves a callable from a runtime value"},
	{marker: "class_exists", reason: "class_exists resolves a class name from a runtime value"},
	{marker: "new $", reason: "a variable class name is resolved at runtime"},
	{marker: "$$", reason: "a variable variable is resolved at runtime"},
	{marker: "spl_autoload_register", reason: "a custom autoloader can load unobserved classes"},
	{marker: "Reflection", reason: "reflection resolves a class or method name from a runtime value"},
	{marker: "is_callable", reason: "is_callable resolves a callable from a runtime value"},
	{marker: "->make(", reason: "a service container resolves a class name from a runtime value"},
}

// ScanImports walks dir and returns the package references it can observe.
func (s *PHPScanner) ScanImports(ctx context.Context, dir string) (ports.SourceImportGraph, error) {
	// Templates and legacy include files are PHP too, and each can reference a package.
	walker := newSourceWalker(s.limits, []string{".php", ".phtml", ".inc", ".module", ".install"}, phpSkipDir)
	scan, err := walker.walk(ctx, dir, func(path string, content []byte, out *scanAccumulator) {
		raw := string(content)
		// `#[` opens a PHP 8 ATTRIBUTE, not a comment; stripping it would delete real code and hide the
		// fully-qualified class names modern Doctrine and Symfony write there.
		body := stripLineComments(raw, "//")
		for _, name := range phpNamespaceRoots(body) {
			out.addPackage(name)
		}
		// PHP does not require a `use`: an inline \Vendor\Class reference is just as real.
		for _, name := range phpInlineNamespaceRoots(body) {
			out.addPackage(name)
		}
		// Detected on the RAW body: over-stripping must never be able to delete an unknown region.
		if phpHasComputedInclude(raw) {
			out.addReason("an include or require path is computed at runtime (" + path + ")")
		}
		out.noteDynamic(raw, phpDynamic, path)
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
	// Longest first, so include_once is not matched as include.
	for _, keyword := range []string{"include_once", "require_once", "include", "require"} {
		idx := 0
		for {
			i := strings.Index(body[idx:], keyword)
			if i < 0 {
				break
			}
			pos := idx + i
			idx = pos + len(keyword)
			// The keyword must stand alone. Without this, $includePath, includeTemplate() and the
			// Laravel validation string 'required|email' all read as a computed include, which makes
			// every PHP project refuse for a reason that is not true.
			if pos > 0 && isPHPIdentByte(body[pos-1]) {
				continue
			}
			after := pos + len(keyword)
			if after < len(body) && isPHPIdentByte(body[after]) {
				continue
			}
			rest := strings.TrimLeft(body[after:], " \t(")
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

// phpInlineNamespaceRoots finds vendor namespace roots referenced without a `use`, either fully
// qualified (`new \Monolog\Logger(...)`, `\Ramsey\Uuid\Uuid::uuid4()`) or in an attribute
// (`#[\Doctrine\ORM\Mapping\Entity]`). PHP requires no import for any of these, so reading only `use`
// lines would report a package the code demonstrably instantiates as unreferenced.
func phpInlineNamespaceRoots(body string) []string {
	var out []string
	for i := 0; i < len(body); i++ {
		if body[i] != '\\' {
			continue
		}
		// The root must be preceded by something that can start an expression, so a namespace
		// continuation (Foo\Bar) does not register Bar as a root.
		if i > 0 && isPHPIdentByte(body[i-1]) {
			continue
		}
		j := i + 1
		start := j
		for j < len(body) && isPHPIdentByte(body[j]) {
			j++
		}
		if j == start || j >= len(body) || body[j] != '\\' {
			continue // a single leading-slash name is a global function or class, not a vendor root
		}
		out = append(out, body[start:j])
		i = j
	}
	return out
}

func isPHPIdentByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
