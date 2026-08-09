// Package srcimports implements source-only first-party import scanners for languages whose dependency
// usage is observable as an import/require/use statement (Rust, PHP, Ruby).
//
// Every scanner here reads and lexes text only. None executes project code, a package manager, a build
// system or a language runtime, and none touches the network — so, like the Python and JavaScript
// scanners, they run in-process rather than inside the sandbox that confines toolchains which compile
// untrusted source.
//
// The load-bearing rule is that a construct which could reference a dependency INVISIBLY must be recorded
// as a coverage reason rather than ignored. A missed reference becomes a false "unreachable", and an
// unreachable verdict suppresses work.
package srcimports

import (
	"context"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// RustScanner observes crate references in first-party Rust source.
type RustScanner struct{ limits scanLimits }

var _ ports.SourceImportScanner = (*RustScanner)(nil)

// NewRustScanner returns a scanner with production bounds.
func NewRustScanner() *RustScanner { return &RustScanner{limits: defaultScanLimits()} }

// Lang reports the package-URL type this scanner observes.
func (RustScanner) Lang() string { return "cargo" }

// rustDynamic are constructs under which a crate can be referenced without a visible `use`: a macro can
// expand to arbitrary paths, and a build script or FFI can pull in code this scan never sees.
var rustDynamic = []dynamicConstruct{
	{marker: "macro_rules!", reason: "macro definition can expand to unobserved crate paths"},
	{marker: "include!", reason: "include! splices unobserved source"},
	{marker: "include_str!", reason: "include_str! splices unobserved content"},
	{marker: "include_bytes!", reason: "include_bytes! splices unobserved content"},
	{marker: "proc_macro", reason: "procedural macro can generate unobserved crate paths"},
	{marker: "#[derive(", reason: "derive macro can generate unobserved crate paths"},
	{marker: "extern \"C\"", reason: "foreign function interface reaches code this scan cannot observe"},
}

// ScanImports walks dir and returns the crate references it can observe.
func (s *RustScanner) ScanImports(ctx context.Context, dir string) (ports.SourceImportGraph, error) {
	walker := newSourceWalker(s.limits, []string{".rs"}, rustSkipDir)
	scan, err := walker.walk(ctx, dir, func(path string, content []byte, out *scanAccumulator) {
		raw := string(content)
		body := stripLineComments(raw, "//")
		for _, name := range rustCrateReferences(body) {
			out.addPackage(name)
		}
		// Inline paths (serde_json::from_str(...)) and attribute macros (#[tokio::main]) reference a
		// crate with no `use` at all, so they are read from the stripped body too.
		for _, name := range rustInlinePathRoots(body) {
			out.addPackage(name)
		}
		// Detected on the RAW body: over-stripping must never be able to delete an unknown region.
		out.noteDynamic(raw, rustDynamic, path)
	})
	if err != nil {
		return ports.SourceImportGraph{}, err
	}
	// Cargo manifests declare the binary and library targets, which are the entrypoints a reader can
	// check a proof against. Their absence is provenance, not a coverage failure.
	scan.entrypoints = append(scan.entrypoints, cargoTargets(ctx, dir, s.limits)...)
	return scan.graph(), nil
}

var rustSkipDir = map[string]bool{
	"target": true, "vendor": true, ".git": true, ".hg": true, ".svn": true,
}

// rustCrateReferences extracts crate names from `use` and `extern crate` statements.
//
// A `use` path's first segment is the crate, except for the keywords that address the current crate or an
// enclosing module. Rust normalizes a hyphenated crate name to underscores in source, so the caller's
// candidate namer must expand both forms.
func rustCrateReferences(body string) []string {
	var out []string
	// Statements, not lines: a `use` group may span lines and two statements may share one line.
	for _, statement := range splitRustStatements(body) {
		trimmed := strings.TrimSpace(statement)
		trimmed = strings.TrimPrefix(trimmed, "pub ")
		// `#[macro_use] extern crate x;` puts the attribute on the same line.
		if i := strings.Index(trimmed, "extern crate "); i >= 0 {
			name := strings.TrimSpace(trimmed[i+len("extern crate "):])
			if root := rustIdentifier(name); root != "" {
				out = append(out, root)
			}
			continue
		}
		if strings.HasPrefix(trimmed, "use ") {
			out = append(out, rustUseRoot(strings.TrimPrefix(trimmed, "use "))...)
		}
	}
	return out
}

// splitRustStatements splits a body on semicolons that are not inside a brace group, so a multi-line
// `use { ... };` stays one statement and `use a::X; use b::Y;` becomes two.
func splitRustStatements(body string) []string {
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 {
				out = append(out, body[start:i])
				start = i + 1
			}
		}
	}
	if start < len(body) {
		out = append(out, body[start:])
	}
	return out
}

// rustUseRoot returns the crate roots named by one `use` statement, including every branch of a grouped
// import like `use {serde, tokio::net};`.
func rustUseRoot(rest string) []string {
	rest = strings.TrimSuffix(strings.TrimSpace(rest), ";")
	if rest == "" {
		return nil
	}
	// A grouped import at the root names several crates.
	if strings.HasPrefix(rest, "{") {
		inner := strings.TrimSuffix(strings.TrimPrefix(rest, "{"), "}")
		var out []string
		for _, part := range strings.Split(inner, ",") {
			out = append(out, rustUseRoot(part)...)
		}
		return out
	}
	// A leading "::" addresses the crate root: `use ::serde_json::Value;`.
	rest = strings.TrimPrefix(rest, "::")
	head := rest
	if i := strings.Index(head, "::"); i >= 0 {
		head = head[:i]
	}
	root := rustIdentifier(head)
	switch root {
	case "", "crate", "self", "super", "std", "core", "alloc":
		// These address the current crate or the language's own libraries, not a dependency.
		return nil
	}
	return []string{root}
}

// rustIdentifier keeps the leading identifier of a token, dropping aliases and punctuation.
func rustIdentifier(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if i := strings.Index(trimmed, " as "); i >= 0 {
		trimmed = trimmed[:i]
	}
	var sb strings.Builder
	for _, r := range strings.TrimSpace(trimmed) {
		if r == '_' || r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
			continue
		}
		break
	}
	return sb.String()
}

// cargoTargets reads the binary and library target names a Cargo manifest declares. Test and bench
// targets are deliberately excluded: a dependency used only by tests is not evidence that shipped code
// reaches it.
func cargoTargets(ctx context.Context, dir string, limits scanLimits) []string {
	content, ok := readBoundedFile(ctx, dir, "Cargo.toml", limits.maxFileBytes)
	if !ok {
		return nil
	}
	var out []string
	var section string
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			section = strings.Trim(trimmed, "[]")
			continue
		}
		if section != "[bin" && section != "bin" && section != "lib" && section != "package" {
			continue
		}
		if name, ok := tomlStringValue(trimmed, "name"); ok {
			out = append(out, name)
		}
	}
	return out
}

// tomlStringValue extracts `key = "value"` from a manifest line.
func tomlStringValue(line, key string) (string, bool) {
	if !strings.HasPrefix(line, key) {
		return "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, key))
	if !strings.HasPrefix(rest, "=") {
		return "", false
	}
	value := strings.TrimSpace(strings.TrimPrefix(rest, "="))
	if len(value) < 2 || value[0] != '"' {
		return "", false
	}
	value = value[1:]
	if i := strings.IndexByte(value, '"'); i >= 0 {
		return value[:i], true
	}
	return "", false
}

// RustCandidates expands a crate name into the forms Rust source may reference it by: Cargo allows
// hyphens in a crate name, but source must write underscores.
func RustCandidates(packageName string) []string {
	name := strings.ToLower(strings.TrimSpace(packageName))
	return normalizeNames([]string{name, strings.ReplaceAll(name, "-", "_"), strings.ReplaceAll(name, "_", "-")})
}

// rustInlinePathRoots finds crate roots referenced by a fully-qualified inline path
// (`serde_json::from_str(...)`) or an attribute macro (`#[tokio::main]`).
//
// Rust 2018 needs no `use` for either, so reading only `use` lines would report a crate that the code
// demonstrably calls as unreferenced. Over-matching here is the safe direction: a local module path
// simply adds a name that no dependency subject will match.
func rustInlinePathRoots(body string) []string {
	var out []string
	for i := 0; i+2 < len(body); i++ {
		if body[i] != ':' || body[i+1] != ':' {
			continue
		}
		// Walk back over the identifier preceding "::".
		end := i
		start := end
		for start > 0 && isRustIdentByte(body[start-1]) {
			start--
		}
		if start == end {
			continue
		}
		// A path segment preceded by "::" is not the root of the path.
		if start >= 2 && body[start-2] == ':' && body[start-1] == ':' {
			continue
		}
		root := body[start:end]
		switch root {
		case "crate", "self", "super", "std", "core", "alloc", "Self":
			continue
		}
		if root != "" && !startsUpper(root) {
			out = append(out, root)
		}
	}
	return out
}

func isRustIdentByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// startsUpper reports an identifier in type position (a type or enum name), which is never a crate root.
func startsUpper(s string) bool { return s != "" && s[0] >= 'A' && s[0] <= 'Z' }
