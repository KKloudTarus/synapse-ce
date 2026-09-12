package srcimports

import (
	"context"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// RustSymbolScanner observes symbol-level references in first-party Rust source. It reuses the bounded,
// confined source walker; it is SOURCE-ONLY (never runs cargo) and case-preserving (Rust symbols are
// case-sensitive). It is used only for RAISE-ONLY reachability, so it captures what it can prove a
// reference to (qualified paths and use-resolved calls) and simply omits what it cannot (method calls,
// macro-hidden references) rather than guessing.
type RustSymbolScanner struct{ limits scanLimits }

// NewRustSymbolScanner returns a symbol-reference scanner with the default source-walk limits.
func NewRustSymbolScanner() *RustSymbolScanner {
	return &RustSymbolScanner{limits: defaultScanLimits()}
}

// ScanSymbols walks dir and returns the symbol references it observed across every .rs file.
func (s *RustSymbolScanner) ScanSymbols(ctx context.Context, dir string) (ports.RustSymbolIndex, error) {
	idx := ports.RustSymbolIndex{Uses: map[string]string{}, Called: map[string]bool{}}
	qualified := map[string]bool{}
	walker := newSourceWalker(s.limits, []string{".rs"}, rustSkipDir)
	_, err := walker.walk(ctx, dir, func(_ string, content []byte, _ *scanAccumulator) {
		body := stripLineComments(string(content), "//")
		for _, st := range splitRustStatements(body) {
			trimmed := strings.TrimPrefix(strings.TrimSpace(st), "pub ")
			if strings.HasPrefix(trimmed, "use ") {
				collectRustUseBindings(strings.TrimPrefix(trimmed, "use "), "", idx.Uses)
			}
		}
		for _, p := range rustQualifiedPaths(body) {
			qualified[p] = true
		}
		for name := range rustCallNames(body) {
			idx.Called[name] = true
		}
	})
	if err != nil {
		return ports.RustSymbolIndex{}, err
	}
	idx.Qualified = make([]string, 0, len(qualified))
	for p := range qualified {
		idx.Qualified = append(idx.Qualified, p)
	}
	sort.Strings(idx.Qualified)
	return idx, nil
}

// collectRustUseBindings resolves one `use` statement into leaf/alias -> full-path bindings, honoring
// grouped imports (`use a::{b, c::d}`) and aliases (`use a::b as c`). prefix is the accumulated path for a
// grouped branch. Only function-like leaves matter downstream, but every binding is recorded; the matcher
// decides relevance. Segments that address the current crate/std are kept verbatim (they still form a path
// the matcher can tail-compare).
func collectRustUseBindings(rest, prefix string, out map[string]string) {
	rest = strings.TrimSuffix(strings.TrimSpace(rest), ";")
	if rest == "" {
		return
	}
	if i := strings.Index(rest, "{"); i >= 0 && strings.HasSuffix(strings.TrimSpace(rest), "}") {
		head := strings.TrimSuffix(strings.TrimSpace(rest[:i]), "::")
		inner := strings.TrimSuffix(rest[i+1:], "}")
		branchPrefix := joinRustPath(prefix, head)
		for _, part := range splitTopLevel(inner, ',') {
			collectRustUseBindings(part, branchPrefix, out)
		}
		return
	}
	// A leaf: "a::b::c" or "a::b as d".
	alias := ""
	if i := strings.Index(rest, " as "); i >= 0 {
		alias = strings.TrimSpace(rest[i+4:])
		rest = strings.TrimSpace(rest[:i])
	}
	full := joinRustPath(prefix, strings.TrimSpace(rest))
	segs := splitRustPathSegments(full)
	if len(segs) == 0 {
		return
	}
	leaf := segs[len(segs)-1]
	if leaf == "*" || leaf == "" {
		return // a glob import binds no specific leaf
	}
	name := leaf
	if alias != "" {
		name = alias
	}
	out[name] = normalizeRustPath(full)
}

// rustQualifiedPaths returns every fully-qualified path reference (2+ segments) that appears in path or
// call position, e.g. "serde_json::from_str" from "serde_json::from_str(x)". Normalized (crate root
// underscored). It scans identifiers joined by "::".
func rustQualifiedPaths(body string) []string {
	var out []string
	n := len(body)
	i := 0
	for i < n {
		if !isRustIdentStart(body[i]) {
			i++
			continue
		}
		start := i
		segs := 1
		for i < n {
			// consume an identifier
			for i < n && isRustIdentByte(body[i]) {
				i++
			}
			// look for "::" continuation
			if i+1 < n && body[i] == ':' && body[i+1] == ':' {
				i += 2
				if i < n && isRustIdentStart(body[i]) {
					segs++
					continue
				}
			}
			break
		}
		if segs >= 2 {
			out = append(out, normalizeRustPath(body[start:i]))
		}
	}
	return out
}

// rustCallNames returns the set of bare identifiers immediately followed by '(' (a call), e.g. "from_str"
// in "from_str(x)". Used with a `use` binding to resolve an imported free function's call.
func rustCallNames(body string) map[string]bool {
	out := map[string]bool{}
	n := len(body)
	for i := 0; i < n; i++ {
		if !isRustIdentStart(body[i]) {
			continue
		}
		start := i
		for i < n && isRustIdentByte(body[i]) {
			i++
		}
		// skip whitespace, then require '('
		j := i
		for j < n && (body[j] == ' ' || body[j] == '\t') {
			j++
		}
		if j < n && body[j] == '(' {
			out[body[start:i]] = true
		}
		i--
	}
	return out
}

func isRustIdentStart(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// normalizeRustPath lowercases ONLY the crate root's hyphens-to-underscores normalization is applied by
// the matcher; here we canonicalize "::" spacing and drop a leading "::". Case is preserved (Rust symbols
// are case-sensitive).
func normalizeRustPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "::")
	return strings.Join(splitRustPathSegments(p), "::")
}

func splitRustPathSegments(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "::") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func joinRustPath(prefix, tail string) string {
	prefix = strings.TrimSpace(prefix)
	tail = strings.TrimSpace(tail)
	switch {
	case prefix == "":
		return tail
	case tail == "":
		return prefix
	default:
		return prefix + "::" + tail
	}
}

// splitTopLevel splits s on sep at brace depth zero (so a nested group stays one part).
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		case sep:
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}
