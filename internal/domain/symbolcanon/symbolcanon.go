// Package symbolcanon canonicalizes vulnerable-symbol names so the advisory side and the
// reachability/observed side compare identically. A canonicalization mismatch between the two
// sides is a silent false negative (the reachable symbol never equals the advisory symbol), so
// this package is the single source of truth, applied SYMMETRICALLY on both sides.
//
// It handles the STRUCTURAL symbol forms Synapse matches on: Go "importPath.Recv.Method", Rust
// "crate::path::func", PHP `Namespace\Class::method`, Ruby "Module::Class#method", and .NET
// "Namespace.Type.Member". It strips generic arguments, pointer-receiver decoration, and normalizes
// separators plus the Rust crate hyphen-to-underscore convention.
//
// It deliberately does NOT demangle compiled binary symbols (C++ Itanium/MSVC, Rust v0). A mangled
// name must be demangled at the extraction site (the binary reachability tracks) BEFORE Canonicalize
// is called; LooksMangled reports a name that still needs demangling so a caller can refuse rather
// than canonicalize garbage. Keeping demangling out of the domain keeps this package stdlib-only,
// as the architecture rule requires.
package symbolcanon

import "strings"

// Language selects the separator and normalization rules for a symbol form. The empty Language
// (Generic) splits on every known separator and applies NO lossy language transform (no generic-strip,
// no hyphen normalization), so it is a safe superset for an unknown source.
type Language string

const (
	Go      Language = "go"
	Rust    Language = "rust"
	PHP     Language = "php"
	Ruby    Language = "ruby"
	DotNet  Language = "dotnet"
	Generic Language = ""
)

// Symbol is a canonical symbol as ordered, non-empty path segments (module/namespace/type/member).
// Case is preserved (every target language here is case-sensitive at the symbol level); the Rust
// crate convention of hyphen-vs-underscore is normalized to underscore.
type Symbol struct{ Segments []string }

// Canonicalize turns a raw advisory-or-observed symbol into its canonical segments. It is total:
// an empty or all-separator input yields a Symbol with no segments, which never tail-matches.
func Canonicalize(lang Language, raw string) Symbol {
	raw = strings.TrimSpace(raw)
	if hasGenerics(lang) {
		raw = stripGenerics(raw)
	}
	var out []string
	for _, seg := range strings.FieldsFunc(raw, separatorFunc(lang)) {
		seg = normalizeSegment(lang, seg)
		if seg != "" {
			out = append(out, seg)
		}
	}
	return Symbol{Segments: out}
}

// String joins the canonical segments with "::" for logs and evidence; it is not itself re-parsed.
func (s Symbol) String() string { return strings.Join(s.Segments, "::") }

// Equal reports whole-symbol canonical equality.
func Equal(a, b Symbol) bool {
	if len(a.Segments) != len(b.Segments) {
		return false
	}
	for i := range a.Segments {
		if a.Segments[i] != b.Segments[i] {
			return false
		}
	}
	return true
}

// TailMatch reports whether want and observed share their last n segments. n=2 ties a function to
// its immediate owner (module or type), so a bare same-named leaf (a local parse()) does not match
// a library's Type::parse; callers use n=2 for a raise-only "references the vulnerable function".
// n<=0 or a symbol shorter than n never matches.
func TailMatch(want, observed Symbol, n int) bool {
	if n <= 0 || len(want.Segments) < n || len(observed.Segments) < n {
		return false
	}
	w, o := want.Segments[len(want.Segments)-n:], observed.Segments[len(observed.Segments)-n:]
	for i := range w {
		if w[i] != o[i] {
			return false
		}
	}
	return true
}

// LooksMangled reports whether raw is a compiled-binary mangled symbol that must be demangled at the
// extraction site before Canonicalize: Itanium C++ ("_Z..."), MSVC ("?..."), or Rust v0 ("_R...").
func LooksMangled(raw string) bool {
	raw = strings.TrimSpace(raw)
	return strings.HasPrefix(raw, "_Z") || strings.HasPrefix(raw, "__Z") ||
		strings.HasPrefix(raw, "_R") || strings.HasPrefix(raw, "__R") || strings.HasPrefix(raw, "?")
}

// separatorFunc returns the segment separator predicate for a language.
func separatorFunc(lang Language) func(rune) bool {
	switch lang {
	case Rust:
		return func(r rune) bool { return r == ':' }
	case PHP:
		return func(r rune) bool { return r == ':' || r == '\\' }
	case Ruby:
		return func(r rune) bool { return r == ':' || r == '#' }
	case DotNet:
		return func(r rune) bool { return r == '.' }
	case Go:
		return func(r rune) bool { return r == '.' || r == '/' }
	default: // Generic: any known separator
		return func(r rune) bool { return r == ':' || r == '.' || r == '/' || r == '\\' || r == '#' }
	}
}

// normalizeSegment strips pointer/reference decoration and wrapping parens, and applies the Rust
// crate-root hyphen-to-underscore convention (a RustSec crate name may be hyphenated where Rust
// source uses underscores).
func normalizeSegment(lang Language, seg string) string {
	seg = strings.TrimSpace(seg)
	// Pointer/reference decoration (a Go/Rust/.NET receiver like (*Server) or &T) is stripped only for the
	// languages that use it. Ruby uses *, **, & as method NAMES (Numeric#*, Set#&), and Generic is lossless,
	// so neither strips, or a valid operator method would lose its segment.
	if lang == Go || lang == Rust || lang == DotNet {
		seg = strings.Trim(seg, "()")
		seg = strings.TrimLeft(seg, "*&")
	}
	seg = strings.TrimSpace(seg)
	if lang == Rust {
		seg = strings.ReplaceAll(seg, "-", "_")
	}
	return seg
}

// hasGenerics reports whether a language uses generic-argument syntax that must be stripped. Ruby has no
// generics (and uses [] / <=> / << as method NAMES, which must survive), and Generic is a lossless
// superset, so neither strips.
func hasGenerics(lang Language) bool {
	return lang == Go || lang == Rust || lang == DotNet
}

// stripGenerics removes generic argument lists so a generic instantiation matches its definition:
// balanced <...> (Go/Rust/C#/Java) and [...] (Go type args), plus the CLR reflection arity marker
// `N (a backtick followed by digits). Depth-counted so nested generics are removed whole.
func stripGenerics(s string) string {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '<', '[':
			depth++
		case '>', ']':
			if depth > 0 {
				depth--
			}
		case '`':
			// CLR arity: drop the backtick and the digits that follow.
			for i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
				i++
			}
		default:
			if depth == 0 {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}
