package srcimports

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/symreach"
)

// Curated symbol-reference scanners for PHP / Ruby / .NET. Each observes FULLY-QUALIFIED
// symbol references in first-party source and returns them for symreach's raise-only tail-match against the
// curated affected symbols. PHP and Ruby additionally resolve an exact, unambiguous local bare call to its
// declaration. They are source-only (never run composer/bundler/dotnet) and capture only what they can prove,
// omitting dynamic, dispatch-resolved, or unqualified references rather than guessing, which is sound because
// the consumer is raise-only (a missed reference forgoes an urgency raise; it never hides a finding).

var (
	// PHP: a namespaced static call `Vendor\Pkg\Class::method(` -> "Vendor\Pkg\Class::method"; and a
	// namespaced instantiation `new Vendor\Pkg\Class(` -> "Vendor\Pkg\Class". A leading "\" is optional.
	phpStaticCallRE = regexp.MustCompile(`\\?([A-Za-z_][A-Za-z0-9_]*(?:\\[A-Za-z_][A-Za-z0-9_]*)+)::([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	phpNewRE        = regexp.MustCompile(`\bnew\s+\\?([A-Za-z_][A-Za-z0-9_]*(?:\\[A-Za-z_][A-Za-z0-9_]*)+)\s*\(`)
	phpFunctionRE   = regexp.MustCompile(`\bfunction\s+&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	phpBareCallRE   = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*\(`)

	// Ruby: a qualified constant method call `Foo::Bar.method(` -> the canonical "Foo::Bar#method"
	// (symbolcanon treats "#" as the Ruby member separator, so the observed "." call is emitted in "#" form
	// to compare symmetrically with an advisory "Module::Class#method").
	rubyQualifiedCallRE = regexp.MustCompile(`([A-Z][A-Za-z0-9_]*(?:::[A-Z][A-Za-z0-9_]*)+)\.([A-Za-z_][A-Za-z0-9_]*[?!]?)`)
	rubyMethodRE        = regexp.MustCompile(`(?m)^[\t ]*def\s+(?:self\.)?([a-z_][A-Za-z0-9_]*[?!]?)(?:[\t ]|\(|;|$)`)
	rubyCallRE          = regexp.MustCompile(`\b([a-z_][A-Za-z0-9_]*[?!]?)\s*\(`)
	rubyBareCallLineRE  = regexp.MustCompile(`^[\t ]*([a-z_][A-Za-z0-9_]*[?!]?)[\t ]*$`)
	rubyAssignmentRE    = regexp.MustCompile(`(?m)^[\t ]*([a-z_][A-Za-z0-9_]*)\s*(?:\|\|=|&&=|=)`)

	// .NET: a dotted qualified call `Namespace.Type.Member(` -> "Namespace.Type.Member", and a qualified
	// instantiation `new Namespace.Type(` -> "Namespace.Type".
	dotnetQualifiedRE = regexp.MustCompile(`\b([A-Z][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){2,})\s*\(`)
	dotnetNewRE       = regexp.MustCompile(`\bnew\s+([A-Z][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\s*\(`)
)

// PHPSymbolScanner observes qualified PHP references and provable local function calls for raise-only
// reachability.
type PHPSymbolScanner struct{ limits scanLimits }

var _ symreach.ProvenanceSymbolReferenceScanner = (*PHPSymbolScanner)(nil)

// NewPHPSymbolScanner returns a PHP symbol-reference scanner with the default source-walk limits.
func NewPHPSymbolScanner() *PHPSymbolScanner { return &PHPSymbolScanner{limits: defaultScanLimits()} }

// ScanSymbolRefs walks dir and returns the PHP symbol references it observed. It remains compatible with
// scanners that only use the legacy reference slice.
func (s *PHPSymbolScanner) ScanSymbolRefs(ctx context.Context, dir string) ([]string, error) {
	refs, _, err := s.ScanSymbolRefsWithProvenance(ctx, dir)
	return refs, err
}

// ScanSymbolRefsWithProvenance preserves qualified references and returns only local bare calls that resolve
// to one unambiguous declaration in the scanned root. Its record location is the declaration, never the call.
func (s *PHPSymbolScanner) ScanSymbolRefsWithProvenance(ctx context.Context, dir string) ([]string, []symreach.SymbolReference, error) {
	return scanLocalSymbolRefs(ctx, dir, s.limits, []string{".php", ".phtml", ".inc", ".module", ".install"}, phpSkipDir, maskPHPSource, collectPHPQualifiedRefs, phpFunctionRE, phpBareCallRE)
}

// RubySymbolScanner observes qualified Ruby references and provable local method calls for raise-only
// reachability.
type RubySymbolScanner struct{ limits scanLimits }

var _ symreach.ProvenanceSymbolReferenceScanner = (*RubySymbolScanner)(nil)

// NewRubySymbolScanner returns a Ruby symbol-reference scanner with the default source-walk limits.
func NewRubySymbolScanner() *RubySymbolScanner {
	return &RubySymbolScanner{limits: defaultScanLimits()}
}

// ScanSymbolRefs walks dir and returns the Ruby symbol references it observed, in "#" member form.
func (s *RubySymbolScanner) ScanSymbolRefs(ctx context.Context, dir string) ([]string, error) {
	refs, _, err := s.ScanSymbolRefsWithProvenance(ctx, dir)
	return refs, err
}

// ScanSymbolRefsWithProvenance preserves qualified references and returns only local bare calls that resolve
// to one unambiguous declaration in the scanned root. Its record location is the declaration, never the call.
func (s *RubySymbolScanner) ScanSymbolRefsWithProvenance(ctx context.Context, dir string) ([]string, []symreach.SymbolReference, error) {
	return scanRubyLocalSymbolRefs(ctx, dir, s.limits)
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

type localSymbolFile struct {
	path string
	body string
}

type localSymbolDeclaration struct {
	symbol string
	path   string
	line   int
	start  int
}

// scanLocalSymbolRefs collects legacy qualified refs and, separately, locally resolved bare PHP calls. A local
// declaration must be unique across the root and the call must be in that declaration's file, preventing a
// bare name in one package or file from becoming evidence for another.
func scanLocalSymbolRefs(
	ctx context.Context,
	dir string,
	limits scanLimits,
	exts []string,
	skip map[string]bool,
	mask func(string) string,
	collectQualified func(string, func(string)),
	declarationRE, callRE *regexp.Regexp,
) ([]string, []symreach.SymbolReference, error) {
	refs := map[string]bool{}
	var files []localSymbolFile
	walker := newSourceWalker(limits, exts, skip)
	_, err := walker.walk(ctx, dir, func(filePath string, content []byte, _ *scanAccumulator) {
		body := mask(string(content))
		collectQualified(body, func(ref string) {
			if ref = strings.TrimSpace(ref); ref != "" {
				refs[ref] = true
			}
		})
		files = append(files, localSymbolFile{path: filePath, body: body})
	})
	if err != nil {
		return nil, nil, err
	}
	return sortedKeys(refs), resolveLocalCalls(files, declarationRE, callRE, phpDynamicNames), nil
}

func collectPHPQualifiedRefs(body string, add func(string)) {
	for _, m := range phpStaticCallRE.FindAllStringSubmatch(body, -1) {
		add(m[1] + "::" + m[2])
	}
	for _, m := range phpNewRE.FindAllStringSubmatch(body, -1) {
		add(m[1])
	}
}

func scanRubyLocalSymbolRefs(ctx context.Context, dir string, limits scanLimits) ([]string, []symreach.SymbolReference, error) {
	refs := map[string]bool{}
	var files []localSymbolFile
	walker := newSourceWalker(limits, []string{".rb", ".rake", ".gemspec", ".ru"}, rubySkipDir)
	_, err := walker.walk(ctx, dir, func(filePath string, content []byte, _ *scanAccumulator) {
		body := maskRubySource(string(content))
		for _, m := range rubyQualifiedCallRE.FindAllStringSubmatch(body, -1) {
			if m[2] == "new" {
				refs[m[1]] = true // Foo::Bar.new -> reference to the class Foo::Bar
				continue
			}
			if !rubyDynamicNames[m[2]] {
				refs[m[1]+"#"+m[2]] = true
			}
		}
		files = append(files, localSymbolFile{path: filePath, body: body})
	})
	if err != nil {
		return nil, nil, err
	}
	assigned := map[string]bool{}
	for _, file := range files {
		for _, m := range rubyAssignmentRE.FindAllStringSubmatch(file.body, -1) {
			assigned[m[1]] = true
		}
	}
	return sortedKeys(refs), resolveRubyLocalCalls(files, assigned), nil
}

func resolveLocalCalls(files []localSymbolFile, declarationRE, callRE *regexp.Regexp, dynamicNames map[string]bool) []symreach.SymbolReference {
	declarations, byFile := localDeclarations(files, declarationRE)
	seen := map[localSymbolDeclaration]bool{}
	for _, file := range files {
		body := maskNamedCallArguments(file.body, dynamicNames, isPHPIdentByte)
		declarationStarts := map[int]bool{}
		for _, declaration := range byFile[file.path] {
			declarationStarts[declaration.start] = true
		}
		for _, match := range callRE.FindAllStringSubmatchIndex(body, -1) {
			nameStart := match[2]
			if declarationStarts[nameStart] || !isBarePHPCall(body, nameStart) {
				continue
			}
			name := body[match[2]:match[3]]
			if len(declarations[name]) != 1 || declarations[name][0].path != file.path {
				continue
			}
			seen[declarations[name][0]] = true
		}
	}
	return sortedLocalReferences(seen)
}

func resolveRubyLocalCalls(files []localSymbolFile, assigned map[string]bool) []symreach.SymbolReference {
	declarations, byFile := localDeclarations(files, rubyMethodRE)
	seen := map[localSymbolDeclaration]bool{}
	for _, file := range files {
		body := maskNamedCallArguments(file.body, rubyDynamicNames, isRubyIdentByte)
		declarationStarts := map[int]bool{}
		for _, declaration := range byFile[file.path] {
			declarationStarts[declaration.start] = true
		}
		for _, match := range rubyCallRE.FindAllStringSubmatchIndex(body, -1) {
			nameStart := match[2]
			if declarationStarts[nameStart] || !isBareRubyCall(body, nameStart) {
				continue
			}
			name := body[match[2]:match[3]]
			if assigned[name] || len(declarations[name]) != 1 || declarations[name][0].path != file.path {
				continue
			}
			seen[declarations[name][0]] = true
		}
		for _, line := range strings.SplitAfter(body, "\n") {
			trimmed := strings.TrimSuffix(line, "\n")
			match := rubyBareCallLineRE.FindStringSubmatchIndex(trimmed)
			if match != nil {
				name := trimmed[match[2]:match[3]]
				if !assigned[name] && len(declarations[name]) == 1 && declarations[name][0].path == file.path {
					seen[declarations[name][0]] = true
				}
			}
		}
	}
	return sortedLocalReferences(seen)
}

func localDeclarations(files []localSymbolFile, declarationRE *regexp.Regexp) (map[string][]localSymbolDeclaration, map[string][]localSymbolDeclaration) {
	all := map[string][]localSymbolDeclaration{}
	byFile := map[string][]localSymbolDeclaration{}
	for _, file := range files {
		for _, match := range declarationRE.FindAllStringSubmatchIndex(file.body, -1) {
			declaration := localSymbolDeclaration{
				symbol: file.body[match[2]:match[3]],
				path:   file.path,
				line:   oneBasedLine(file.body, match[2]),
				start:  match[2],
			}
			all[declaration.symbol] = append(all[declaration.symbol], declaration)
			byFile[file.path] = append(byFile[file.path], declaration)
		}
	}
	return all, byFile
}

func sortedLocalReferences(seen map[localSymbolDeclaration]bool) []symreach.SymbolReference {
	out := make([]symreach.SymbolReference, 0, len(seen))
	for declaration := range seen {
		out = append(out, symreach.SymbolReference{Symbol: declaration.symbol, ModulePath: declaration.path, Line: declaration.line})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Symbol != out[j].Symbol {
			return out[i].Symbol < out[j].Symbol
		}
		if out[i].ModulePath != out[j].ModulePath {
			return out[i].ModulePath < out[j].ModulePath
		}
		return out[i].Line < out[j].Line
	})
	return out
}

func oneBasedLine(body string, offset int) int {
	return strings.Count(body[:offset], "\n") + 1
}

func isBarePHPCall(body string, start int) bool {
	previous := previousNonSpace(body, start)
	return previous != '\\' && previous != '$' && previous != ':' && previous != '>' && previous != '.'
}

func isBareRubyCall(body string, start int) bool {
	previous := previousNonSpace(body, start)
	return previous != '.' && previous != ':' && previous != '@' && previous != '$'
}

func previousNonSpace(body string, start int) byte {
	for index := start - 1; index >= 0; index-- {
		switch body[index] {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return body[index]
		}
	}
	return 0
}

var phpDynamicNames = map[string]bool{
	"array_filter": true, "array_map": true, "call_user_func": true, "call_user_func_array": true,
	"forward_static_call": true, "forward_static_call_array": true, "register_shutdown_function": true,
	"ReflectionClass": true, "ReflectionFunction": true, "ReflectionMethod": true, "ReflectionProperty": true,
	"uasort": true, "uksort": true, "usort": true,
}

var rubyDynamicNames = map[string]bool{
	"__send__": true, "class_eval": true, "const_get": true, "define_method": true,
	"define_singleton_method": true, "eval": true, "instance_eval": true, "method": true,
	"module_eval": true, "public_send": true, "send": true,
}

// maskNamedCallArguments blanks known dynamic-dispatch arguments after strings and comments are already masked.
// It keeps newlines and the surrounding call intact, so a runtime-selected name can never become local evidence.
func maskNamedCallArguments(body string, names map[string]bool, isIdent func(byte) bool) string {
	masked := []byte(body)
	for index := 0; index < len(masked); {
		if !isIdent(masked[index]) || (index > 0 && isIdent(masked[index-1])) {
			index++
			continue
		}
		start := index
		for index < len(masked) && isIdent(masked[index]) {
			index++
		}
		if !names[string(masked[start:index])] {
			continue
		}
		open := index
		for open < len(masked) && (masked[open] == ' ' || masked[open] == '\t' || masked[open] == '\r' || masked[open] == '\n') {
			open++
		}
		if open == len(masked) || masked[open] != '(' {
			continue
		}
		depth := 1
		close := open + 1
		for ; close < len(masked) && depth > 0; close++ {
			switch masked[close] {
			case '(':
				depth++
			case ')':
				depth--
			}
		}
		if depth != 0 {
			close = len(masked)
		}
		for argument := open + 1; argument < close-1; argument++ {
			if masked[argument] != '\n' {
				masked[argument] = ' '
			}
		}
		index = close
	}
	return string(masked)
}

// maskPHPSource replaces comments and quoted strings with spaces while keeping every newline. PHP attributes
// (`#[...]`) are code, not hash comments, so the opening marker is preserved.
func maskPHPSource(body string) string {
	masked := []byte(body)
	const (
		normal = iota
		singleQuote
		doubleQuote
		lineComment
		blockComment
	)
	state := normal
	for index := 0; index < len(masked); index++ {
		current := masked[index]
		switch state {
		case normal:
			switch {
			case current == '\'':
				masked[index] = ' '
				state = singleQuote
			case current == '"':
				masked[index] = ' '
				state = doubleQuote
			case current == '/' && index+1 < len(masked) && masked[index+1] == '/':
				masked[index], masked[index+1] = ' ', ' '
				index++
				state = lineComment
			case current == '/' && index+1 < len(masked) && masked[index+1] == '*':
				masked[index], masked[index+1] = ' ', ' '
				index++
				state = blockComment
			case current == '#' && (index+1 == len(masked) || masked[index+1] != '['):
				masked[index] = ' '
				state = lineComment
			}
		case singleQuote, doubleQuote:
			if current == '\\' && index+1 < len(masked) {
				if current != '\n' {
					masked[index] = ' '
				}
				index++
				if masked[index] != '\n' {
					masked[index] = ' '
				}
				continue
			}
			if current != '\n' {
				masked[index] = ' '
			}
			if (state == singleQuote && current == '\'') || (state == doubleQuote && current == '"') {
				state = normal
			}
		case lineComment:
			if current == '\n' {
				state = normal
			} else {
				masked[index] = ' '
			}
		case blockComment:
			if current == '*' && index+1 < len(masked) && masked[index+1] == '/' {
				masked[index], masked[index+1] = ' ', ' '
				index++
				state = normal
			} else if current != '\n' {
				masked[index] = ' '
			}
		}
	}
	return string(masked)
}

// maskRubySource replaces Ruby comments, =begin/=end blocks, and quoted strings with spaces while keeping
// every newline. It deliberately omits unsupported computed forms rather than treating their contents as calls.
func maskRubySource(body string) string {
	masked := []byte(body)
	const (
		normal = iota
		singleQuote
		doubleQuote
		backtickQuote
		lineComment
		blockComment
	)
	state := normal
	lineStart := true
	for index := 0; index < len(masked); index++ {
		current := masked[index]
		if state == blockComment && lineStart && rubyBlockMarker(masked, index, "=end") {
			for end := index; end < index+4; end++ {
				masked[end] = ' '
			}
			index += 3
			state = normal
			lineStart = false
			continue
		}
		switch state {
		case normal:
			switch {
			case lineStart && rubyBlockMarker(masked, index, "=begin"):
				for end := index; end < index+6; end++ {
					masked[end] = ' '
				}
				index += 5
				state = blockComment
				lineStart = false
				continue
			case current == '\'':
				masked[index] = ' '
				state = singleQuote
			case current == '"':
				masked[index] = ' '
				state = doubleQuote
			case current == '`':
				masked[index] = ' '
				state = backtickQuote
			case current == '#':
				masked[index] = ' '
				state = lineComment
			}
		case singleQuote, doubleQuote, backtickQuote:
			if current == '\\' && index+1 < len(masked) {
				masked[index] = ' '
				index++
				if masked[index] != '\n' {
					masked[index] = ' '
				}
				continue
			}
			if current != '\n' {
				masked[index] = ' '
			}
			if (state == singleQuote && current == '\'') || (state == doubleQuote && current == '"') || (state == backtickQuote && current == '`') {
				state = normal
			}
		case lineComment:
			if current == '\n' {
				state = normal
			} else {
				masked[index] = ' '
			}
		case blockComment:
			if current != '\n' {
				masked[index] = ' '
			}
		}
		lineStart = current == '\n'
	}
	return string(masked)
}

func rubyBlockMarker(body []byte, index int, marker string) bool {
	if index+len(marker) > len(body) || string(body[index:index+len(marker)]) != marker {
		return false
	}
	if index+len(marker) == len(body) {
		return true
	}
	next := body[index+len(marker)]
	return next == '\n' || next == '\r' || next == ' ' || next == '\t'
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

// stripDotNetComments removes C-style // line and /* */ block comments.
func stripDotNetComments(body string) string {
	return stripRustBlockComments(stripLineComments(body, "//"))
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
