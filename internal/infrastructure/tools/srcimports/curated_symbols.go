package srcimports

import (
	"context"
	"fmt"
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

// localSymbolMetadata is the bounded state kept between passes: file identity and declarations. It never
// retains a source body. The two passes take O(accepted source bytes) time
// and O(max file bytes + declarations + references) space; accepted source is capped by the walker at 64 MiB.
type localSymbolMetadata struct {
	files              []sourceFile
	declarations       map[string][]localSymbolDeclaration
	declarationsByFile map[string][]localSymbolDeclaration
}

type localSymbolDeclaration struct {
	symbol string
	path   string
	line   int
	start  int
}

func newLocalSymbolMetadata() *localSymbolMetadata {
	return &localSymbolMetadata{
		declarations:       map[string][]localSymbolDeclaration{},
		declarationsByFile: map[string][]localSymbolDeclaration{},
	}
}

func (m *localSymbolMetadata) addFile(path string, content []byte) {
	m.files = append(m.files, sourceFile{path: path, bytes: int64(len(content))})
}

// addDeclarations derives line numbers as matches advance through the file, so it visits each source byte
// at most once for line accounting instead of recounting every declaration prefix.
func (m *localSymbolMetadata) addDeclarations(path, body string, declarationRE *regexp.Regexp) {
	line, previousStart := 1, 0
	for _, match := range declarationRE.FindAllStringSubmatchIndex(body, -1) {
		nameStart := match[2]
		line += strings.Count(body[previousStart:nameStart], "\n")
		previousStart = nameStart
		declaration := localSymbolDeclaration{
			symbol: body[nameStart:match[3]],
			path:   path,
			line:   line,
			start:  nameStart,
		}
		m.declarations[declaration.symbol] = append(m.declarations[declaration.symbol], declaration)
		m.declarationsByFile[path] = append(m.declarationsByFile[path], declaration)
	}
}

// scanLocalSymbolRefs collects qualified references and declaration metadata in its first pass. The second
// pass is deliberately limited to the accepted first-pass paths, resolving local bare calls without keeping
// the corpus in memory.
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
	metadata := newLocalSymbolMetadata()
	walker := newSourceWalker(limits, exts, skip)
	_, err := walker.walk(ctx, dir, func(filePath string, content []byte, _ *scanAccumulator) {
		body := mask(string(content))
		collectQualified(body, func(ref string) {
			if ref = strings.TrimSpace(ref); ref != "" {
				refs[ref] = true
			}
		})
		metadata.addFile(filePath, content)
		metadata.addDeclarations(filePath, body, declarationRE)
	})
	if err != nil {
		return nil, nil, err
	}
	local, err := resolveLocalCalls(ctx, dir, walker, metadata, mask, callRE, phpDynamicNames)
	if err != nil {
		return nil, nil, err
	}
	return sortedKeys(refs), local, nil
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
	metadata := newLocalSymbolMetadata()
	assigned := map[string]bool{}
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
		metadata.addFile(filePath, content)
		metadata.addDeclarations(filePath, body, rubyMethodRE)
		for _, assignment := range rubyAssignmentRE.FindAllStringSubmatch(body, -1) {
			assigned[assignment[1]] = true
		}
	})
	if err != nil {
		return nil, nil, err
	}
	local, err := resolveRubyLocalCalls(ctx, dir, walker, metadata, assigned)
	if err != nil {
		return nil, nil, err
	}
	return sortedKeys(refs), local, nil
}

func resolveLocalCalls(
	ctx context.Context,
	dir string,
	walker *sourceWalker,
	metadata *localSymbolMetadata,
	mask func(string) string,
	callRE *regexp.Regexp,
	dynamicNames map[string]bool,
) ([]symreach.SymbolReference, error) {
	seen := map[localSymbolDeclaration]bool{}
	err := walker.rescan(ctx, dir, metadata.files, func(filePath string, content []byte) error {
		body := maskNamedCallArguments(mask(string(content)), dynamicNames, isPHPIdentByte)
		declarationStarts := localDeclarationStarts(metadata.declarationsByFile[filePath])
		for _, match := range callRE.FindAllStringSubmatchIndex(body, -1) {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return fmt.Errorf("source scan cancelled: %w", ctxErr)
			}
			nameStart := match[2]
			if declarationStarts[nameStart] || !isBarePHPCall(body, nameStart) {
				continue
			}
			name := body[nameStart:match[3]]
			if declarations := metadata.declarations[name]; len(declarations) == 1 && declarations[0].path == filePath {
				seen[declarations[0]] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sortedLocalReferences(seen), nil
}

func resolveRubyLocalCalls(
	ctx context.Context,
	dir string,
	walker *sourceWalker,
	metadata *localSymbolMetadata,
	assigned map[string]bool,
) ([]symreach.SymbolReference, error) {
	seen := map[localSymbolDeclaration]bool{}
	err := walker.rescan(ctx, dir, metadata.files, func(filePath string, content []byte) error {
		body := maskNamedCallArguments(maskRubySource(string(content)), rubyDynamicNames, isRubyIdentByte)
		declarationStarts := localDeclarationStarts(metadata.declarationsByFile[filePath])
		for _, match := range rubyCallRE.FindAllStringSubmatchIndex(body, -1) {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return fmt.Errorf("source scan cancelled: %w", ctxErr)
			}
			nameStart := match[2]
			if declarationStarts[nameStart] || !isBareRubyCall(body, nameStart) {
				continue
			}
			name := body[nameStart:match[3]]
			if !assigned[name] {
				if declarations := metadata.declarations[name]; len(declarations) == 1 && declarations[0].path == filePath {
					seen[declarations[0]] = true
				}
			}
		}
		for lineStart := 0; lineStart < len(body); {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return fmt.Errorf("source scan cancelled: %w", ctxErr)
			}
			lineEnd := strings.IndexByte(body[lineStart:], '\n')
			if lineEnd < 0 {
				lineEnd = len(body)
			} else {
				lineEnd += lineStart
			}
			if match := rubyBareCallLineRE.FindStringSubmatchIndex(body[lineStart:lineEnd]); match != nil {
				name := body[lineStart+match[2] : lineStart+match[3]]
				if !assigned[name] {
					if declarations := metadata.declarations[name]; len(declarations) == 1 && declarations[0].path == filePath {
						seen[declarations[0]] = true
					}
				}
			}
			if lineEnd == len(body) {
				break
			}
			lineStart = lineEnd + 1
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sortedLocalReferences(seen), nil
}

func localDeclarationStarts(declarations []localSymbolDeclaration) map[int]bool {
	starts := make(map[int]bool, len(declarations))
	for _, declaration := range declarations {
		starts[declaration.start] = true
	}
	return starts
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
