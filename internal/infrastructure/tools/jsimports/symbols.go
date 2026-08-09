package jsimports

import "github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"

// Tier-2 symbol observation.
//
// Tier-1 only needs to know THAT a module imports a package. Tier-2 needs to know which EXPORT is
// reached, and for a whole-module binding (`const _ = require('lodash')`, `import * as _`) that is
// knowable only if every reference to the local is an observable property read. This file records those
// references. It deliberately over-reports: an unrecognised reference shape becomes an opaque use, which
// downstream means "unknown", never "unused".

// rawLocalUse is one observed reference to a local name, before the module path is known.
type rawLocalUse struct {
	local    string
	property string
	kind     modulegraph.LocalUseKind
	detail   string
	line     int
}

// historyLimit bounds the look-back window used to recover a CommonJS binding pattern. It is a fixed
// cost per file and far longer than any real destructuring clause; a pattern that overruns it yields NO
// bindings, which downstream reads as a whole-module binding — the conservative direction.
const historyLimit = 128

// jsKeywords are identifier-shaped tokens that are never a local binding. The lexer emits keywords and
// numeric literals as tokenIdent, so without this list `if`, `return` and `42` would each be recorded as
// a reference to a local of that name. That would be harmless noise for the join (no import binds them)
// but it would also mean a genuine local named, say, `from` is treated inconsistently, so the list is
// applied uniformly.
var jsKeywords = map[string]bool{
	"await": true, "break": true, "case": true, "catch": true, "class": true, "const": true,
	"continue": true, "debugger": true, "default": true, "delete": true, "do": true, "else": true,
	"enum": true, "export": true, "extends": true, "false": true, "finally": true, "for": true,
	"function": true, "if": true, "implements": true, "import": true, "in": true, "instanceof": true,
	"interface": true, "let": true, "new": true, "null": true, "package": true, "private": true,
	"protected": true, "public": true, "return": true, "static": true, "super": true, "switch": true,
	"this": true, "throw": true, "true": true, "try": true, "typeof": true, "var": true, "void": true,
	"while": true, "with": true, "yield": true,
	// TypeScript-only modifiers and type keywords that appear in positions a local never does.
	"abstract": true, "as": true, "asserts": true, "declare": true, "is": true, "keyof": true,
	"namespace": true, "readonly": true, "satisfies": true, "type": true, "infer": true,
}

// bindingKeywords introduce a name rather than reference one, so the identifier that follows is a
// declaration site and not a use.
var bindingKeywords = map[string]bool{
	"const": true, "let": true, "var": true, "function": true, "class": true,
	"interface": true, "enum": true, "namespace": true, "type": true,
}

// isLocalName reports whether t can name a local binding.
func isLocalName(t token) bool {
	if t.kind != tokenIdent || t.text == "" {
		return false
	}
	if jsKeywords[t.text] {
		return false
	}
	first := t.text[0]
	if first >= '0' && first <= '9' {
		return false
	}
	return true
}

// observeLocal records what the module does with one identifier occurrence.
//
// It is called for every identifier the main loop sees. Identifiers consumed inside an import clause
// never reach it, which is exactly right: a binding site introduces the local, it does not use it.
func (e *extractor) observeLocal(t, prev token, havePrev bool) {
	if !isLocalName(t) {
		return
	}
	// `a.b` — b is a property name, not a reference to a local called b. The member use was already
	// recorded when a was seen.
	if havePrev && prev.kind == tokenPunct && (prev.text == "." || prev.text == "?.") {
		return
	}
	// `const x = ...`, `function x(...)`, `class x` — a declaration site.
	if havePrev && prev.kind == tokenIdent && bindingKeywords[prev.text] {
		return
	}

	next := e.peek()
	if next.kind != tokenPunct {
		e.addLocalUse(rawLocalUse{local: t.text, kind: modulegraph.LocalUseOpaque,
			detail: "referenced without a property access", line: t.line})
		return
	}

	switch next.text {
	case ".", "?.":
		dot := e.next()
		prop := e.next()
		// `a?.()` is an optional CALL, not a member read: the whole binding is invoked.
		if isLocalName(prop) {
			e.addLocalUse(rawLocalUse{local: t.text, property: prop.text,
				kind: modulegraph.LocalUseProperty, line: t.line})
		} else {
			e.addLocalUse(rawLocalUse{local: t.text, kind: modulegraph.LocalUseOpaque,
				detail: "member access with a non-identifier property", line: t.line})
		}
		// Restore the stream. push is LIFO, so the property goes back first.
		e.push(prop)
		e.push(dot)
	case "[":
		// `a[name]` can read ANY export, including the affected one.
		e.addLocalUse(rawLocalUse{local: t.text, kind: modulegraph.LocalUseOpaque,
			detail: "indexed with a computed key", line: t.line})
	case "=":
		// An assignment TARGET rebinds the name; it is not a read of the imported module. A declaration
		// (`const x = require(...)`) also lands here and is likewise not a use.
		return
	case ":":
		// `{ key: value }` and `x: Type` bind or annotate a name; `cond ? a : b` READS one. The three are
		// only distinguishable by what precedes the identifier, and an identifier that is not provably in
		// a key or annotation position is treated as a read — the ternary consequent is an ordinary
		// escaping reference, and calling it a key would lose it.
		if havePrev && prev.kind == tokenPunct && (prev.text == "{" || prev.text == "," || prev.text == ";" || prev.text == "(") {
			return
		}
		e.addLocalUse(rawLocalUse{local: t.text, kind: modulegraph.LocalUseOpaque,
			detail: "the binding escapes as a value", line: t.line})
		return
	default:
		// Passed as an argument, spread, returned, compared, awaited: the module object escapes.
		e.addLocalUse(rawLocalUse{local: t.text, kind: modulegraph.LocalUseOpaque,
			detail: "the binding escapes as a value", line: t.line})
	}
}

// addLocalUse records one reference, deduplicated at the point of record.
//
// The budget is charged against DISTINCT records, not raw occurrences: a file that reads `_.merge` twenty
// thousand times carries exactly one piece of evidence, and charging it twenty thousand times would
// declare a benign file unobservable. Deduplicating here is safe precisely because identical records
// carry identical evidence.
func (e *extractor) addLocalUse(use rawLocalUse) {
	key := rawLocalUse{local: use.local, property: use.property, kind: use.kind, detail: use.detail}
	if e.seenLocalUses == nil {
		e.seenLocalUses = map[rawLocalUse]bool{}
	}
	if e.seenLocalUses[key] {
		return
	}
	if len(e.out.localUses) >= maxLocalUsesPerFile {
		// A dropped reference could be the one that reaches the affected symbol, so the file's symbol
		// evidence becomes untrustworthy. It is recorded as a SYMBOL limitation, not a graph hazard: the
		// import graph is unaffected, and a Tier-2 budget must not refuse a sound Tier-1 answer.
		e.out.symbolBudgetHit = true
		return
	}
	e.seenLocalUses[key] = true
	e.out.localUses = append(e.out.localUses, use)
}

// maxLocalUsesPerFile bounds per-file symbol evidence, counted in distinct records.
const maxLocalUsesPerFile = 20000

// commonJSBindings recovers the binding pattern of a `... = require('pkg')` declaration by looking back
// over the tokens the main loop has already consumed.
//
// It returns nil when the pattern is anything it does not fully understand — a rest element, a default
// value, a nested pattern, a member-assignment target, a bare call whose result is not bound. nil means
// "whole module bound opaquely", which is the conservative reading: downstream, a require edge with no
// named bindings can reach any export.
//
// followedByNavigation reports whether the require CALL is further navigated (`require('x').y`,
// `require('x')()`); in that case whatever is bound is a sub-object, not the module, and claiming it as
// the module's own local would attribute the sub-object's property reads to the wrong thing.
func commonJSBindings(history []token, followedByNavigation bool) []modulegraph.Binding {
	if len(history) == 0 || followedByNavigation {
		return nil
	}
	last := history[len(history)-1]
	if last.kind != tokenPunct || last.text != "=" {
		// Not bound to anything this scanner can name: `foo(require('x'))`, `require('x').y`.
		return nil
	}
	pattern := history[:len(history)-1]
	if len(pattern) == 0 {
		return nil
	}

	// A single identifier: `const ns = require('pkg')`. It must be a genuine DECLARATION, not a member
	// assignment: `exports.lodash = require('lodash')` publishes the whole module somewhere this scanner
	// cannot follow, and recording `lodash` as a local would silently model that escape as a binding
	// nothing ever reads.
	if tail := pattern[len(pattern)-1]; isLocalName(tail) {
		if len(pattern) >= 2 {
			if before := pattern[len(pattern)-2]; before.kind == tokenPunct && (before.text == "." || before.text == "?." || before.text == "[") {
				return nil
			}
		}
		return []modulegraph.Binding{{Local: tail.text, Namespace: true}}
	}

	// A destructuring clause: `const { a, b: c } = require('pkg')`.
	if closing := pattern[len(pattern)-1]; closing.kind != tokenPunct || closing.text != "}" {
		return nil
	}
	open := -1
	for i := len(pattern) - 2; i >= 0; i-- {
		t := pattern[i]
		if t.kind == tokenPunct && t.text == "}" {
			// A nested pattern; not modelled.
			return nil
		}
		if t.kind == tokenPunct && t.text == "{" {
			open = i
			break
		}
	}
	if open < 0 {
		return nil
	}
	return destructuredBindings(pattern[open+1 : len(pattern)-1])
}

// destructuredBindings parses the inside of `{ ... }`. Any element it does not fully understand aborts
// the whole clause, because a partial binding list would look like a complete one.
func destructuredBindings(inner []token) []modulegraph.Binding {
	var out []modulegraph.Binding
	i := 0
	for i < len(inner) {
		t := inner[i]
		if t.kind == tokenPunct && t.text == "," {
			i++
			continue
		}
		if !isLocalName(t) {
			return nil
		}
		binding := modulegraph.Binding{Imported: t.text, Local: t.text}
		i++
		if i < len(inner) && inner[i].kind == tokenPunct && inner[i].text == ":" {
			i++
			if i >= len(inner) || !isLocalName(inner[i]) {
				return nil
			}
			binding.Local = inner[i].text
			i++
		}
		// A default value (`{ a = fallback }`) or anything else is not modelled.
		if i < len(inner) && !(inner[i].kind == tokenPunct && inner[i].text == ",") {
			return nil
		}
		out = append(out, binding)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// recordHistory keeps the main loop's recent tokens. Only the main loop feeds it: tokens consumed inside
// a recogniser are part of a construct that has already been interpreted, and mixing them in would make
// the look-back window describe something other than the statement's left-hand side.
func (e *extractor) recordHistory(t token) {
	e.history = append(e.history, t)
	if len(e.history) > historyLimit {
		e.history = e.history[len(e.history)-historyLimit:]
	}
}

// recordLocalUses attaches one file's local references to the graph, deduplicated.
//
// Deduplication is safe here and nowhere else: two identical (local, property, kind) references from the
// same module carry the same evidence, so collapsing them cannot hide a distinct reference. The line is
// dropped for a duplicate because the FIRST occurrence is the one a reader is pointed at.
func (sc *scanState) recordLocalUses(modulePath string, result extraction) {
	if result.sawJSX {
		sc.jsxModules = append(sc.jsxModules, modulePath)
	}
	if result.symbolBudgetHit {
		sc.symbolCoverage = append(sc.symbolCoverage, modulegraph.CoverageIssue{
			Kind:   modulegraph.CoverageSymbolEvidenceIncomplete,
			Path:   modulePath,
			Detail: "distinct local reference budget exceeded",
		})
		return
	}
	// A scan-wide bound as well as the per-file one: a hostile repository of many small files would
	// otherwise exhaust memory that no single file's budget notices. A breach makes the whole scan's
	// symbol evidence untrustworthy, so it is reported rather than silently truncated.
	if len(sc.localUses) >= maxLocalUsesPerScan {
		sc.symbolCoverage = append(sc.symbolCoverage, modulegraph.CoverageIssue{
			Kind:   modulegraph.CoverageSymbolEvidenceIncomplete,
			Path:   modulePath,
			Detail: "scan-wide local reference budget exceeded",
		})
		return
	}
	for _, use := range result.localUses {
		sc.localUses = append(sc.localUses, modulegraph.LocalUse{
			Module:   modulePath,
			Local:    use.local,
			Property: use.property,
			Kind:     use.kind,
			Detail:   use.detail,
			Line:     use.line,
		})
	}
}

// maxLocalUsesPerScan bounds symbol evidence across the whole scan.
const maxLocalUsesPerScan = 2_000_000

// keepImportedLocals drops references to locals that no import binds.
//
// The observer records every identifier it sees, because at the time it sees one it does not yet know
// which locals will turn out to be import bindings (a `require` can appear anywhere in the file). The
// join downstream only ever looks up bindings, so the rest is noise — and on a large repository it is
// noise measured in millions of records. Filtering here is a memory decision, not a semantic one: a
// local no import binds could never have contributed evidence.
func keepImportedLocals(imports []rawImport, uses []rawLocalUse) []rawLocalUse {
	bound := map[string]bool{}
	for _, imp := range imports {
		for _, binding := range imp.bindings {
			if binding.Local != "" {
				bound[binding.Local] = true
			}
		}
	}
	if len(bound) == 0 {
		return nil
	}
	kept := uses[:0]
	for _, use := range uses {
		if bound[use.local] {
			kept = append(kept, use)
		}
	}
	return kept
}
