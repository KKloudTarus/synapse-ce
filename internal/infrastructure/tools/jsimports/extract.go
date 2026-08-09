package jsimports

import "github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"

// rawImport is one statically observed module-loading site, before path resolution.
type rawImport struct {
	specifier string
	kind      modulegraph.ImportKind
	bindings  []modulegraph.Binding
	typeOnly  bool
	position  modulegraph.Position
}

// extraction is everything one source file yields: its import sites and its coverage hazards.
type extraction struct {
	imports []rawImport
	hazards []hazard
}

// indirectLoaders are call-shaped module loaders this scanner does not extract specifiers from. Each one
// really loads a module, so seeing it must degrade coverage: otherwise a dependency loaded through, say,
// an AMD define() would look unused and could be reported unreachable.
var indirectLoaders = map[string]string{
	"define":                  "amd define",
	"requirejs":               "requirejs loader",
	"importScripts":           "worker importScripts",
	"__non_webpack_require__": "webpack require escape hatch",
	"__webpack_require__":     "webpack runtime require",
	"requireActual":           "test-runner requireActual",
	"requireMock":             "test-runner requireMock",
	"dlopen":                  "native addon dlopen",
}

// referenceIsEnough names loaders whose mere REFERENCE degrades coverage, because aliasing one
// (`const wr = __webpack_require__; wr(4)`) loads a module just as calling it does. Names common as
// first-party identifiers (define) stay call-only so ordinary code is not flagged.
var referenceIsEnough = map[string]bool{
	"__webpack_require__": true, "__non_webpack_require__": true,
	"importScripts": true, "requirejs": true, "createRequire": true,
	"requireActual": true, "requireMock": true, "dlopen": true,
}

// loaderNames are the loader identifiers recognised through a computed member access
// (`module["require"](...)`), which produces no identifier token at all.
var loaderNames = map[string]bool{
	"require": true, "eval": true, "Function": true, "import": true,
	"importScripts": true, "define": true, "requirejs": true, "createRequire": true,
	"__webpack_require__": true, "__non_webpack_require__": true, "dlopen": true,
}

// memberReachableLoaders are loaders that are still loaders when called through a receiver, because the
// receiver is the loader's own namespace (jest.requireActual, process.dlopen) rather than an unrelated
// object that happens to expose a same-named method.
var memberReachableLoaders = map[string]bool{
	"requireActual": true, "requireMock": true, "dlopen": true,
}

// globalObjects are receivers through which the global evaluator is still the global evaluator.
var globalObjects = map[string]bool{
	"globalThis": true, "window": true, "global": true, "self": true,
}

// requireReceivers are receivers whose `.require(...)` is a genuine Node module loader rather than an
// unrelated method that happens to be called require.
var requireReceivers = map[string]bool{
	"module": true, "mainModule": true, "main": true,
}

// extractor turns a token stream into import sites. It is a focused recogniser, not a full parser: it
// matches the module-loading forms in the epic's scope and records anything else that could load a module
// as a hazard, so an unrecognised construct degrades coverage instead of silently disappearing.
type extractor struct {
	lex *lexer
	// buf holds tokens pushed back by the recognisers (single-token lookahead is not always enough).
	buf []token
	out extraction
}

func newExtractor(src []byte, jsxAware bool) *extractor {
	return &extractor{lex: newLexer(src, jsxAware)}
}

func (e *extractor) next() token {
	if n := len(e.buf); n > 0 {
		t := e.buf[n-1]
		e.buf = e.buf[:n-1]
		return t
	}
	return e.lex.next()
}

func (e *extractor) push(t token) { e.buf = append(e.buf, t) }

// peek returns the next token without consuming it.
func (e *extractor) peek() token {
	t := e.next()
	e.push(t)
	return t
}

func (e *extractor) addHazard(kind hazardKind, line int, detail string) {
	e.out.hazards = append(e.out.hazards, hazard{kind: kind, line: line, detail: detail})
}

// addImport records an import site. A specifier whose literal contained an escape this lexer does not
// decode is NOT recorded as an edge: its decoded value is not the runtime specifier, so resolving it
// could name the wrong package. It degrades coverage instead.
func (e *extractor) addImport(imp rawImport, undecodedEscape bool) {
	if undecodedEscape {
		e.addHazard(hazardUnsupportedLoader, imp.position.Line, "module specifier contains an undecoded escape")
		return
	}
	e.out.imports = append(e.out.imports, imp)
}

// run walks the whole file. Every token is examined; only the recognised module-loading forms and the
// hazards produce output.
func (e *extractor) run() extraction {
	// prev and prev2 track the two previous significant tokens so member expressions
	// (`module.require`, `require.main.require`, `globalThis.eval`) can be recognised.
	var prev, prev2 token
	var havePrev bool

	for {
		t := e.next()
		if t.kind == tokenEOF {
			break
		}

		switch {
		case t.kind == tokenIdent && t.text == "import":
			e.handleImportKeyword(t, prev, havePrev)
		case t.kind == tokenIdent && t.text == "export":
			e.handleExportKeyword(t)
		case t.kind == tokenIdent && t.text == "require":
			e.handleRequire(t, prev, prev2, havePrev)
		case t.kind == tokenIdent && t.text == "eval":
			e.handleEval(t, prev, prev2, havePrev)
		case t.kind == tokenIdent && t.text == "Function":
			// `new Function(src)` and a bare `Function(src)` both compile a string into code that can
			// require anything, and `const F = Function` aliases the same power. A type position
			// (`x: Function`) or a prototype read (`x instanceof Function`) is harmless.
			switch {
			case e.peekIsCall():
				e.addHazard(hazardNewFunction, t.line, "Function constructor")
			case havePrev && prev.kind == tokenPunct && (prev.text == "=" || prev.text == "(" || prev.text == ","):
				// Aliased or passed as an argument; a TypeScript type position (`cb: Function`) has
				// prev == ":" and is deliberately excluded.
				e.addHazard(hazardNewFunction, t.line, "Function constructor aliased")
			}
		case t.kind == tokenIdent && t.text == "createRequire":
			// A reference is enough: `const cr = createRequire` aliases a factory that mints a real
			// loader, so the module it later loads is just as unobservable.
			e.addHazard(hazardModuleCreateRequire, t.line, "module.createRequire")
		case t.kind == tokenIdent && t.text == "Worker":
			// A worker entry module is loaded at runtime and is not statically resolvable here.
			if havePrev && prev.kind == tokenIdent && prev.text == "new" && e.peekIsCall() {
				e.addHazard(hazardUnsupportedLoader, t.line, "worker constructor")
			}
		case t.kind == tokenIdent && t.text == "System":
			// `System.import(...)` is the SystemJS loader.
			if e.peekIsMember("import") {
				e.addHazard(hazardUnsupportedLoader, t.line, "systemjs loader")
			}
		case t.kind == tokenIdent:
			// A member call such as db.define(...) merely shares a loader's name; only a bare call is
			// the loader itself. jest.requireActual is the deliberate exception: its receiver is the
			// test runner and the call really does load a module.
			memberCall := havePrev && prev.kind == tokenPunct && (prev.text == "." || prev.text == "?.")
			if detail, ok := indirectLoaders[t.text]; ok {
				// For most of these a mere reference is enough, because aliasing the loader loads a
				// module just as calling it does.
				if e.peekIsCall() || referenceIsEnough[t.text] {
					if !memberCall || memberReachableLoaders[t.text] {
						e.addHazard(hazardUnsupportedLoader, t.line, detail)
					}
				}
			}
		case t.kind == tokenString && havePrev && prev.kind == tokenPunct && prev.text == "[":
			// A computed member access (module["require"](...)) produces no loader IDENTIFIER token, so
			// the handlers above never run. The property name is the only observable signal.
			if loaderNames[t.text] {
				e.addHazard(hazardUnsupportedLoader, t.line, "computed loader access")
			}
		}

		prev2, prev, havePrev = prev, t, true
	}

	e.out.hazards = append(e.out.hazards, e.lex.hazards...)
	return e.out
}

// peekIsCall reports whether the next token opens a call argument list, including an optional call.
func (e *extractor) peekIsCall() bool {
	t := e.peek()
	if t.kind != tokenPunct {
		return false
	}
	return t.text == "(" || t.text == "?."
}

// peekIsMember reports whether the next two tokens are `.name`.
func (e *extractor) peekIsMember(name string) bool {
	dot := e.next()
	if dot.kind != tokenPunct || dot.text != "." {
		e.push(dot)
		return false
	}
	prop := e.next()
	matched := prop.kind == tokenIdent && prop.text == name
	e.push(prop)
	e.push(dot)
	return matched
}

// handleEval recognises every shape through which the global evaluator can run code. eval can load a
// module through a string, so any reference to it — not just a direct call — degrades coverage.
func (e *extractor) handleEval(t, prev, prev2 token, havePrev bool) {
	isMember := havePrev && prev.kind == tokenPunct && (prev.text == "." || prev.text == "?.")
	if isMember {
		// `globalThis.eval(...)` IS global eval; `sandbox.eval(...)` is an unrelated method.
		if prev2.kind == tokenIdent && globalObjects[prev2.text] {
			e.addHazard(hazardEval, t.line, "global eval via global object")
		}
		return
	}
	// A bare `eval` reference, called or aliased (`const e = eval; e(src)`), is a hazard either way.
	e.addHazard(hazardEval, t.line, "eval reference")
}

// handleImportKeyword recognises every `import`-led form: `import.meta...`, dynamic `import(...)`,
// TypeScript `import x = require(...)`, and the static ESM declarations.
func (e *extractor) handleImportKeyword(kw, prev token, havePrev bool) {
	// `foo.import` is a property access; `System.import(...)` is reported by the caller's loader table.
	if havePrev && prev.kind == tokenPunct && (prev.text == "." || prev.text == "?.") {
		return
	}

	t := e.next()
	switch {
	case t.kind == tokenPunct && t.text == ":":
		// An object key named `import` (`{ import: 1 }`) is not a declaration.
		e.push(t)
		return
	case t.kind == tokenPunct && t.text == ".":
		// import.meta — only `import.meta.glob(...)` matters (a bundler-expanded multi-module load).
		meta := e.next()
		if meta.kind == tokenIdent && meta.text == "meta" {
			dot := e.next()
			if dot.kind == tokenPunct && dot.text == "." {
				prop := e.next()
				if prop.kind == tokenIdent && (prop.text == "glob" || prop.text == "globEager") && e.peekIsCall() {
					e.addHazard(hazardImportMetaGlob, kw.line, "import.meta."+prop.text)
					return
				}
				e.push(prop)
				return
			}
			e.push(dot)
			return
		}
		e.push(meta)
	case t.kind == tokenPunct && (t.text == "(" || t.text == "?."):
		if t.text == "?." {
			if open := e.next(); open.kind != tokenPunct || open.text != "(" {
				e.push(open)
				return
			}
		}
		e.handleDynamicImport(kw)
	case t.kind == tokenString:
		// Side-effect import: `import "mod"`.
		e.addImport(rawImport{
			specifier: t.text,
			kind:      modulegraph.ImportESMStatic,
			position:  modulegraph.Position{Line: kw.line, Column: kw.column},
		}, t.undecodedEscape)
	case t.kind == tokenTemplate:
		// `import \`mod\`` is not valid ESM; treat as unsupported rather than guess.
		e.addHazard(hazardUnsupportedLoader, kw.line, "template literal import specifier")
	default:
		e.push(t)
		e.handleStaticImportClause(kw)
	}
}

// handleDynamicImport handles `import( ... )`. A literal specifier yields a dynamic-literal edge; any
// non-literal argument is a hazard, because the loaded module cannot be named statically.
func (e *extractor) handleDynamicImport(kw token) {
	if spec, escaped, ok := e.readLiteralCallArgument(); ok {
		e.addImport(rawImport{
			specifier: spec,
			kind:      modulegraph.ImportESMDynamic,
			position:  modulegraph.Position{Line: kw.line, Column: kw.column},
		}, escaped)
		return
	}
	e.addHazard(hazardDynamicImport, kw.line, "non-literal dynamic import specifier")
}

// readLiteralCallArgument reads the first argument of a call that has just consumed its "(". It succeeds
// only when the argument is a COMPLETE literal — a string or substitution-free template immediately
// followed by "," or ")".
//
// The terminator check is what makes `require("a" + b)` a hazard rather than a false edge to "a": a
// concatenated specifier is computed at runtime, so its real target is unobservable and treating the
// first fragment as the module would be a silently wrong dependency edge.
func (e *extractor) readLiteralCallArgument() (string, bool, bool) {
	arg := e.next()
	isLiteral := arg.kind == tokenString || (arg.kind == tokenTemplate && !arg.hasSubstitution)
	if !isLiteral {
		e.push(arg)
		return "", false, false
	}
	// A literal specifier may be followed only by the end of the argument list or by a second argument
	// (ESM import attributes: `import("m", { with: { type: "json" } })`).
	terminator := e.peek()
	if terminator.kind != tokenPunct || (terminator.text != ")" && terminator.text != ",") {
		return "", false, false
	}
	return arg.text, arg.undecodedEscape, true
}

// handleStaticImportClause consumes an ESM import declaration's clause and its `from "specifier"`.
// It also recognises the TypeScript `import name = require("mod")` form.
func (e *extractor) handleStaticImportClause(kw token) {
	first := e.next()

	// `import type ...` — but `import type from "m"` / `import type, {x} from "m"` bind a value named
	// "type", so the modifier reading only applies when the following token is neither.
	typeOnly := false
	if first.kind == tokenIdent && first.text == "type" {
		lookahead := e.peek()
		isBindingName := lookahead.kind == tokenIdent && lookahead.text == "from"
		isBindingName = isBindingName || (lookahead.kind == tokenPunct && lookahead.text == ",")
		if !isBindingName {
			typeOnly = true
			first = e.next()
		}
	}

	// TypeScript import-equals: `import fs = require("fs")`.
	if first.kind == tokenIdent {
		if eq := e.peek(); eq.kind == tokenPunct && eq.text == "=" {
			e.next() // consume '='
			e.handleImportEquals(kw, first)
			return
		}
	}

	e.push(first)
	bindings, ok := e.readImportBindings()
	if !ok {
		e.addHazard(hazardUnsupportedLoader, kw.line, "unrecognised import clause")
		return
	}

	specifier, escaped, sok := e.readFromSpecifier(kw, "import")
	if !sok {
		return
	}
	e.addImport(rawImport{
		specifier: specifier,
		kind:      modulegraph.ImportESMStatic,
		bindings:  bindings,
		// Only a KEYWORD-level `import type` is fully erased. An all-inline-type binding list
		// (`import { type A } from "pkg"`) still emits `import "pkg"` under verbatimModuleSyntax, which
		// is a real side-effect module load — so it must stay runtime evidence.
		typeOnly: typeOnly,
		position: modulegraph.Position{Line: kw.line, Column: kw.column},
	}, escaped)
}

// handleImportEquals handles `import name = require("mod")` and `import name = A.B` (an alias, no module).
func (e *extractor) handleImportEquals(kw, name token) {
	req := e.next()
	if req.kind != tokenIdent || req.text != "require" {
		// A namespace alias such as `import X = A.B` loads no module.
		e.push(req)
		return
	}
	open := e.next()
	if open.kind != tokenPunct || open.text != "(" {
		e.push(open)
		return
	}
	spec, escaped, ok := e.readLiteralCallArgument()
	if !ok {
		e.addHazard(hazardDynamicRequire, kw.line, "non-literal import-equals require")
		return
	}
	e.addImport(rawImport{
		specifier: spec,
		kind:      modulegraph.ImportTypeScriptEqual,
		bindings:  []modulegraph.Binding{{Local: name.text, Namespace: true}},
		position:  modulegraph.Position{Line: kw.line, Column: kw.column},
	}, escaped)
}

// readImportBindings consumes the binding clause of an import declaration. It returns false when the
// clause is not one of the recognised shapes, so the caller can degrade coverage.
func (e *extractor) readImportBindings() ([]modulegraph.Binding, bool) {
	var bindings []modulegraph.Binding
	for {
		t := e.next()
		switch {
		case t.kind == tokenIdent && t.text == "from":
			e.push(t)
			return bindings, true
		case t.kind == tokenIdent:
			// Default binding.
			bindings = append(bindings, modulegraph.Binding{Imported: "default", Local: t.text, Default: true})
		case t.kind == tokenPunct && t.text == "*":
			as := e.next()
			if as.kind == tokenIdent && as.text == "as" {
				local := e.next()
				if local.kind != tokenIdent {
					e.push(local)
					return nil, false
				}
				bindings = append(bindings, modulegraph.Binding{Local: local.text, Namespace: true})
			} else {
				e.push(as)
				bindings = append(bindings, modulegraph.Binding{Namespace: true})
			}
		case t.kind == tokenPunct && t.text == "{":
			named, ok := e.readNamedBindings()
			if !ok {
				return nil, false
			}
			bindings = append(bindings, named...)
		case t.kind == tokenPunct && t.text == ",":
			// Separator between default and named/namespace clauses.
		default:
			e.push(t)
			return nil, false
		}
	}
}

// readNamedBindings consumes `{ a, b as c, type D }` after the opening brace.
func (e *extractor) readNamedBindings() ([]modulegraph.Binding, bool) {
	var bindings []modulegraph.Binding
	for {
		t := e.next()
		switch {
		case t.kind == tokenPunct && t.text == "}":
			return bindings, true
		case t.kind == tokenPunct && t.text == ",":
			continue
		case t.kind == tokenIdent || t.kind == tokenString:
			// `type X` / `type X as Y` marks a single inline type-only binding; `type as X` and
			// `type` alone are ordinary bindings named "type".
			memberTypeOnly := false
			name := t
			if t.kind == tokenIdent && t.text == "type" {
				lookahead := e.peek()
				if (lookahead.kind == tokenIdent && lookahead.text != "as") || lookahead.kind == tokenString {
					memberTypeOnly = true
					name = e.next()
				}
			}
			binding := modulegraph.Binding{Imported: name.text, Local: name.text, TypeOnly: memberTypeOnly}
			if as := e.peek(); as.kind == tokenIdent && as.text == "as" {
				e.next()
				local := e.next()
				if local.kind != tokenIdent && local.kind != tokenString {
					e.push(local)
					return nil, false
				}
				binding.Local = local.text
			}
			bindings = append(bindings, binding)
		default:
			e.push(t)
			return nil, false
		}
	}
}

// readFromSpecifier consumes `from "specifier"`, recording a hazard when the specifier is not literal.
func (e *extractor) readFromSpecifier(kw token, form string) (string, bool, bool) {
	from := e.next()
	if from.kind != tokenIdent || from.text != "from" {
		e.push(from)
		e.addHazard(hazardUnsupportedLoader, kw.line, "missing from clause in "+form)
		return "", false, false
	}
	spec := e.next()
	switch {
	case spec.kind == tokenString:
		return spec.text, spec.undecodedEscape, true
	case spec.kind == tokenTemplate && !spec.hasSubstitution:
		return spec.text, false, true
	default:
		e.push(spec)
		e.addHazard(hazardUnsupportedLoader, kw.line, "non-literal "+form+" specifier")
		return "", false, false
	}
}

// handleExportKeyword recognises the re-export forms that create a module edge:
// `export ... from "m"`, `export * from "m"`, `export * as ns from "m"`, and their type-only variants.
// A local export (`export const x = 1`) creates no edge and is skipped.
func (e *extractor) handleExportKeyword(kw token) {
	t := e.next()

	typeOnly := false
	if t.kind == tokenIdent && t.text == "type" {
		lookahead := e.peek()
		// `export type {X} from "m"` / `export type * from "m"` are type-only re-exports;
		// `export type X = ...` is a local type alias with no specifier.
		if lookahead.kind == tokenPunct && (lookahead.text == "{" || lookahead.text == "*") {
			typeOnly = true
			t = e.next()
		}
	}

	switch {
	case t.kind == tokenPunct && t.text == "*":
		var bindings []modulegraph.Binding
		if as := e.peek(); as.kind == tokenIdent && as.text == "as" {
			e.next()
			local := e.next()
			if local.kind == tokenIdent || local.kind == tokenString {
				bindings = append(bindings, modulegraph.Binding{Local: local.text, Namespace: true, TypeOnly: typeOnly})
			} else {
				e.push(local)
			}
		} else {
			bindings = append(bindings, modulegraph.Binding{Namespace: true, TypeOnly: typeOnly})
		}
		specifier, escaped, ok := e.readFromSpecifier(kw, "export")
		if !ok {
			return
		}
		e.addImport(rawImport{
			specifier: specifier,
			kind:      modulegraph.ImportReExport,
			bindings:  bindings,
			typeOnly:  typeOnly,
			position:  modulegraph.Position{Line: kw.line, Column: kw.column},
		}, escaped)
	case t.kind == tokenPunct && t.text == "{":
		bindings, ok := e.readNamedBindings()
		if !ok {
			e.addHazard(hazardUnsupportedLoader, kw.line, "unrecognised export clause")
			return
		}
		// A local re-export list (`export {a}`) has no `from` and creates no module edge.
		if from := e.peek(); from.kind != tokenIdent || from.text != "from" {
			return
		}
		specifier, escaped, sok := e.readFromSpecifier(kw, "export")
		if !sok {
			return
		}
		e.addImport(rawImport{
			specifier: specifier,
			kind:      modulegraph.ImportReExport,
			bindings:  bindings,
			typeOnly:  typeOnly,
			position:  modulegraph.Position{Line: kw.line, Column: kw.column},
		}, escaped)
	default:
		// `export default ...`, `export const ...`, `export = ...`: no module specifier.
		e.push(t)
	}
}

// handleRequire recognises every shape of the CommonJS loader.
//
// A `require` that is neither a direct call nor a known member form is itself a hazard: aliasing it
// (`const r = require; r("pkg")`), reaching it indirectly (`(0, require)("pkg")`) or calling it through a
// receiver (`module.require("pkg")`) all load a module that this scanner cannot name.
func (e *extractor) handleRequire(kw, prev, prev2 token, havePrev bool) {
	if havePrev && prev.kind == tokenPunct && (prev.text == "." || prev.text == "?.") {
		// `module.require(...)` / `require.main.require(...)` are genuine loaders; an unrelated
		// `vm.require(...)` method is not.
		if prev2.kind == tokenIdent && requireReceivers[prev2.text] {
			e.addHazard(hazardDynamicRequire, kw.line, "require through a module receiver")
		}
		return
	}

	t := e.next()
	switch {
	case t.kind == tokenPunct && t.text == ".":
		prop := e.next()
		if prop.kind == tokenIdent {
			switch prop.text {
			case "context", "ensure":
				// A reference is enough: `const ctx = require.context` aliases the loader.
				e.addHazard(hazardRequireContext, kw.line, "require."+prop.text)
				return
			case "resolve":
				// require.resolve locates a module without loading it, but a LITERAL argument still
				// names a real dependency of first-party code, so it is honest evidence of use. Only a
				// computed argument degrades coverage.
				if open := e.next(); open.kind == tokenPunct && open.text == "(" {
					if spec, escaped, ok := e.readLiteralCallArgument(); ok {
						e.addImport(rawImport{
							specifier: spec,
							kind:      modulegraph.ImportCommonJS,
							position:  modulegraph.Position{Line: kw.line, Column: kw.column},
						}, escaped)
						return
					}
				} else {
					e.push(open)
				}
				e.addHazard(hazardUnsupportedLoader, kw.line, "require.resolve")
				return
			case "main", "cache", "extensions":
				// require.main.require(...) and friends reach the loader indirectly.
				e.addHazard(hazardDynamicRequire, kw.line, "require internals accessed")
				return
			}
		}
		e.push(prop)
		e.addHazard(hazardDynamicRequire, kw.line, "unrecognised require property")
	case t.kind == tokenPunct && (t.text == "(" || t.text == "?."):
		if t.text == "?." {
			// Optional call `require?.("pkg")` still loads the module.
			if open := e.next(); open.kind != tokenPunct || open.text != "(" {
				e.push(open)
				e.addHazard(hazardDynamicRequire, kw.line, "require referenced outside a call")
				return
			}
		}
		if spec, escaped, ok := e.readLiteralCallArgument(); ok {
			e.addImport(rawImport{
				specifier: spec,
				kind:      modulegraph.ImportCommonJS,
				position:  modulegraph.Position{Line: kw.line, Column: kw.column},
			}, escaped)
			return
		}
		e.addHazard(hazardDynamicRequire, kw.line, "non-literal require specifier")
	case t.kind == tokenPunct && t.text == ":":
		// An object key named require (`{ require: fn }`) is not the loader.
		//
		// A PARAMETER named require — the UMD wrapper `function (require, exports, module) {}` — is
		// deliberately NOT excluded: lexically it is indistinguishable from `register(require)`, which
		// passes the real loader somewhere this scanner cannot follow. The false hazard costs coverage
		// utility; missing the indirection would cost a suppressed vulnerability.
		e.push(t)
	default:
		e.push(t)
		e.addHazard(hazardDynamicRequire, kw.line, "require referenced outside a call")
	}
}
