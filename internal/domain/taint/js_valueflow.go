package taint

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	maxJsValueEdges   = 4_000_000
	maxJsTaintSources = 200_000
	maxJsTaintSinks   = 1_000_000
	maxJsTaintPath    = 64
	maxJsTaintWork    = 4_000_000
)

// allJsTaintClasses is the set a fully untrusted request source taints. It is intentionally the JS subset
// that has a modeled sink today; a source can never introduce a class the engine cannot terminate in a sink.
var allJsTaintClasses = []TaintClass{
	TaintCode, TaintCommand, TaintDeserialization, TaintPathTraversal, TaintRedirect, TaintReDoS, TaintSSRF, TaintXSS,
}

// JsCallablePattern matches a JS/TS callee. Because PR1's facts carry no resolver, matching is done three
// ways, in order of trust:
//   - Modules + Names: the callee's base identifier resolves (lexically, shadow-aware) to an IMPORT of one
//     of Modules, and the accessed member matches one of Names. This is the sound, package-anchored path
//     (child_process.exec, fs.readFile, axios.get).
//   - Globals: the callee is a BARE identifier equal to one of Globals that is neither imported nor shadowed
//     by a local binding, i.e. a language global (eval, Function, fetch, Number).
//   - RawSuffixes: the callee's syntactic dotted path EQUALS one of RawSuffixes (exact, e.g. res.send,
//     document.write), and the receiver base is not a locally constructed object or import. This is the
//     receiver-NAME convention used only where a package anchor is impossible, exactly as the Python catalog
//     matches cursor.execute / session.execute, tightened for JS with receiver provenance (see
//     receiverLocallyConstructed) because res/response are more reused than cursor.
type JsCallablePattern struct {
	Modules     []string
	Names       []string
	Globals     []string
	RawSuffixes []string
	// CallModule matches a DIRECT call of the imported module or default export (`const esc =
	// require('escape-html'); esc(x)`, `got(url)`), where there is no accessed member. It matches only when
	// Modules also matches, so it stays package-anchored.
	CallModule bool
}

func (p JsCallablePattern) empty() bool {
	return len(p.Modules) == 0 && len(p.Names) == 0 && len(p.Globals) == 0 && len(p.RawSuffixes) == 0 && !p.CallModule
}

// JsSourceModel marks a call result as untrusted for the listed classes.
type JsSourceModel struct {
	Pattern JsCallablePattern
	Classes []TaintClass
}

// JsSinkModel marks selected call arguments (zero-based), or every argument, as dangerous.
type JsSinkModel struct {
	Pattern         JsCallablePattern
	Class           TaintClass
	CWE             string
	Rule            string
	ArgumentIndexes []int
	AllArguments    bool // model every argument (e.g. new Function(...args, body): any arg is program text)
}

// JsSanitizerModel neutralizes only its listed classes at the call-result slot.
type JsSanitizerModel struct {
	Pattern JsCallablePattern
	Classes []TaintClass
}

// JsCatalog is the reviewable framework/library model used by the JS value-flow builder.
type JsCatalog struct {
	// ReferenceSourcePrefixes taint a member-read value whose reference segments START WITH the prefix, e.g.
	// ["req","query"] taints req.query and req.query.id. Prefix (not suffix) matching is used because in JS
	// the request is a positional parameter, so the untrusted object is anchored at the head of the path.
	ReferenceSourcePrefixes [][]string
	Sources                 []JsSourceModel
	Sinks                   []JsSinkModel
	Sanitizers              []JsSanitizerModel
}

// JsTypedValueSource is one source slot for one taint class.
type JsTypedValueSource struct {
	ValueID string
	Class   TaintClass
	Pos     jsprogram.Position
}

// JsTypedValueSink is a synthetic sink node fed only by the modeled dangerous argument(s).
type JsTypedValueSink struct {
	ValueID string
	CallID  string
	Callee  string
	Class   TaintClass
	CWE     string
	Rule    string
	Pos     jsprogram.Position
}

// JsTypedSanitizer is a class-specific wall at a call result.
type JsTypedSanitizer struct {
	ValueID string
	Class   TaintClass
}

// JsValueFlowGraph is the precise JS/TS value graph.
type JsValueFlowGraph struct {
	Flows      []Flow
	Sources    []JsTypedValueSource
	Sinks      []JsTypedValueSink
	Sanitizers []JsTypedSanitizer
	Positions  map[string]jsprogram.Position
	Truncated  bool
}

// JsTaintPath is one typed source-to-dangerous-argument witness.
type JsTaintPath struct {
	Class     TaintClass
	CWE       string
	Rule      string
	SourceID  string
	SinkID    string
	CallID    string
	Callee    string
	Path      []string
	SourcePos jsprogram.Position
	SinkPos   jsprogram.Position
}

// jsImportBinding is one resolved local binding introduced by an import/require.
type jsImportBinding struct {
	module string
	name   string // imported member ("exec"), "default", or "" for a namespace / module object
	kind   jsprogram.ImportKind
}

// BuildJsValueGraph joins syntax value facts with import-anchored call resolution, parameter binding, and
// return flow. Unlike the Python twin it takes no separate Resolution: PR1 folded the resolver out, so the
// call binding is done here, lexically and shadow-aware, directly over the document's imports and symbols.
func BuildJsValueGraph(document jsprogram.Document, catalog JsCatalog) (JsValueFlowGraph, error) {
	if err := document.Validate(); err != nil {
		return JsValueFlowGraph{}, fmt.Errorf("build js value flow: %w", err)
	}
	if err := validateJsCatalog(catalog); err != nil {
		return JsValueFlowGraph{}, err
	}
	b := jsValueBuilder{
		document: document, catalog: catalog,
		values: map[string]jsprogram.Value{}, symbols: map[string]jsprogram.Symbol{},
		parents: map[string]string{}, definitions: map[string]map[string][]jsprogram.Value{},
		returns: map[string][]string{}, imports: map[string]map[string]jsImportBinding{},
		functionsByName: map[string]map[string][]string{}, declaredCallables: map[string]map[string]bool{},
		flows: map[string]bool{}, sources: map[string]JsTypedValueSource{}, sinks: map[string]JsTypedValueSink{},
		sanitizers: map[string]JsTypedSanitizer{}, positions: map[string]jsprogram.Position{},
	}
	b.index()
	b.addSyntaxFlows()
	b.bindReferences()
	b.modelCalls()
	b.modelReferenceSources()
	return b.finish(), nil
}

type jsValueBuilder struct {
	document        jsprogram.Document
	catalog         JsCatalog
	values          map[string]jsprogram.Value
	symbols         map[string]jsprogram.Symbol
	parents         map[string]string
	definitions     map[string]map[string][]jsprogram.Value
	returns         map[string][]string
	imports         map[string]map[string]jsImportBinding // scopeID -> localName -> binding
	functionsByName map[string]map[string][]string        // module -> function name -> symbol IDs
	// declaredCallables indexes function/class DECLARATIONS by their enclosing scope and bare name. A
	// `function fetch(){}` or `class Function{}` binds that name in its scope but emits no ValueBinding, so it
	// is invisible to the definitions map; without this index globalCallee would treat a call to the local
	// wrapper as the language global and fire a false sink (CWE-918/CWE-94).
	declaredCallables map[string]map[string]bool // scopeID -> declared function/class name -> present
	flows             map[string]bool
	sources           map[string]JsTypedValueSource
	sinks             map[string]JsTypedValueSink
	sanitizers        map[string]JsTypedSanitizer
	positions         map[string]jsprogram.Position
	truncated         bool
}

func (b *jsValueBuilder) index() {
	for _, symbol := range b.document.Symbols {
		b.symbols[symbol.ID] = symbol
		b.parents[symbol.ID] = symbol.ParentID
		if symbol.Kind == jsprogram.SymbolFunction || symbol.Kind == jsprogram.SymbolArrow || symbol.Kind == jsprogram.SymbolMethod {
			if b.functionsByName[symbol.Module] == nil {
				b.functionsByName[symbol.Module] = map[string][]string{}
			}
			b.functionsByName[symbol.Module][symbol.Name] = append(b.functionsByName[symbol.Module][symbol.Name], symbol.ID)
		}
		// A function or class DECLARATION binds its bare name in the enclosing scope (ParentID) and shadows a
		// same-named language global for that scope subtree. Methods (reached only via a receiver) and arrows
		// (assigned through a ValueBinding the definitions map already carries) are not bare-name shadows.
		if (symbol.Kind == jsprogram.SymbolFunction || symbol.Kind == jsprogram.SymbolClass) && symbol.Name != "" {
			if b.declaredCallables[symbol.ParentID] == nil {
				b.declaredCallables[symbol.ParentID] = map[string]bool{}
			}
			b.declaredCallables[symbol.ParentID][symbol.Name] = true
		}
	}
	for _, value := range b.document.Values {
		b.values[value.ID] = value
		b.positions[value.ID] = value.Pos
		if value.Kind == jsprogram.ValueParameter || value.Kind == jsprogram.ValueBinding {
			if b.definitions[value.ScopeID] == nil {
				b.definitions[value.ScopeID] = map[string][]jsprogram.Value{}
			}
			b.definitions[value.ScopeID][value.Name] = append(b.definitions[value.ScopeID][value.Name], value)
		}
	}
	for scope := range b.definitions {
		for name := range b.definitions[scope] {
			sort.Slice(b.definitions[scope][name], func(i, j int) bool {
				return jsPositionBefore(b.definitions[scope][name][i].Pos, b.definitions[scope][name][j].Pos)
			})
		}
	}
	for _, item := range b.document.Imports {
		local := item.Alias
		if local == "" || local == "*" {
			continue // a re-export or a bare namespace import introduces no callable local binding
		}
		if b.imports[item.ScopeID] == nil {
			b.imports[item.ScopeID] = map[string]jsImportBinding{}
		}
		// First binding for a name in a scope wins; a later shadowing redeclaration only reduces coverage.
		if _, exists := b.imports[item.ScopeID][local]; !exists {
			b.imports[item.ScopeID][local] = jsImportBinding{module: normalizeJsModule(item.Module), name: item.Name, kind: item.Kind}
		}
	}
	for _, item := range b.document.Returns {
		if item.SlotID != "" {
			b.returns[item.ScopeID] = append(b.returns[item.ScopeID], item.SlotID)
		}
	}
}

func (b *jsValueBuilder) addSyntaxFlows() {
	for _, flow := range b.document.Flows {
		b.addFlow(flow.FromID, flow.ToID)
	}
}

func (b *jsValueBuilder) bindReferences() {
	for _, value := range b.document.Values {
		if value.Kind != jsprogram.ValueReference || value.Ref.Kind != jsprogram.ReferenceName || len(value.Ref.Segments) != 1 {
			continue
		}
		name := value.Ref.Segments[0]
		for _, scope := range b.scopeChain(value.ScopeID) {
			definitions := b.definitions[scope][name]
			var prior []jsprogram.Value
			for _, definition := range definitions {
				if definition.Kind == jsprogram.ValueParameter || jsPositionBefore(definition.Pos, value.Pos) {
					prior = append(prior, definition)
				}
			}
			if len(prior) > 0 {
				for _, definition := range prior {
					b.addFlow(definition.ID, value.ID)
				}
				break
			}
		}
	}
}

func (b *jsValueBuilder) modelCalls() {
	for _, call := range b.document.Calls {
		local := false
		for _, symbolID := range b.localCallees(call) {
			symbol := b.symbols[symbolID]
			local = true
			b.bindCall(call, symbol)
		}
		module, member, resolved := b.resolveCatalogCallee(call)
		global, isGlobal := b.globalCallee(call)
		raw := strings.Join(call.Callee.Segments, ".")
		receiverConstructed := b.receiverLocallyConstructed(call)
		matchedRole := false
		for _, model := range b.catalog.Sources {
			if jsCallMatches(model.Pattern, module, member, resolved, global, isGlobal, raw, receiverConstructed) && call.ResultID != "" {
				matchedRole = true
				for _, class := range model.Classes {
					b.addSource(call.ResultID, class, call.Pos)
				}
			}
		}
		for index, model := range b.catalog.Sinks {
			if !jsCallMatches(model.Pattern, module, member, resolved, global, isGlobal, raw, receiverConstructed) {
				continue
			}
			matchedRole = true
			if len(b.sinks) >= maxJsTaintSinks {
				b.truncated = true
				continue
			}
			sinkID := call.ID + "#sink:" + string(model.Class) + ":" + strconv.Itoa(index)
			b.positions[sinkID] = call.Pos
			b.sinks[sinkID] = JsTypedValueSink{
				ValueID: sinkID, CallID: call.ID, Callee: jsTrustedCallee(module, member, resolved, global, isGlobal, raw),
				Class: model.Class, CWE: model.CWE, Rule: model.Rule, Pos: call.Pos,
			}
			if model.AllArguments {
				for _, argument := range call.Arguments {
					b.addFlow(argument.ValueID, sinkID)
				}
			}
			for _, argument := range model.ArgumentIndexes {
				if argument >= 0 && argument < len(call.Arguments) {
					b.addFlow(call.Arguments[argument].ValueID, sinkID)
				}
			}
		}
		for _, model := range b.catalog.Sanitizers {
			if !jsCallMatches(model.Pattern, module, member, resolved, global, isGlobal, raw, receiverConstructed) || call.ResultID == "" {
				continue
			}
			matchedRole = true
			b.propagateCallInputs(call)
			for _, class := range model.Classes {
				key := call.ResultID + "\x00" + string(class)
				b.sanitizers[key] = JsTypedSanitizer{ValueID: call.ResultID, Class: class}
			}
		}
		// Local callees have explicit parameter/return edges. An unknown/external call conservatively
		// propagates its receiver and arguments into its result so taint survives a pass through an
		// unmodeled transformer (str.trim(), Buffer.from(x)), unless a source/sink/sanitizer model already
		// gives the call its semantics.
		if !local && !matchedRole {
			b.propagateCallInputs(call)
		}
	}
}

// localCallees returns the in-document function/arrow symbols a bare, unshadowed call resolves to. Only a
// bare-name call to a uniquely-named module-level function is bound: an ambiguous name, a member call, or a
// name shadowed by a parameter/binding/import is left unbound (a missed interprocedural edge, never a wrong
// one).
func (b *jsValueBuilder) localCallees(call jsprogram.Call) []string {
	if call.Callee.Kind != jsprogram.ReferenceName || len(call.Callee.Segments) != 1 {
		return nil
	}
	name := call.Callee.Segments[0]
	for _, scope := range b.scopeChain(call.CallerID) {
		if len(b.definitions[scope][name]) > 0 {
			return nil // shadowed by a local parameter/binding
		}
		if _, ok := b.imports[scope][name]; ok {
			return nil // the name is an import, not a local function
		}
	}
	symbol, ok := b.symbols[call.CallerID]
	if !ok {
		return nil
	}
	candidates := b.functionsByName[symbol.Module][name]
	if len(candidates) != 1 {
		return nil // absent or ambiguous
	}
	callee := b.symbols[candidates[0]]
	if callee.Kind != jsprogram.SymbolFunction && callee.Kind != jsprogram.SymbolArrow {
		return nil // a bare call never targets a method
	}
	if callee.QualifiedName != name {
		return nil // only a module-level function (qualified name == bare name) is reachable by a bare call
	}
	return []string{callee.ID}
}

func (b *jsValueBuilder) bindCall(call jsprogram.Call, callee jsprogram.Symbol) {
	parameters := callee.Parameters
	positional := 0
	for _, argument := range call.Arguments {
		if argument.ValueID == "" {
			continue
		}
		if argument.Spread {
			// A spread argument can land in any remaining parameter, so conservatively feed all of them.
			for i := positional; i < len(parameters); i++ {
				b.addFlow(argument.ValueID, parameters[i].ValueID)
			}
			continue
		}
		if positional < len(parameters) {
			b.addFlow(argument.ValueID, parameters[positional].ValueID)
			if parameters[positional].Kind != jsprogram.ParameterRest {
				positional++ // a rest parameter absorbs this and every later positional argument
			}
		}
	}
	for _, returnID := range b.returns[callee.ID] {
		b.addFlow(returnID, call.ResultID)
	}
}

func (b *jsValueBuilder) propagateCallInputs(call jsprogram.Call) {
	for _, argument := range call.Arguments {
		b.addFlow(argument.ValueID, call.ResultID)
	}
	b.addFlow(call.ReceiverValueID, call.ResultID)
}

// resolveCatalogCallee resolves the callee's base identifier to an import and returns the anchored
// (module, member) pair. member is "" when the module object itself is invoked or when the base is the
// default/namespace object called directly.
func (b *jsValueBuilder) resolveCatalogCallee(call jsprogram.Call) (module, member string, ok bool) {
	segments := call.Callee.Segments
	if (call.Callee.Kind != jsprogram.ReferenceName && call.Callee.Kind != jsprogram.ReferenceAttribute) || len(segments) == 0 {
		return "", "", false
	}
	base := segments[0]
	binding, isImport := b.resolveImport(call.CallerID, base)
	if !isImport {
		return "", "", false
	}
	rest := segments[1:]
	switch binding.kind {
	case jsprogram.ImportNamed, jsprogram.ImportRequire:
		if binding.name != "" && binding.name != "default" {
			// The base IS the imported function; a member access appends to it (fs promises.readFile style).
			member = binding.name
			if len(rest) > 0 {
				member += "." + strings.Join(rest, ".")
			}
			return binding.module, member, true
		}
		// A namespace-style require (`const fs = require('fs')`) or default require: the base is the module
		// object, so the member is the accessed path.
		return binding.module, strings.Join(rest, "."), true
	case jsprogram.ImportDefault, jsprogram.ImportNamespace:
		// The base is the default export or the namespace object; the member is the accessed path.
		return binding.module, strings.Join(rest, "."), true
	default:
		return "", "", false
	}
}

// globalCallee reports a bare-name callee that is neither imported nor shadowed by a local binding, i.e. a
// language/runtime global (eval, Function, fetch, Number).
func (b *jsValueBuilder) globalCallee(call jsprogram.Call) (string, bool) {
	if call.Callee.Kind != jsprogram.ReferenceName || len(call.Callee.Segments) != 1 {
		return "", false
	}
	name := call.Callee.Segments[0]
	for _, scope := range b.scopeChain(call.CallerID) {
		if len(b.definitions[scope][name]) > 0 {
			return "", false
		}
		if _, ok := b.imports[scope][name]; ok {
			return "", false
		}
		if b.declaredCallables[scope][name] {
			return "", false // a local function/class declaration of this name shadows the global
		}
	}
	return name, true
}

// resolveImport finds the lexical import binding for name in scope, treating any local parameter/binding of
// the same name in a nearer scope as a shadow that removes the import. Over-treating a name as shadowed only
// loses an edge; it never invents one, which is the safe direction against a false finding.
func (b *jsValueBuilder) resolveImport(scopeID, name string) (jsImportBinding, bool) {
	for _, scope := range b.scopeChain(scopeID) {
		if len(b.definitions[scope][name]) > 0 {
			return jsImportBinding{}, false // shadowed by a local parameter/binding
		}
		if binding, ok := b.imports[scope][name]; ok {
			return binding, true
		}
	}
	return jsImportBinding{}, false
}

func (b *jsValueBuilder) modelReferenceSources() {
	if len(b.catalog.ReferenceSourcePrefixes) == 0 {
		return
	}
	for _, value := range b.document.Values {
		if value.Kind != jsprogram.ValueReference {
			continue
		}
		if value.Ref.Kind != jsprogram.ReferenceName && value.Ref.Kind != jsprogram.ReferenceAttribute {
			continue
		}
		if !jsSegmentsMatchAnyPrefix(value.Ref.Segments, b.catalog.ReferenceSourcePrefixes) {
			continue
		}
		for _, class := range allJsTaintClasses {
			b.addSource(value.ID, class, value.Pos)
		}
	}
}

func (b *jsValueBuilder) addFlow(from, to string) {
	if from == "" || to == "" || from == to || b.truncated {
		return
	}
	key := from + "\x00" + to
	if b.flows[key] {
		return
	}
	if len(b.flows) >= maxJsValueEdges {
		b.truncated = true
		return
	}
	b.flows[key] = true
}

func (b *jsValueBuilder) addSource(valueID string, class TaintClass, pos jsprogram.Position) {
	if valueID == "" || !class.Valid() || len(b.sources) >= maxJsTaintSources {
		if len(b.sources) >= maxJsTaintSources {
			b.truncated = true
		}
		return
	}
	key := valueID + "\x00" + string(class)
	b.sources[key] = JsTypedValueSource{ValueID: valueID, Class: class, Pos: pos}
}

func (b *jsValueBuilder) scopeChain(scope string) []string {
	var out []string
	seen := map[string]bool{}
	for scope != "" && !seen[scope] {
		seen[scope] = true
		out = append(out, scope)
		scope = b.parents[scope]
	}
	return out
}

func (b *jsValueBuilder) finish() JsValueFlowGraph {
	graph := JsValueFlowGraph{Positions: b.positions, Truncated: b.truncated}
	for key := range b.flows {
		parts := strings.SplitN(key, "\x00", 2)
		graph.Flows = append(graph.Flows, Flow{From: parts[0], To: parts[1]})
	}
	for _, source := range b.sources {
		graph.Sources = append(graph.Sources, source)
	}
	for _, sink := range b.sinks {
		if len(graph.Sinks) >= maxJsTaintSinks {
			graph.Truncated = true
			break
		}
		graph.Sinks = append(graph.Sinks, sink)
	}
	for _, sanitizer := range b.sanitizers {
		graph.Sanitizers = append(graph.Sanitizers, sanitizer)
	}
	sort.Slice(graph.Flows, func(i, j int) bool {
		if graph.Flows[i].From != graph.Flows[j].From {
			return graph.Flows[i].From < graph.Flows[j].From
		}
		return graph.Flows[i].To < graph.Flows[j].To
	})
	sort.Slice(graph.Sources, func(i, j int) bool {
		if graph.Sources[i].ValueID != graph.Sources[j].ValueID {
			return graph.Sources[i].ValueID < graph.Sources[j].ValueID
		}
		return graph.Sources[i].Class < graph.Sources[j].Class
	})
	sort.Slice(graph.Sinks, func(i, j int) bool {
		if graph.Sinks[i].ValueID != graph.Sinks[j].ValueID {
			return graph.Sinks[i].ValueID < graph.Sinks[j].ValueID
		}
		return graph.Sinks[i].Class < graph.Sinks[j].Class
	})
	sort.Slice(graph.Sanitizers, func(i, j int) bool {
		if graph.Sanitizers[i].ValueID != graph.Sanitizers[j].ValueID {
			return graph.Sanitizers[i].ValueID < graph.Sanitizers[j].ValueID
		}
		return graph.Sanitizers[i].Class < graph.Sanitizers[j].Class
	})
	return graph
}

// Vulnerabilities returns deterministic, bounded, class-aware value-flow witnesses.
func (g *JsValueFlowGraph) Vulnerabilities() []JsTaintPath {
	return g.vulnerabilities(maxJsTaintWork)
}

func (g *JsValueFlowGraph) vulnerabilities(maxWork int) []JsTaintPath {
	adjacency := map[string][]string{}
	for _, flow := range g.Flows {
		if flow.From != "" && flow.To != "" {
			adjacency[flow.From] = append(adjacency[flow.From], flow.To)
		}
	}
	for from := range adjacency {
		sort.Strings(adjacency[from])
	}
	sinks := map[string][]JsTypedValueSink{}
	for _, sink := range g.Sinks {
		sinks[sink.ValueID] = append(sinks[sink.ValueID], sink)
	}
	sanitized := map[string]bool{}
	for _, sanitizer := range g.Sanitizers {
		sanitized[sanitizer.ValueID+"\x00"+string(sanitizer.Class)] = true
	}
	var findings []JsTaintPath
	seenFinding := map[string]bool{}
	work := 0
	for _, source := range g.Sources {
		queue := []string{source.ValueID}
		seen := map[string]bool{source.ValueID: true}
		parent := map[string]string{}
		depth := map[string]int{source.ValueID: 1}
		for len(queue) > 0 {
			work++
			if work > maxWork {
				g.Truncated = true
				return sortedJsTaintPaths(findings)
			}
			currentID := queue[0]
			queue = queue[1:]
			for _, sink := range sinks[currentID] {
				if sink.Class != source.Class {
					continue
				}
				key := source.ValueID + "\x00" + sink.ValueID + "\x00" + string(sink.Class) + "\x00" + sink.Rule
				if seenFinding[key] {
					continue
				}
				seenFinding[key] = true
				findings = append(findings, JsTaintPath{
					Class: sink.Class, CWE: sink.CWE, Rule: sink.Rule, SourceID: source.ValueID,
					SinkID: sink.ValueID, CallID: sink.CallID, Callee: sink.Callee,
					Path: reconstructJsTaintPath(parent, source.ValueID, currentID), SourcePos: source.Pos, SinkPos: sink.Pos,
				})
			}
			if depth[currentID] >= maxJsTaintPath || sanitized[currentID+"\x00"+string(source.Class)] {
				continue
			}
			for _, next := range adjacency[currentID] {
				if seen[next] {
					continue
				}
				seen[next] = true
				parent[next] = currentID
				depth[next] = depth[currentID] + 1
				queue = append(queue, next)
			}
		}
	}
	return sortedJsTaintPaths(findings)
}

func reconstructJsTaintPath(parent map[string]string, source, node string) []string {
	path := []string{node}
	for cur := node; cur != source; {
		prev, ok := parent[cur]
		if !ok {
			break
		}
		path = append(path, prev)
		cur = prev
	}
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	return path
}

func sortedJsTaintPaths(findings []JsTaintPath) []JsTaintPath {
	sort.Slice(findings, func(i, j int) bool {
		left := string(findings[i].Class) + "\x00" + findings[i].SourceID + "\x00" + findings[i].SinkID
		right := string(findings[j].Class) + "\x00" + findings[j].SourceID + "\x00" + findings[j].SinkID
		return left < right
	})
	return findings
}

func jsCallMatches(pattern JsCallablePattern, module, member string, resolved bool, global string, isGlobal bool, raw string, receiverConstructed bool) bool {
	if isGlobal && len(pattern.Globals) > 0 && containsString(pattern.Globals, global) {
		return true
	}
	if resolved && len(pattern.Modules) > 0 && jsMatchesModule(module, pattern.Modules) {
		if pattern.CallModule && member == "" {
			return true
		}
		if len(pattern.Names) > 0 && member != "" && matchesAnyName(member, pattern.Names) {
			return true
		}
	}
	// The receiver-NAME convention (res.send, document.write) matches the EXACT dotted path only, and only
	// when the receiver is not a locally constructed object or an import. A deeper path (widget.document.write)
	// or a `const res = {...}` plain object is not the framework request/response object, so it is not matched;
	// that coverage gap is the safe direction against a false finding.
	if !receiverConstructed {
		for _, suffix := range pattern.RawSuffixes {
			if raw == suffix {
				return true
			}
		}
	}
	return false
}

// receiverLocallyConstructed reports whether the callee's base identifier resolves to a locally CONSTRUCTED
// value (a const/let/var binding) or an import in the nearest scope that declares it. Express binds the
// request/response as PARAMETERS (`(req, res) => ...`), so a parameter (or an undeclared free/global name
// such as the DOM `document`) is the convention and does NOT disqualify; a `const res = { send() {} }` plain
// object, or an imported name, is not a framework response and must not satisfy the receiver-name convention.
func (b *jsValueBuilder) receiverLocallyConstructed(call jsprogram.Call) bool {
	segments := call.Callee.Segments
	if len(segments) == 0 {
		return false
	}
	base := segments[0]
	for _, scope := range b.scopeChain(call.CallerID) {
		if defs := b.definitions[scope][base]; len(defs) > 0 {
			for _, def := range defs {
				if def.Kind == jsprogram.ValueParameter {
					return false // the Express (req, res) handler convention: a parameter is the real object
				}
			}
			return true // only const/let/var bindings of this name in the nearest scope: a constructed object
		}
		if _, ok := b.imports[scope][base]; ok {
			return true // an imported name is not a request/response object
		}
	}
	return false
}

// jsMatchesModule matches an import specifier against the catalog's bare module names. The specifier's
// "node:" builtin prefix is normalized away before matching, and a scoped subpath ("lodash/fp") matches its
// package root ("lodash").
func jsMatchesModule(module string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if module == pattern || strings.HasPrefix(module, pattern+"/") {
			return true
		}
	}
	return false
}

func normalizeJsModule(module string) string {
	return strings.TrimPrefix(module, "node:")
}

// jsTrustedCallee builds a stable, non-sensitive callee label for the witness metadata.
func jsTrustedCallee(module, member string, resolved bool, global string, isGlobal bool, raw string) string {
	switch {
	case resolved:
		if member == "" {
			return "js:" + module
		}
		return "js:" + module + ":" + member
	case isGlobal:
		return "js:global:" + global
	case raw != "":
		if len(raw) > 256 {
			return "js:unresolved"
		}
		return "js:syntactic:" + raw
	default:
		return "js:unresolved"
	}
}

func jsSegmentsMatchAnyPrefix(segments []string, prefixes [][]string) bool {
	for _, prefix := range prefixes {
		if jsSegmentsHavePrefix(segments, prefix) {
			return true
		}
	}
	return false
}

func jsSegmentsHavePrefix(segments, prefix []string) bool {
	if len(prefix) == 0 || len(segments) < len(prefix) {
		return false
	}
	for i := range prefix {
		if segments[i] != prefix[i] {
			return false
		}
	}
	return true
}

func validateJsCatalog(catalog JsCatalog) error {
	if len(catalog.Sinks) == 0 {
		return fmt.Errorf("%w: JS taint catalog needs sinks", shared.ErrValidation)
	}
	hasSource := len(catalog.ReferenceSourcePrefixes) > 0 || len(catalog.Sources) > 0
	if !hasSource {
		return fmt.Errorf("%w: JS taint catalog needs sources", shared.ErrValidation)
	}
	for _, source := range catalog.Sources {
		if source.Pattern.empty() {
			return fmt.Errorf("%w: JS source model needs a pattern", shared.ErrValidation)
		}
		for _, class := range source.Classes {
			if !class.Valid() {
				return fmt.Errorf("%w: invalid JS source taint class", shared.ErrValidation)
			}
		}
	}
	for _, prefix := range catalog.ReferenceSourcePrefixes {
		if len(prefix) == 0 {
			return fmt.Errorf("%w: JS reference source prefix cannot be empty", shared.ErrValidation)
		}
	}
	for _, sink := range catalog.Sinks {
		if sink.Pattern.empty() {
			return fmt.Errorf("%w: JS sink model needs a pattern", shared.ErrValidation)
		}
		if !sink.Class.Valid() || !strings.HasPrefix(sink.CWE, "CWE-") || sink.Rule == "" {
			return fmt.Errorf("%w: invalid JS sink model", shared.ErrValidation)
		}
		if !sink.AllArguments && len(sink.ArgumentIndexes) == 0 {
			return fmt.Errorf("%w: JS sink model models no argument", shared.ErrValidation)
		}
	}
	for _, sanitizer := range catalog.Sanitizers {
		if sanitizer.Pattern.empty() {
			return fmt.Errorf("%w: JS sanitizer model needs a pattern", shared.ErrValidation)
		}
		for _, class := range sanitizer.Classes {
			if !class.Valid() {
				return fmt.Errorf("%w: invalid JS sanitizer taint class", shared.ErrValidation)
			}
		}
	}
	return nil
}

func jsPositionBefore(left, right jsprogram.Position) bool {
	if left.File != right.File {
		return left.File < right.File
	}
	if left.Line != right.Line {
		return left.Line < right.Line
	}
	return left.Column < right.Column
}
