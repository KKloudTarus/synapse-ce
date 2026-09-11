package taint

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/javaprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	maxJavaValueEdges   = 4_000_000
	maxJavaTaintSources = 200_000
	maxJavaTaintSinks   = 1_000_000
	maxJavaTaintPath    = 64
	maxJavaTaintWork    = 4_000_000
)

// allJavaTaintClasses is the set a fully untrusted request source taints. It is intentionally the Java
// subset with a MODELED sink today (a source never introduces a class the engine has no sink to terminate);
// it grows as DefaultJavaCatalog gains sinks for XSS/LDAP/XPath/XXE/SSTI/log.
var allJavaTaintClasses = []TaintClass{
	TaintCommand, TaintPathTraversal, TaintSQL, TaintSSRF, TaintDeserialization, TaintCode,
}

// JavaCallablePattern matches a Java callee. Java has NO bare language globals, so matching is two-tiered:
//   - Modules + Names / CallModule / Constructor: the callee's base identifier resolves (via an import, or a
//     fully-qualified path) to one of Modules, and the accessed member matches one of Names (or it is a
//     direct call of a statically-imported name, or a `new` of an imported type). This is the sound,
//     import-anchored tier (Runtime.getRuntime().exec via java.lang.Runtime, new java.io.File, Paths.get).
//   - RawSuffixes: the callee's syntactic dotted path ENDS WITH one of RawSuffixes (method-name suffix,
//     e.g. ".executeQuery"). This is the RECEIVER-TYPED floor for instance methods whose receiver is a
//     runtime value the source-only facts cannot type (stmt.executeQuery, request.getParameter). It is
//     looser and more FP-prone than the import anchor, and is used only where a type anchor is impossible;
//     findings are propose-only and separately verified, exactly as the Python cursor.execute floor.
type JavaCallablePattern struct {
	Modules     []string
	Names       []string
	RawSuffixes []string
	// RawConstructor matches a `new X(...)` whose type-name path ends with one of these, for an AUTO-IMPORTED
	// type (java.lang.ProcessBuilder) that has no import to anchor. It fires ONLY on a constructor call, so a
	// same-named ordinary method never matches.
	RawConstructor []string
	CallModule     bool // a direct call of a statically-imported name (import static ...max; max(x))
	Constructor    bool // matches only a `new X(...)` (object_creation) call of an imported/FQ type
}

func (p JavaCallablePattern) empty() bool {
	return len(p.Modules) == 0 && len(p.Names) == 0 && len(p.RawSuffixes) == 0 && len(p.RawConstructor) == 0 && !p.CallModule && !p.Constructor
}

// JavaSourceModel marks a call result as untrusted for the listed classes.
type JavaSourceModel struct {
	Pattern JavaCallablePattern
	Classes []TaintClass
}

// JavaSinkModel marks selected call arguments (zero-based), or every argument, as dangerous.
type JavaSinkModel struct {
	Pattern         JavaCallablePattern
	Class           TaintClass
	CWE             string
	Rule            string
	ArgumentIndexes []int
	AllArguments    bool
}

// JavaSanitizerModel neutralizes only its listed classes at the call-result slot.
type JavaSanitizerModel struct {
	Pattern JavaCallablePattern
	Classes []TaintClass
}

// JavaCatalog is the reviewable framework/library model used by the Java value-flow builder.
type JavaCatalog struct {
	// SourceAnnotations are the SIMPLE names of parameter annotations that mark a controller parameter as
	// untrusted web input (Spring @RequestParam, @RequestBody, @PathVariable, ...). A parameter carrying one
	// becomes a fully-untrusted source, the annotation analog of the JS request-object prefix.
	SourceAnnotations []string
	Sources           []JavaSourceModel
	Sinks             []JavaSinkModel
	Sanitizers        []JavaSanitizerModel
}

// JavaTypedValueSource is one source slot for one taint class.
type JavaTypedValueSource struct {
	ValueID string
	Class   TaintClass
	Pos     javaprogram.Position
}

// JavaTypedValueSink is a synthetic sink node fed only by the modeled dangerous argument(s).
type JavaTypedValueSink struct {
	ValueID string
	CallID  string
	Callee  string
	Class   TaintClass
	CWE     string
	Rule    string
	Pos     javaprogram.Position
}

// JavaTypedSanitizer is a class-specific wall at a call result.
type JavaTypedSanitizer struct {
	ValueID string
	Class   TaintClass
}

// JavaValueFlowGraph is the precise Java value graph.
type JavaValueFlowGraph struct {
	Flows      []Flow
	Sources    []JavaTypedValueSource
	Sinks      []JavaTypedValueSink
	Sanitizers []JavaTypedSanitizer
	Positions  map[string]javaprogram.Position
	Truncated  bool
}

// JavaTaintPath is one typed source-to-dangerous-argument witness.
type JavaTaintPath struct {
	Class     TaintClass
	CWE       string
	Rule      string
	SourceID  string
	SinkID    string
	CallID    string
	Callee    string
	Path      []string
	SourcePos javaprogram.Position
	SinkPos   javaprogram.Position
}

// javaImportBinding is one resolved local binding introduced by an import.
type javaImportBinding struct {
	module string // the imported package or type FQN ("java.sql.Statement", "java.lang.Runtime")
	name   string // the imported simple name, or the static member name
	kind   javaprogram.ImportKind
}

// BuildJavaValueGraph joins syntax value facts with import-anchored call resolution, parameter binding,
// return flow, and annotation-driven sources. Like the JS twin it takes no separate resolver: the call
// binding is done here, lexically and shadow-aware, over the document's imports and symbols.
func BuildJavaValueGraph(document javaprogram.Document, catalog JavaCatalog) (JavaValueFlowGraph, error) {
	if err := document.Validate(); err != nil {
		return JavaValueFlowGraph{}, fmt.Errorf("build java value flow: %w", err)
	}
	if err := validateJavaCatalog(catalog); err != nil {
		return JavaValueFlowGraph{}, err
	}
	b := javaValueBuilder{
		document: document, catalog: catalog,
		values: map[string]javaprogram.Value{}, symbols: map[string]javaprogram.Symbol{},
		parents: map[string]string{}, definitions: map[string]map[string][]javaprogram.Value{},
		returns: map[string][]string{}, imports: map[string]map[string]javaImportBinding{},
		methodsByName: map[string][]string{}, declaredCallables: map[string]map[string]bool{},
		flows: map[string]bool{}, sources: map[string]JavaTypedValueSource{}, sinks: map[string]JavaTypedValueSink{},
		sanitizers: map[string]JavaTypedSanitizer{}, positions: map[string]javaprogram.Position{},
	}
	b.index()
	b.addSyntaxFlows()
	b.bindReferences()
	b.modelCalls()
	b.modelAnnotationSources()
	return b.finish(), nil
}

type javaValueBuilder struct {
	document          javaprogram.Document
	catalog           JavaCatalog
	values            map[string]javaprogram.Value
	symbols           map[string]javaprogram.Symbol
	parents           map[string]string
	definitions       map[string]map[string][]javaprogram.Value
	returns           map[string][]string
	imports           map[string]map[string]javaImportBinding // scopeID -> localName -> binding
	methodsByName     map[string][]string                     // "module\x00name" -> symbol IDs
	declaredCallables map[string]map[string]bool              // scopeID -> declared method/type name -> present
	flows             map[string]bool
	sources           map[string]JavaTypedValueSource
	sinks             map[string]JavaTypedValueSink
	sanitizers        map[string]JavaTypedSanitizer
	positions         map[string]javaprogram.Position
	truncated         bool
}

func (b *javaValueBuilder) index() {
	for _, symbol := range b.document.Symbols {
		b.symbols[symbol.ID] = symbol
		b.parents[symbol.ID] = symbol.ParentID
		if symbol.Kind == javaprogram.SymbolMethod || symbol.Kind == javaprogram.SymbolConstructor || symbol.Kind == javaprogram.SymbolLambda {
			key := symbol.Module + "\x00" + symbol.Name
			b.methodsByName[key] = append(b.methodsByName[key], symbol.ID)
		}
		if (symbol.Kind == javaprogram.SymbolMethod || symbol.Kind == javaprogram.SymbolClass || symbol.Kind == javaprogram.SymbolInterface) && symbol.Name != "" {
			if b.declaredCallables[symbol.ParentID] == nil {
				b.declaredCallables[symbol.ParentID] = map[string]bool{}
			}
			b.declaredCallables[symbol.ParentID][symbol.Name] = true
		}
	}
	for _, value := range b.document.Values {
		b.values[value.ID] = value
		b.positions[value.ID] = value.Pos
		if value.Kind == javaprogram.ValueParameter || value.Kind == javaprogram.ValueBinding {
			if b.definitions[value.ScopeID] == nil {
				b.definitions[value.ScopeID] = map[string][]javaprogram.Value{}
			}
			b.definitions[value.ScopeID][value.Name] = append(b.definitions[value.ScopeID][value.Name], value)
		}
	}
	for scope := range b.definitions {
		for name := range b.definitions[scope] {
			sort.Slice(b.definitions[scope][name], func(i, j int) bool {
				return javaPositionBefore(b.definitions[scope][name][i].Pos, b.definitions[scope][name][j].Pos)
			})
		}
	}
	for _, item := range b.document.Imports {
		local := javaImportLocal(item)
		if local == "" {
			continue // an on-demand import introduces no specific callable binding
		}
		if b.imports[item.ScopeID] == nil {
			b.imports[item.ScopeID] = map[string]javaImportBinding{}
		}
		if _, exists := b.imports[item.ScopeID][local]; !exists {
			b.imports[item.ScopeID][local] = javaImportBinding{module: item.Module, name: item.Name, kind: item.Kind}
		}
	}
	for _, item := range b.document.Returns {
		if item.SlotID != "" {
			b.returns[item.ScopeID] = append(b.returns[item.ScopeID], item.SlotID)
		}
	}
}

// javaImportLocal is the local name a single-import binds. `import java.sql.Statement;` binds "Statement";
// `import static java.lang.Math.max;` binds "max". On-demand imports bind no specific name.
func javaImportLocal(item javaprogram.Import) string {
	switch item.Kind {
	case javaprogram.ImportSingle, javaprogram.ImportStatic:
		if item.Name != "" {
			return item.Name
		}
	}
	return ""
}

func (b *javaValueBuilder) addSyntaxFlows() {
	for _, flow := range b.document.Flows {
		b.addFlow(flow.FromID, flow.ToID)
	}
}

func (b *javaValueBuilder) bindReferences() {
	for _, value := range b.document.Values {
		if value.Kind != javaprogram.ValueReference || value.Ref.Kind != javaprogram.ReferenceName || len(value.Ref.Segments) != 1 {
			continue
		}
		name := value.Ref.Segments[0]
		for _, scope := range b.scopeChain(value.ScopeID) {
			definitions := b.definitions[scope][name]
			var prior []javaprogram.Value
			for _, definition := range definitions {
				if definition.Kind == javaprogram.ValueParameter || javaPositionBefore(definition.Pos, value.Pos) {
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

func (b *javaValueBuilder) modelCalls() {
	for _, call := range b.document.Calls {
		local := false
		for _, symbolID := range b.localCallees(call) {
			local = true
			b.bindCall(call, b.symbols[symbolID])
		}
		module, member, resolved := b.resolveCatalogCallee(call)
		raw := strings.Join(call.Callee.Segments, ".")
		matchedRole := false
		for _, model := range b.catalog.Sources {
			if javaCallMatches(model.Pattern, module, member, resolved, raw, call.New) && call.ResultID != "" {
				matchedRole = true
				for _, class := range model.Classes {
					b.addSource(call.ResultID, class, call.Pos)
				}
			}
		}
		for index, model := range b.catalog.Sinks {
			if !javaCallMatches(model.Pattern, module, member, resolved, raw, call.New) {
				continue
			}
			matchedRole = true
			if len(b.sinks) >= maxJavaTaintSinks {
				b.truncated = true
				continue
			}
			sinkID := call.ID + "#sink:" + string(model.Class) + ":" + strconv.Itoa(index)
			b.positions[sinkID] = call.Pos
			b.sinks[sinkID] = JavaTypedValueSink{
				ValueID: sinkID, CallID: call.ID, Callee: javaTrustedCallee(module, member, resolved, raw),
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
			if !javaCallMatches(model.Pattern, module, member, resolved, raw, call.New) || call.ResultID == "" {
				continue
			}
			matchedRole = true
			b.propagateCallInputs(call)
			for _, class := range model.Classes {
				key := call.ResultID + "\x00" + string(class)
				b.sanitizers[key] = JavaTypedSanitizer{ValueID: call.ResultID, Class: class}
			}
		}
		// An unmodeled external call conservatively propagates its receiver + arguments into its result so
		// taint survives a pass through an unmodeled transformer (String.trim(), StringBuilder.append(x)),
		// unless a local binding or a role model already gives the call its semantics.
		if !local && !matchedRole {
			b.propagateCallInputs(call)
		}
	}
}

// localCallees returns the in-document method a bare, unshadowed call resolves to. Only a bare-name call
// with a single unambiguous same-module method target is bound: an ambiguous name, a member call, or a name
// shadowed by a local binding/import is left unbound (a missed edge, never a wrong one, the safe direction
// against a false finding).
func (b *javaValueBuilder) localCallees(call javaprogram.Call) []string {
	if call.New || call.Callee.Kind != javaprogram.ReferenceName || len(call.Callee.Segments) != 1 {
		return nil
	}
	name := call.Callee.Segments[0]
	for _, scope := range b.scopeChain(call.CallerID) {
		if len(b.definitions[scope][name]) > 0 {
			return nil
		}
		if _, ok := b.imports[scope][name]; ok {
			return nil
		}
	}
	symbol, ok := b.symbols[call.CallerID]
	if !ok {
		return nil
	}
	candidates := b.methodsByName[symbol.Module+"\x00"+name]
	if len(candidates) != 1 {
		return nil // absent or ambiguous (overloads): skip rather than bind the wrong method
	}
	callee := b.symbols[candidates[0]]
	if callee.Kind != javaprogram.SymbolMethod {
		return nil
	}
	return []string{callee.ID}
}

func (b *javaValueBuilder) bindCall(call javaprogram.Call, callee javaprogram.Symbol) {
	parameters := callee.Parameters
	positional := 0
	for _, argument := range call.Arguments {
		if argument.ValueID == "" {
			continue
		}
		if positional < len(parameters) {
			b.addFlow(argument.ValueID, parameters[positional].ValueID)
			if parameters[positional].Kind != javaprogram.ParameterVararg {
				positional++ // a vararg absorbs this and every later positional argument
			}
		}
	}
	for _, returnID := range b.returns[callee.ID] {
		b.addFlow(returnID, call.ResultID)
	}
}

func (b *javaValueBuilder) propagateCallInputs(call javaprogram.Call) {
	for _, argument := range call.Arguments {
		b.addFlow(argument.ValueID, call.ResultID)
	}
	b.addFlow(call.ReceiverValueID, call.ResultID)
}

// resolveCatalogCallee resolves the callee's base identifier to an import and returns the anchored
// (module, member) pair. member is "" when the imported name is invoked directly (a static import) or when
// a type is constructed. It does not resolve a receiver whose base is a runtime variable (the SQLi/exec
// instance-method case), which is why those sinks fall to the RawSuffixes floor.
func (b *javaValueBuilder) resolveCatalogCallee(call javaprogram.Call) (module, member string, ok bool) {
	segments := call.Callee.Segments
	if (call.Callee.Kind != javaprogram.ReferenceName && call.Callee.Kind != javaprogram.ReferenceAttribute) || len(segments) == 0 {
		return "", "", false
	}
	base := segments[0]
	rest := segments[1:]
	if binding, isImport := b.resolveImport(call.CallerID, base); isImport {
		switch binding.kind {
		case javaprogram.ImportSingle:
			// The base IS the imported type; the member is the accessed path (Runtime.getRuntime().exec ->
			// module java.lang.Runtime, member getRuntime.exec). A bare `new File(...)` has no member.
			return binding.module, strings.Join(rest, "."), true
		case javaprogram.ImportStatic:
			// A statically-imported member invoked directly (max(x)) or with a trailing access.
			member := binding.name
			if len(rest) > 0 {
				member += "." + strings.Join(rest, ".")
			}
			return binding.module, member, true
		}
	}
	// A fully-qualified callee with no import (`new java.io.File(x)`, `java.nio.file.Paths.get(x)`): the base
	// is a package segment, not a binding, so the whole path is the anchor. A local named like a package
	// (a variable `java`) shadows it, so it is checked against the scope's definitions first.
	if len(segments) >= 2 && looksLikePackageBase(base) && !b.baseShadowed(call.CallerID, base) {
		return raw(segments), lastSegment(segments), true
	}
	return "", "", false
}

// baseShadowed reports whether a local binding of name exists in the caller's scope chain, so a callee base
// that looks like a package is actually a local variable.
func (b *javaValueBuilder) baseShadowed(scopeID, name string) bool {
	for _, scope := range b.scopeChain(scopeID) {
		if len(b.definitions[scope][name]) > 0 {
			return true
		}
	}
	return false
}

// resolveImport finds the lexical import binding for name in scope, treating any local binding of the same
// name in a nearer scope as a shadow that removes the import (over-treating as shadowed only loses an edge).
func (b *javaValueBuilder) resolveImport(scopeID, name string) (javaImportBinding, bool) {
	for _, scope := range b.scopeChain(scopeID) {
		if len(b.definitions[scope][name]) > 0 {
			return javaImportBinding{}, false
		}
		if binding, ok := b.imports[scope][name]; ok {
			return binding, true
		}
	}
	return javaImportBinding{}, false
}

// modelAnnotationSources taints a controller parameter whose declaration carries a web-input annotation
// (Spring @RequestParam/@RequestBody/@PathVariable/...). The annotation-bound parameter value slot becomes a
// fully untrusted source for every class the engine can terminate, the annotation analog of a request object.
func (b *javaValueBuilder) modelAnnotationSources() {
	if len(b.catalog.SourceAnnotations) == 0 {
		return
	}
	classes := javaSourceClasses(b.catalog)
	for _, symbol := range b.document.Symbols {
		for _, parameter := range symbol.Parameters {
			if parameter.ValueID == "" || !javaParamHasSourceAnnotation(parameter, b.catalog.SourceAnnotations) {
				continue
			}
			for _, class := range classes {
				b.addSource(parameter.ValueID, class, parameter.Pos)
			}
		}
	}
}

func javaParamHasSourceAnnotation(parameter javaprogram.Parameter, sourceAnnotations []string) bool {
	for _, annotation := range parameter.Annotations {
		if len(annotation.Segments) == 0 {
			continue
		}
		if containsString(sourceAnnotations, annotation.Segments[len(annotation.Segments)-1]) {
			return true
		}
	}
	return false
}

// javaSourceClasses is the set a fully untrusted source produces: every built-in class plus any class a
// custom sink introduced (so a custom rule's class can fire).
func javaSourceClasses(catalog JavaCatalog) []TaintClass {
	seen := map[TaintClass]bool{}
	out := make([]TaintClass, 0, len(allJavaTaintClasses))
	for _, c := range allJavaTaintClasses {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	for _, s := range catalog.Sinks {
		if s.Class != "" && !seen[s.Class] {
			seen[s.Class] = true
			out = append(out, s.Class)
		}
	}
	return out
}

func (b *javaValueBuilder) addFlow(from, to string) {
	if from == "" || to == "" || from == to || b.truncated {
		return
	}
	key := from + "\x00" + to
	if b.flows[key] {
		return
	}
	if len(b.flows) >= maxJavaValueEdges {
		b.truncated = true
		return
	}
	b.flows[key] = true
}

func (b *javaValueBuilder) addSource(valueID string, class TaintClass, pos javaprogram.Position) {
	if valueID == "" || !class.Valid() || len(b.sources) >= maxJavaTaintSources {
		if len(b.sources) >= maxJavaTaintSources {
			b.truncated = true
		}
		return
	}
	key := valueID + "\x00" + string(class)
	b.sources[key] = JavaTypedValueSource{ValueID: valueID, Class: class, Pos: pos}
}

func (b *javaValueBuilder) scopeChain(scope string) []string {
	var out []string
	seen := map[string]bool{}
	for scope != "" && !seen[scope] {
		seen[scope] = true
		out = append(out, scope)
		scope = b.parents[scope]
	}
	return out
}

func (b *javaValueBuilder) finish() JavaValueFlowGraph {
	graph := JavaValueFlowGraph{Positions: b.positions, Truncated: b.truncated}
	for key := range b.flows {
		parts := strings.SplitN(key, "\x00", 2)
		graph.Flows = append(graph.Flows, Flow{From: parts[0], To: parts[1]})
	}
	for _, source := range b.sources {
		graph.Sources = append(graph.Sources, source)
	}
	for _, sink := range b.sinks {
		if len(graph.Sinks) >= maxJavaTaintSinks {
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
func (g *JavaValueFlowGraph) Vulnerabilities() []JavaTaintPath {
	return g.vulnerabilities(maxJavaTaintWork)
}

func (g *JavaValueFlowGraph) vulnerabilities(maxWork int) []JavaTaintPath {
	adjacency := map[string][]string{}
	for _, flow := range g.Flows {
		if flow.From != "" && flow.To != "" {
			adjacency[flow.From] = append(adjacency[flow.From], flow.To)
		}
	}
	for from := range adjacency {
		sort.Strings(adjacency[from])
	}
	sinks := map[string][]JavaTypedValueSink{}
	for _, sink := range g.Sinks {
		sinks[sink.ValueID] = append(sinks[sink.ValueID], sink)
	}
	sanitized := map[string]bool{}
	for _, sanitizer := range g.Sanitizers {
		sanitized[sanitizer.ValueID+"\x00"+string(sanitizer.Class)] = true
	}
	var findings []JavaTaintPath
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
				return sortedJavaTaintPaths(findings)
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
				findings = append(findings, JavaTaintPath{
					Class: sink.Class, CWE: sink.CWE, Rule: sink.Rule, SourceID: source.ValueID,
					SinkID: sink.ValueID, CallID: sink.CallID, Callee: sink.Callee,
					Path: reconstructJavaTaintPath(parent, source.ValueID, currentID), SourcePos: source.Pos, SinkPos: sink.Pos,
				})
			}
			if depth[currentID] >= maxJavaTaintPath || sanitized[currentID+"\x00"+string(source.Class)] {
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
	return sortedJavaTaintPaths(findings)
}

func reconstructJavaTaintPath(parent map[string]string, source, node string) []string {
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

func sortedJavaTaintPaths(findings []JavaTaintPath) []JavaTaintPath {
	sort.Slice(findings, func(i, j int) bool {
		left := string(findings[i].Class) + "\x00" + findings[i].SourceID + "\x00" + findings[i].SinkID
		right := string(findings[j].Class) + "\x00" + findings[j].SourceID + "\x00" + findings[j].SinkID
		return left < right
	})
	return findings
}

func javaCallMatches(pattern JavaCallablePattern, module, member string, resolved bool, raw string, isNew bool) bool {
	if resolved && len(pattern.Modules) > 0 && javaMatchesModule(module, pattern.Modules) {
		if pattern.Constructor && isNew {
			return true
		}
		if pattern.CallModule && member == "" {
			return true
		}
		if len(pattern.Names) > 0 && matchesAnyName(member, pattern.Names) {
			return true
		}
	}
	// A raw constructor floor for an auto-imported type: only a `new X(...)` whose type name matches.
	if isNew {
		for _, suffix := range pattern.RawConstructor {
			if raw == suffix || strings.HasSuffix(raw, "."+suffix) {
				return true
			}
		}
	}
	// The receiver-typed method-name floor: match when the syntactic dotted path ends with the suffix. This
	// is the instance-method case (stmt.executeQuery) whose receiver type is unknown source-only.
	for _, suffix := range pattern.RawSuffixes {
		if raw == suffix || strings.HasSuffix(raw, "."+suffix) {
			return true
		}
	}
	return false
}

// javaMatchesModule matches a resolved module/type anchor against the catalog's module patterns, both ways:
// an import of "java.io.File" matches a pattern "java.io" (package) and a pattern "java.io.File" (type).
func javaMatchesModule(module string, patterns []string) bool {
	for _, pattern := range patterns {
		if module == pattern || strings.HasPrefix(module, pattern+".") || strings.HasPrefix(pattern, module+".") {
			return true
		}
	}
	return false
}

// javaTrustedCallee builds a stable, non-sensitive callee label for the witness metadata.
func javaTrustedCallee(module, member string, resolved bool, raw string) string {
	switch {
	case resolved:
		if member == "" {
			return "java:" + module
		}
		return "java:" + module + ":" + member
	case raw != "":
		if len(raw) > 256 {
			return "java:unresolved"
		}
		return "java:syntactic:" + raw
	default:
		return "java:unresolved"
	}
}

// looksLikePackageBase reports whether a callee base identifier looks like a lowercase package segment
// (java, javax, org, com, ...) rather than a local variable, so a fully-qualified call can be anchored.
func looksLikePackageBase(base string) bool {
	if base == "" {
		return false
	}
	for _, r := range base {
		if r >= 'A' && r <= 'Z' {
			return false // a Type or a local: not a package root
		}
	}
	return true
}

func raw(segments []string) string  { return strings.Join(segments, ".") }
func lastSegment(s []string) string { return s[len(s)-1] }

func validateJavaCatalog(catalog JavaCatalog) error {
	if len(catalog.Sinks) == 0 {
		return fmt.Errorf("%w: Java taint catalog needs sinks", shared.ErrValidation)
	}
	if len(catalog.SourceAnnotations) == 0 && len(catalog.Sources) == 0 {
		return fmt.Errorf("%w: Java taint catalog needs sources", shared.ErrValidation)
	}
	for _, source := range catalog.Sources {
		if source.Pattern.empty() {
			return fmt.Errorf("%w: Java source model needs a pattern", shared.ErrValidation)
		}
		for _, class := range source.Classes {
			if !class.Valid() {
				return fmt.Errorf("%w: invalid Java source taint class", shared.ErrValidation)
			}
		}
	}
	for _, sink := range catalog.Sinks {
		if sink.Pattern.empty() {
			return fmt.Errorf("%w: Java sink model needs a pattern", shared.ErrValidation)
		}
		if !sink.Class.Valid() || !strings.HasPrefix(sink.CWE, "CWE-") || sink.Rule == "" {
			return fmt.Errorf("%w: invalid Java sink model", shared.ErrValidation)
		}
		if !sink.AllArguments && len(sink.ArgumentIndexes) == 0 {
			return fmt.Errorf("%w: Java sink model models no argument", shared.ErrValidation)
		}
	}
	for _, sanitizer := range catalog.Sanitizers {
		if sanitizer.Pattern.empty() {
			return fmt.Errorf("%w: Java sanitizer model needs a pattern", shared.ErrValidation)
		}
		for _, class := range sanitizer.Classes {
			if !class.Valid() {
				return fmt.Errorf("%w: invalid Java sanitizer taint class", shared.ErrValidation)
			}
		}
	}
	return nil
}

func javaPositionBefore(left, right javaprogram.Position) bool {
	if left.File != right.File {
		return left.File < right.File
	}
	if left.Line != right.Line {
		return left.Line < right.Line
	}
	return left.Column < right.Column
}
