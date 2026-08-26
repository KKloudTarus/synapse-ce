package taint

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/pythonprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	maxPythonValueEdges   = 4_000_000
	maxPythonTaintSources = 200_000
	maxPythonTaintSinks   = 1_000_000
	maxPythonTaintPath    = 64
	maxPythonTaintWork    = 4_000_000
)

// TaintClass separates neutralization semantics: an HTML escaper cannot sanitize SQL or a URL.
type TaintClass string

const (
	TaintSQL             TaintClass = "sql"
	TaintCommand         TaintClass = "command"
	TaintPathTraversal   TaintClass = "path"
	TaintSSRF            TaintClass = "ssrf"
	TaintXSS             TaintClass = "xss"
	TaintDeserialization TaintClass = "deserialization"
	TaintRedirect        TaintClass = "redirect"
)

func (c TaintClass) Valid() bool {
	switch c {
	case TaintSQL, TaintCommand, TaintPathTraversal, TaintSSRF, TaintXSS, TaintDeserialization, TaintRedirect:
		return true
	}
	return false
}

var allPythonTaintClasses = []TaintClass{
	TaintCommand, TaintDeserialization, TaintPathTraversal, TaintRedirect, TaintSQL, TaintSSRF, TaintXSS,
}

// PythonCallablePattern matches a resolved Python callable and, when resolution is unavailable, a
// bounded syntactic callee suffix. Module prefixes match package boundaries, not arbitrary strings.
type PythonCallablePattern struct {
	Modules     []string
	Names       []string
	RawSuffixes []string
}

// PythonSourceModel marks a call result as untrusted for the listed classes.
type PythonSourceModel struct {
	Pattern PythonCallablePattern
	Classes []TaintClass
}

// PythonSinkModel marks selected call arguments (zero-based) or the receiver as dangerous.
type PythonSinkModel struct {
	Pattern          PythonCallablePattern
	Class            TaintClass
	CWE              string
	Rule             string
	ArgumentIndexes  []int
	ArgumentKeywords []string
	Receiver         bool
}

// PythonSanitizerModel neutralizes only its listed classes at the call-result slot.
type PythonSanitizerModel struct {
	Pattern PythonCallablePattern
	Classes []TaintClass
}

// PythonCatalog is the reviewable framework/library model used by the value-flow builder.
type PythonCatalog struct {
	Sources              []PythonSourceModel
	Sinks                []PythonSinkModel
	Sanitizers           []PythonSanitizerModel
	ReferenceSources     []string
	EntrypointParameters bool
}

// TypedValueSource is one source slot for one taint class.
type TypedValueSource struct {
	ValueID string
	Class   TaintClass
	Pos     pythonprogram.Position
}

// TypedValueSink is a synthetic sink node fed only by the modeled dangerous argument(s).
type TypedValueSink struct {
	ValueID string
	CallID  string
	Callee  string
	Class   TaintClass
	CWE     string
	Rule    string
	Pos     pythonprogram.Position
}

// TypedSanitizer is a class-specific wall at a call result.
type TypedSanitizer struct {
	ValueID string
	Class   TaintClass
}

// ValueFlowGraph is the precise Python value graph. It is independent of the legacy function-level
// FlowGraph so callers cannot accidentally interpret call edges as value propagation.
type ValueFlowGraph struct {
	Flows      []Flow
	Sources    []TypedValueSource
	Sinks      []TypedValueSink
	Sanitizers []TypedSanitizer
	Positions  map[string]pythonprogram.Position
	Truncated  bool
}

// PythonTaintPath is one typed source-to-dangerous-argument witness.
type PythonTaintPath struct {
	Class     TaintClass
	CWE       string
	Rule      string
	SourceID  string
	SinkID    string
	CallID    string
	Callee    string
	Path      []string
	SourcePos pythonprogram.Position
	SinkPos   pythonprogram.Position
}

// BuildPythonValueGraph joins syntax value facts with resolved calls, parameter binding and return flow.
func BuildPythonValueGraph(document pythonprogram.Document, resolution pythonprogram.Resolution, catalog PythonCatalog) (ValueFlowGraph, error) {
	if err := document.Validate(); err != nil {
		return ValueFlowGraph{}, fmt.Errorf("build python value flow: %w", err)
	}
	if err := validatePythonCatalog(catalog); err != nil {
		return ValueFlowGraph{}, err
	}
	b := pythonValueBuilder{
		document: document, resolution: resolution, catalog: catalog,
		values: map[string]pythonprogram.Value{}, symbols: map[string]pythonprogram.Symbol{},
		parents: map[string]string{}, definitions: map[string]map[string][]pythonprogram.Value{},
		returns: map[string][]string{}, calls: map[string]pythonprogram.ResolvedCall{},
		flows: map[string]bool{}, sources: map[string]TypedValueSource{}, sinks: map[string]TypedValueSink{},
		sanitizers: map[string]TypedSanitizer{}, positions: map[string]pythonprogram.Position{},
	}
	b.index()
	b.addSyntaxFlows()
	b.bindReferences()
	b.modelCalls()
	b.modelEntrypointAndReferenceSources()
	return b.finish(), nil
}

type pythonValueBuilder struct {
	document    pythonprogram.Document
	resolution  pythonprogram.Resolution
	catalog     PythonCatalog
	values      map[string]pythonprogram.Value
	symbols     map[string]pythonprogram.Symbol
	parents     map[string]string
	definitions map[string]map[string][]pythonprogram.Value
	returns     map[string][]string
	calls       map[string]pythonprogram.ResolvedCall
	flows       map[string]bool
	sources     map[string]TypedValueSource
	sinks       map[string]TypedValueSink
	sanitizers  map[string]TypedSanitizer
	positions   map[string]pythonprogram.Position
	truncated   bool
}

func (b *pythonValueBuilder) index() {
	for _, symbol := range b.document.Symbols {
		b.symbols[symbol.ID] = symbol
		b.parents[symbol.ID] = symbol.ParentID
	}
	for _, value := range b.document.Values {
		b.values[value.ID] = value
		b.positions[value.ID] = value.Pos
		if value.Kind == pythonprogram.ValueParameter || value.Kind == pythonprogram.ValueBinding {
			if b.definitions[value.ScopeID] == nil {
				b.definitions[value.ScopeID] = map[string][]pythonprogram.Value{}
			}
			b.definitions[value.ScopeID][value.Name] = append(b.definitions[value.ScopeID][value.Name], value)
		}
	}
	for scope := range b.definitions {
		for name := range b.definitions[scope] {
			sort.Slice(b.definitions[scope][name], func(i, j int) bool {
				return positionBefore(b.definitions[scope][name][i].Pos, b.definitions[scope][name][j].Pos)
			})
		}
	}
	for _, item := range b.document.Returns {
		if item.SlotID != "" {
			b.returns[item.ScopeID] = append(b.returns[item.ScopeID], item.SlotID)
		}
	}
	for _, item := range b.resolution.Calls {
		b.calls[item.CallID] = item
	}
}

func (b *pythonValueBuilder) addSyntaxFlows() {
	for _, flow := range b.document.Flows {
		b.addFlow(flow.FromID, flow.ToID)
	}
}

func (b *pythonValueBuilder) bindReferences() {
	for _, value := range b.document.Values {
		if value.Kind != pythonprogram.ValueReference || value.Ref.Kind != pythonprogram.ReferenceName || len(value.Ref.Segments) != 1 {
			continue
		}
		name := value.Ref.Segments[0]
		for _, scope := range b.scopeChain(value.ScopeID) {
			definitions := b.definitions[scope][name]
			var prior []pythonprogram.Value
			for _, definition := range definitions {
				if definition.Kind == pythonprogram.ValueParameter || positionBefore(definition.Pos, value.Pos) {
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

func (b *pythonValueBuilder) modelCalls() {
	for _, call := range b.document.Calls {
		resolved := b.calls[call.ID]
		local := false
		for _, callee := range resolved.Callees {
			symbol, ok := b.symbols[callee]
			if !ok || (symbol.Kind != pythonprogram.SymbolFunction && symbol.Kind != pythonprogram.SymbolMethod && symbol.Kind != pythonprogram.SymbolLambda) {
				continue
			}
			local = true
			b.bindCall(call, symbol)
		}
		candidates := resolved.Callees
		raw := strings.Join(call.Callee.Segments, ".")
		matchedRole := false
		for _, model := range b.catalog.Sources {
			if callMatches(model.Pattern, candidates, raw) && call.ResultID != "" {
				matchedRole = true
				for _, class := range model.Classes {
					b.addSource(call.ResultID, class, call.Pos)
				}
			}
		}
		for index, model := range b.catalog.Sinks {
			if !callMatches(model.Pattern, candidates, raw) {
				continue
			}
			matchedRole = true
			if len(b.sinks) >= maxPythonTaintSinks {
				b.truncated = true
				continue
			}
			sinkID := call.ID + "#sink:" + string(model.Class) + ":" + strconv.Itoa(index)
			b.positions[sinkID] = call.Pos
			b.sinks[sinkID] = TypedValueSink{
				ValueID: sinkID, CallID: call.ID, Callee: trustedCallee(candidates, raw), Class: model.Class,
				CWE: model.CWE, Rule: model.Rule, Pos: call.Pos,
			}
			for _, argument := range model.ArgumentIndexes {
				if argument >= 0 && argument < len(call.Arguments) {
					b.addFlow(call.Arguments[argument].ValueID, sinkID)
				}
			}
			for _, argument := range call.Arguments {
				if containsString(model.ArgumentKeywords, argument.Keyword) {
					b.addFlow(argument.ValueID, sinkID)
				}
			}
			if model.Receiver {
				b.addFlow(call.ReceiverValueID, sinkID)
			}
		}
		for _, model := range b.catalog.Sanitizers {
			if !callMatches(model.Pattern, candidates, raw) || call.ResultID == "" {
				continue
			}
			matchedRole = true
			b.propagateCallInputs(call)
			for _, class := range model.Classes {
				key := call.ResultID + "\x00" + string(class)
				b.sanitizers[key] = TypedSanitizer{ValueID: call.ResultID, Class: class}
			}
		}
		// Local callees have explicit parameter/return edges. Unknown/external transformations
		// conservatively propagate receiver and arguments into their result unless a source/sink-only model
		// already gives the call semantics. Sanitizers still propagate for non-neutralized classes above.
		if !local && !matchedRole {
			b.propagateCallInputs(call)
		}
	}
}

func (b *pythonValueBuilder) bindCall(call pythonprogram.Call, callee pythonprogram.Symbol) {
	parameters := callee.Parameters
	positional := 0
	if callee.Kind == pythonprogram.SymbolMethod && len(parameters) > 0 && !pythonStaticMethod(callee) {
		receiverID := call.ReceiverValueID
		if receiverID == "" && callee.Name == "__init__" {
			// A constructor is written as Class(...), so the syntax fact has no attribute receiver. Its
			// result is the instance bound to self; user positional arguments still start at parameter 1.
			receiverID = call.ResultID
		}
		b.addFlow(receiverID, parameters[0].ValueID)
		positional = 1
	}
	for _, argument := range call.Arguments {
		if argument.ValueID == "" {
			continue
		}
		if argument.Keyword != "" && argument.Keyword != "**" {
			for _, parameter := range parameters {
				if parameter.Name == argument.Keyword {
					b.addFlow(argument.ValueID, parameter.ValueID)
				}
			}
			continue
		}
		if argument.Star || argument.Keyword == "**" {
			for _, parameter := range parameters {
				b.addFlow(argument.ValueID, parameter.ValueID)
			}
			continue
		}
		for positional < len(parameters) && parameters[positional].Kind == pythonprogram.ParameterKwArgs {
			positional++
		}
		if positional < len(parameters) {
			b.addFlow(argument.ValueID, parameters[positional].ValueID)
			if parameters[positional].Kind != pythonprogram.ParameterVarArgs {
				positional++
			}
		}
	}
	for _, returnID := range b.returns[callee.ID] {
		b.addFlow(returnID, call.ResultID)
	}
}

func pythonStaticMethod(symbol pythonprogram.Symbol) bool {
	for _, decorator := range symbol.Decorators {
		if len(decorator.Segments) > 0 && decorator.Segments[len(decorator.Segments)-1] == "staticmethod" {
			return true
		}
	}
	return false
}

func (b *pythonValueBuilder) propagateCallInputs(call pythonprogram.Call) {
	for _, argument := range call.Arguments {
		b.addFlow(argument.ValueID, call.ResultID)
	}
	b.addFlow(call.ReceiverValueID, call.ResultID)
}

func (b *pythonValueBuilder) modelEntrypointAndReferenceSources() {
	explicit := map[string]bool{}
	for _, hint := range b.document.Entrypoints {
		if hint.Kind != "module_import" {
			explicit[hint.SymbolID] = true
		}
	}
	if b.catalog.EntrypointParameters {
		for _, symbol := range b.document.Symbols {
			for _, parameter := range symbol.Parameters {
				if parameter.ValueID == "" || parameter.Name == "self" || parameter.Name == "cls" {
					continue
				}
				if !explicit[symbol.ID] && !likelyRequestParameter(parameter.Name) {
					continue
				}
				for _, class := range allPythonTaintClasses {
					b.addSource(parameter.ValueID, class, parameter.Pos)
				}
			}
		}
	}
	for _, value := range b.document.Values {
		if value.Kind != pythonprogram.ValueReference || len(value.Ref.Segments) == 0 {
			continue
		}
		raw := strings.Join(value.Ref.Segments, ".")
		for _, suffix := range b.catalog.ReferenceSources {
			if raw == suffix || strings.HasSuffix(raw, "."+suffix) {
				for _, class := range allPythonTaintClasses {
					b.addSource(value.ID, class, value.Pos)
				}
				break
			}
		}
	}
}

func (b *pythonValueBuilder) addFlow(from, to string) {
	if from == "" || to == "" || from == to || b.truncated {
		return
	}
	key := from + "\x00" + to
	if b.flows[key] {
		return
	}
	if len(b.flows) >= maxPythonValueEdges {
		b.truncated = true
		return
	}
	b.flows[key] = true
}

func (b *pythonValueBuilder) addSource(valueID string, class TaintClass, pos pythonprogram.Position) {
	if valueID == "" || !class.Valid() || len(b.sources) >= maxPythonTaintSources {
		if len(b.sources) >= maxPythonTaintSources {
			b.truncated = true
		}
		return
	}
	key := valueID + "\x00" + string(class)
	b.sources[key] = TypedValueSource{ValueID: valueID, Class: class, Pos: pos}
}

func (b *pythonValueBuilder) scopeChain(scope string) []string {
	var out []string
	seen := map[string]bool{}
	for scope != "" && !seen[scope] {
		seen[scope] = true
		out = append(out, scope)
		scope = b.parents[scope]
	}
	return out
}

func (b *pythonValueBuilder) finish() ValueFlowGraph {
	graph := ValueFlowGraph{Positions: b.positions, Truncated: b.truncated}
	for key := range b.flows {
		parts := strings.SplitN(key, "\x00", 2)
		graph.Flows = append(graph.Flows, Flow{From: parts[0], To: parts[1]})
	}
	for _, source := range b.sources {
		graph.Sources = append(graph.Sources, source)
	}
	for _, sink := range b.sinks {
		if len(graph.Sinks) >= maxPythonTaintSinks {
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
func (g *ValueFlowGraph) Vulnerabilities() []PythonTaintPath {
	return g.vulnerabilities(maxPythonTaintWork)
}

func (g *ValueFlowGraph) vulnerabilities(maxWork int) []PythonTaintPath {
	adjacency := map[string][]string{}
	for _, flow := range g.Flows {
		if flow.From != "" && flow.To != "" {
			adjacency[flow.From] = append(adjacency[flow.From], flow.To)
		}
	}
	for from := range adjacency {
		sort.Strings(adjacency[from])
	}
	sinks := map[string][]TypedValueSink{}
	for _, sink := range g.Sinks {
		sinks[sink.ValueID] = append(sinks[sink.ValueID], sink)
	}
	sanitized := map[string]bool{}
	for _, sanitizer := range g.Sanitizers {
		sanitized[sanitizer.ValueID+"\x00"+string(sanitizer.Class)] = true
	}
	var findings []PythonTaintPath
	seenFinding := map[string]bool{}
	work := 0
	for _, source := range g.Sources {
		type state struct {
			id   string
			path []string
		}
		queue := []state{{id: source.ValueID, path: []string{source.ValueID}}}
		seen := map[string]bool{source.ValueID: true}
		for len(queue) > 0 {
			work++
			if work > maxWork {
				g.Truncated = true
				return sortedPythonTaintPaths(findings)
			}
			current := queue[0]
			queue = queue[1:]
			for _, sink := range sinks[current.id] {
				if sink.Class != source.Class {
					continue
				}
				key := source.ValueID + "\x00" + sink.ValueID + "\x00" + string(sink.Class) + "\x00" + sink.Rule
				if seenFinding[key] {
					continue
				}
				seenFinding[key] = true
				findings = append(findings, PythonTaintPath{
					Class: sink.Class, CWE: sink.CWE, Rule: sink.Rule, SourceID: source.ValueID,
					SinkID: sink.ValueID, CallID: sink.CallID, Callee: sink.Callee,
					Path: append([]string(nil), current.path...), SourcePos: source.Pos, SinkPos: sink.Pos,
				})
			}
			if len(current.path) >= maxPythonTaintPath || sanitized[current.id+"\x00"+string(source.Class)] {
				continue
			}
			for _, next := range adjacency[current.id] {
				if seen[next] {
					continue
				}
				seen[next] = true
				path := append(append([]string(nil), current.path...), next)
				queue = append(queue, state{id: next, path: path})
			}
		}
	}
	return sortedPythonTaintPaths(findings)
}

func sortedPythonTaintPaths(findings []PythonTaintPath) []PythonTaintPath {
	sort.Slice(findings, func(i, j int) bool {
		left := string(findings[i].Class) + "\x00" + findings[i].SourceID + "\x00" + findings[i].SinkID
		right := string(findings[j].Class) + "\x00" + findings[j].SourceID + "\x00" + findings[j].SinkID
		return left < right
	})
	return findings
}

func callMatches(pattern PythonCallablePattern, candidates []string, raw string) bool {
	if len(pattern.Modules) > 0 || len(pattern.Names) > 0 {
		for _, candidate := range candidates {
			module, qualified, ok := splitPythonCallable(candidate)
			if !ok || !matchesAnyModule(module, pattern.Modules) || !matchesAnyName(qualified, pattern.Names) {
				continue
			}
			return true
		}
	}
	for _, suffix := range pattern.RawSuffixes {
		if raw == suffix || strings.HasSuffix(raw, "."+suffix) {
			return true
		}
	}
	return false
}

func splitPythonCallable(value string) (module, qualified string, ok bool) {
	if !strings.HasPrefix(value, "python:") {
		return "", "", false
	}
	rest := strings.TrimPrefix(value, "python:")
	colon := strings.IndexByte(rest, ':')
	if colon <= 0 || colon == len(rest)-1 {
		return "", "", false
	}
	return rest[:colon], rest[colon+1:], true
}

func matchesAnyModule(module string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if module == pattern || strings.HasPrefix(module, pattern+".") {
			return true
		}
	}
	return false
}

func matchesAnyName(qualified string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if qualified == pattern || strings.HasSuffix(qualified, "."+pattern) {
			return true
		}
	}
	return false
}

func trustedCallee(candidates []string, raw string) string {
	if len(candidates) > 0 {
		copy := append([]string(nil), candidates...)
		sort.Strings(copy)
		return copy[0]
	}
	if len(raw) > 256 {
		return "python:unresolved"
	}
	return "python:syntactic:" + raw
}

func validatePythonCatalog(catalog PythonCatalog) error {
	if len(catalog.Sources) == 0 || len(catalog.Sinks) == 0 {
		return fmt.Errorf("%w: Python taint catalog needs sources and sinks", shared.ErrValidation)
	}
	for _, source := range catalog.Sources {
		for _, class := range source.Classes {
			if !class.Valid() {
				return fmt.Errorf("%w: invalid Python source taint class", shared.ErrValidation)
			}
		}
	}
	for _, sink := range catalog.Sinks {
		if !sink.Class.Valid() || !strings.HasPrefix(sink.CWE, "CWE-") || sink.Rule == "" {
			return fmt.Errorf("%w: invalid Python sink model", shared.ErrValidation)
		}
		for _, keyword := range sink.ArgumentKeywords {
			if keyword == "" || strings.ContainsAny(keyword, "\r\n\t") {
				return fmt.Errorf("%w: invalid Python sink keyword", shared.ErrValidation)
			}
		}
	}
	for _, sanitizer := range catalog.Sanitizers {
		for _, class := range sanitizer.Classes {
			if !class.Valid() {
				return fmt.Errorf("%w: invalid Python sanitizer taint class", shared.ErrValidation)
			}
		}
	}
	return nil
}

func positionBefore(left, right pythonprogram.Position) bool {
	if left.File != right.File {
		return left.File < right.File
	}
	if left.Line != right.Line {
		return left.Line < right.Line
	}
	return left.Column < right.Column
}

func likelyRequestParameter(name string) bool {
	switch strings.ToLower(name) {
	case "request", "req", "body", "data", "payload", "form", "query", "params", "headers", "cookies", "path":
		return true
	}
	return false
}

func containsString(values []string, want string) bool {
	if want == "" {
		return false
	}
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
