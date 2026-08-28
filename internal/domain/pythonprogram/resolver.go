package pythonprogram

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
)

const (
	maxResolvedCandidates = 128
	maxResolvedEdges      = 4_000_000
)

// CallResolutionStatus records whether one syntactic call has a unique semantic target. Ambiguous calls
// retain every conservative candidate but make negative reachability incomplete.
type CallResolutionStatus string

const (
	CallResolved   CallResolutionStatus = "resolved"
	CallExternal   CallResolutionStatus = "external"
	CallAmbiguous  CallResolutionStatus = "ambiguous"
	CallUnresolved CallResolutionStatus = "unresolved"
)

// ResolvedCall connects a source call fact to its deterministic semantic candidates.
type ResolvedCall struct {
	CallID    string               `json:"call_id"`
	CallerID  string               `json:"caller_id"`
	Callees   []string             `json:"callees,omitempty"`
	Status    CallResolutionStatus `json:"status"`
	Pos       Position             `json:"position"`
	Ambiguous bool                 `json:"ambiguous,omitempty"`
}

// Resolution is the pure Tier-2 result. Graph remains useful for positive evidence when Complete is
// false; callers must require Complete before treating absence of a path as a negative proof.
type Resolution struct {
	Graph    callgraph.Graph `json:"-"`
	Calls    []ResolvedCall  `json:"calls"`
	Gaps     []CoverageGap   `json:"coverage_gaps"`
	Complete bool            `json:"complete"`
}

type importBinding struct {
	module string
	name   string
	alias  string
	direct bool
	pos    Position
}

type pythonType struct {
	module    string
	qualified string
	classID   string
}

type semanticResolver struct {
	document  Document
	symbols   map[string]Symbol
	modules   map[string]string
	children  map[string]map[string][]string
	imports   map[string]map[string][]importBinding
	receivers map[string]map[string][]pythonType
	bases     map[string][]string
	gaps      []CoverageGap
}

// Resolve builds a deterministic, conservative Python call graph without filesystem or interpreter I/O.
func Resolve(document Document) (Resolution, error) {
	if err := document.Validate(); err != nil {
		return Resolution{}, fmt.Errorf("resolve python facts: %w", err)
	}
	r := newSemanticResolver(document)
	r.indexImports()
	r.indexBases()
	r.indexReceivers()

	edges := make(map[string]map[string]bool)
	resolved := make([]ResolvedCall, 0, len(document.Calls))
	edgeCount := 0
	for _, call := range document.Calls {
		candidates, external := r.resolveReference(call.CallerID, call.Callee)
		candidates = sortedUnique(candidates)
		status := CallResolved
		switch {
		case len(candidates) == 0:
			status = CallUnresolved
			r.addGap(GapUnresolvedCall, call.CallerID, "unresolved_call", call.Pos)
		case len(candidates) > maxResolvedCandidates:
			status = CallAmbiguous
			candidates = candidates[:maxResolvedCandidates]
			r.addGap(GapBudget, call.CallerID, "call_candidate_budget", call.Pos)
		case len(candidates) > 1:
			status = CallAmbiguous
			r.addGap(GapUnresolvedCall, call.CallerID, "ambiguous_call", call.Pos)
		case external:
			status = CallExternal
		}
		resolved = append(resolved, ResolvedCall{
			CallID: call.ID, CallerID: call.CallerID, Callees: candidates, Status: status,
			Pos: call.Pos, Ambiguous: status == CallAmbiguous,
		})
		for _, callee := range candidates {
			if edgeCount >= maxResolvedEdges {
				r.addGap(GapBudget, call.CallerID, "call_edge_budget", call.Pos)
				break
			}
			if edges[call.CallerID] == nil {
				edges[call.CallerID] = map[string]bool{}
			}
			if !edges[call.CallerID][callee] {
				edges[call.CallerID][callee] = true
				edgeCount++
			}
		}
	}

	graph := callgraph.Graph{Positions: make(map[string]string, len(document.Symbols))}
	for _, symbol := range document.Symbols {
		graph.Positions[symbol.ID] = symbol.Pos.File + ":" + strconv.Itoa(symbol.Pos.Line)
	}
	for caller, targets := range edges {
		callees := make([]string, 0, len(targets))
		for target := range targets {
			callees = append(callees, target)
		}
		sort.Strings(callees)
		graph.Edges = append(graph.Edges, callgraph.Edge{Caller: caller, Callees: callees})
	}
	sort.Slice(graph.Edges, func(i, j int) bool { return graph.Edges[i].Caller < graph.Edges[j].Caller })
	entrySet := r.derivedEntrypoints()
	for _, hint := range document.Entrypoints {
		if _, ok := r.symbols[hint.SymbolID]; ok {
			entrySet[hint.SymbolID] = true
		}
	}
	for entry := range entrySet {
		graph.Entrypoints = append(graph.Entrypoints, entry)
	}
	sort.Strings(graph.Entrypoints)
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].CallID < resolved[j].CallID })
	r.gaps = canonicalGaps(append(append([]CoverageGap{}, document.CoverageGaps...), r.gaps...))
	return Resolution{Graph: graph, Calls: resolved, Gaps: r.gaps, Complete: document.Complete() && len(r.gaps) == 0}, nil
}

func newSemanticResolver(document Document) *semanticResolver {
	r := &semanticResolver{
		document:  document,
		symbols:   make(map[string]Symbol, len(document.Symbols)),
		modules:   make(map[string]string, len(document.Modules)),
		children:  map[string]map[string][]string{},
		imports:   map[string]map[string][]importBinding{},
		receivers: map[string]map[string][]pythonType{},
		bases:     map[string][]string{},
	}
	for _, symbol := range document.Symbols {
		r.symbols[symbol.ID] = symbol
		if symbol.Kind == SymbolModule {
			r.modules[symbol.Module] = symbol.ID
		}
		if symbol.ParentID != "" {
			if r.children[symbol.ParentID] == nil {
				r.children[symbol.ParentID] = map[string][]string{}
			}
			r.children[symbol.ParentID][symbol.Name] = append(r.children[symbol.ParentID][symbol.Name], symbol.ID)
		}
	}
	for parent := range r.children {
		for name := range r.children[parent] {
			sort.Strings(r.children[parent][name])
		}
	}
	return r
}

func (r *semanticResolver) indexImports() {
	for _, item := range r.document.Imports {
		module, ok := r.absoluteImportModule(item.ScopeID, item.Module, item.Level)
		if !ok {
			r.addGap(GapUnresolvedImport, item.ScopeID, "relative_import", item.Pos)
			continue
		}
		bound := item.Alias
		direct := item.Name == ""
		if bound == "" {
			if direct {
				bound = strings.Split(module, ".")[0]
			} else {
				bound = item.Name
			}
		}
		if bound == "" || item.Wildcard {
			continue
		}
		if r.imports[item.ScopeID] == nil {
			r.imports[item.ScopeID] = map[string][]importBinding{}
		}
		r.imports[item.ScopeID][bound] = append(r.imports[item.ScopeID][bound], importBinding{
			module: module, name: item.Name, alias: item.Alias, direct: direct, pos: item.Pos,
		})
	}
}

func (r *semanticResolver) indexBases() {
	for _, symbol := range r.document.Symbols {
		if symbol.Kind != SymbolClass {
			continue
		}
		for _, base := range symbol.Bases {
			candidates := r.resolveClassReference(symbol.ParentID, base)
			localCount := 0
			for _, candidate := range candidates {
				if candidate.classID != "" && candidate.classID != symbol.ID {
					r.bases[symbol.ID] = append(r.bases[symbol.ID], candidate.classID)
					localCount++
				}
			}
			if localCount == 0 {
				r.addGap(GapUnresolvedValue, symbol.ID, "unresolved_base", symbol.Pos)
			} else if localCount > 1 || len(candidates) > localCount {
				r.addGap(GapUnresolvedValue, symbol.ID, "ambiguous_base", symbol.Pos)
			}
		}
		r.bases[symbol.ID] = sortedUnique(r.bases[symbol.ID])
	}
}

func (r *semanticResolver) derivedEntrypoints() map[string]bool {
	entrypoints := map[string]bool{}
	for _, symbol := range r.document.Symbols {
		if symbol.Kind == SymbolModule {
			entrypoints[symbol.ID] = true
			continue
		}
		if strings.HasPrefix(symbol.Name, "_") || symbol.Kind == SymbolLambda {
			continue
		}
		parent := r.symbols[symbol.ParentID]
		// A public module-level callable is an API entrypoint. A public method on a public class is also
		// externally invocable in a library scan. This intentionally over-approximates reachability.
		if parent.Kind == SymbolModule || parent.Kind == SymbolClass && !strings.HasPrefix(parent.Name, "_") {
			entrypoints[symbol.ID] = true
		}
	}
	return entrypoints
}

func (r *semanticResolver) indexReceivers() {
	// A small fixed point handles chains such as alias = Service; instance = alias(). Unknown or
	// control-flow-dependent assignments remain conservative and are surfaced when their calls resolve.
	for pass := 0; pass < 4; pass++ {
		changed := false
		for _, assignment := range r.document.Assignments {
			if assignment.Value.Kind != ReferenceCall || len(assignment.Value.Segments) == 0 {
				continue
			}
			types := r.resolveClassReference(assignment.ScopeID, assignment.Value)
			if len(types) == 0 {
				continue
			}
			for _, target := range assignment.Targets {
				ownerID := assignment.ScopeID
				name := ""
				switch {
				case target.Kind == ReferenceName && len(target.Segments) == 1:
					name = target.Segments[0]
				case target.Kind == ReferenceAttribute && len(target.Segments) == 2 && (target.Segments[0] == "self" || target.Segments[0] == "cls"):
					ownerID = r.enclosingClass(assignment.ScopeID)
					name = target.Segments[1]
				}
				if ownerID == "" || name == "" {
					continue
				}
				if r.receivers[ownerID] == nil {
					r.receivers[ownerID] = map[string][]pythonType{}
				}
				before := len(r.receivers[ownerID][name])
				r.receivers[ownerID][name] = uniqueTypes(append(r.receivers[ownerID][name], types...))
				changed = changed || len(r.receivers[ownerID][name]) != before
			}
		}
		if !changed {
			break
		}
	}
}

func (r *semanticResolver) resolveReference(scopeID string, ref Reference) ([]string, bool) {
	if len(ref.Segments) == 0 || ref.Kind == ReferenceUnknown || ref.Kind == ReferenceLiteral {
		return nil, false
	}
	segments := ref.Segments
	if (segments[0] == "self" || segments[0] == "cls") && len(segments) > 1 {
		if classID := r.enclosingClass(scopeID); classID != "" {
			if len(segments) > 2 {
				var candidates []string
				for _, typ := range r.receiverTypes(scopeID, segments[1]) {
					candidates = append(candidates, r.methodsForType(typ, segments[2:])...)
				}
				if len(candidates) > 0 {
					return sortedUnique(candidates), hasExternalCandidate(candidates, r.symbols)
				}
			}
			return r.methodsForType(pythonType{classID: classID}, segments[1:]), false
		}
	}
	if len(segments) > 1 {
		var candidates []string
		for _, typ := range r.receiverTypes(scopeID, segments[0]) {
			candidates = append(candidates, r.methodsForType(typ, segments[1:])...)
		}
		if len(candidates) > 0 {
			return sortedUnique(candidates), hasExternalCandidate(candidates, r.symbols)
		}
	}
	if local := r.lookupLexical(scopeID, segments[0]); len(local) > 0 {
		var candidates []string
		for _, id := range local {
			candidates = append(candidates, r.targetsFromLocal(id, segments[1:])...)
		}
		return sortedUnique(candidates), false
	}
	if bindings := r.lookupImports(scopeID, segments[0]); len(bindings) > 0 {
		var candidates []string
		for _, binding := range bindings {
			candidates = append(candidates, r.targetsFromImport(binding, segments)...)
		}
		candidates = sortedUnique(candidates)
		return candidates, hasExternalCandidate(candidates, r.symbols)
	}
	if builtinCallables[segments[0]] && len(segments) == 1 {
		return []string{canonicalPythonSymbolID("builtins", segments[0])}, true
	}
	return nil, false
}

func (r *semanticResolver) resolveClassReference(scopeID string, ref Reference) []pythonType {
	if len(ref.Segments) == 0 {
		return nil
	}
	segments := ref.Segments
	if local := r.lookupLexical(scopeID, segments[0]); len(local) > 0 {
		var out []pythonType
		for _, id := range local {
			symbol := r.symbols[id]
			if symbol.Kind == SymbolClass && len(segments) == 1 {
				out = append(out, pythonType{module: symbol.Module, qualified: symbol.QualifiedName, classID: id})
			}
		}
		return uniqueTypes(out)
	}
	if bindings := r.lookupImports(scopeID, segments[0]); len(bindings) > 0 {
		var out []pythonType
		for _, binding := range bindings {
			local := r.localSymbolsFromImport(binding, segments)
			for _, id := range local {
				if symbol := r.symbols[id]; symbol.Kind == SymbolClass {
					out = append(out, pythonType{module: symbol.Module, qualified: symbol.QualifiedName, classID: id})
				}
			}
			if len(local) > 0 {
				continue
			}
			if binding.direct {
				qualifier := r.directImportQualifier(binding, segments)
				if qualifier != "" {
					out = append(out, pythonType{module: binding.module, qualified: qualifier})
				}
			} else {
				qualified := binding.name
				if len(segments) > 1 {
					qualified += "." + strings.Join(segments[1:], ".")
				}
				out = append(out, pythonType{module: binding.module, qualified: qualified})
			}
		}
		return uniqueTypes(out)
	}
	return nil
}

func (r *semanticResolver) targetsFromLocal(id string, rest []string) []string {
	symbol, ok := r.symbols[id]
	if !ok {
		return nil
	}
	if len(rest) == 0 {
		if symbol.Kind == SymbolClass {
			constructors := r.lookupMethods(id, []string{"__init__"}, map[string]bool{})
			if len(constructors) > 0 {
				return constructors
			}
		}
		return []string{id}
	}
	if symbol.Kind == SymbolClass {
		return r.lookupMethods(id, rest, map[string]bool{})
	}
	return nil
}

func (r *semanticResolver) targetsFromImport(binding importBinding, segments []string) []string {
	if local := r.localTargetsFromImport(binding, segments); len(local) > 0 {
		return local
	}
	if binding.direct {
		qualifier := r.directImportQualifier(binding, segments)
		if qualifier == "" {
			return nil
		}
		return []string{canonicalPythonSymbolID(binding.module, qualifier)}
	}
	qualified := binding.name
	if len(segments) > 1 {
		qualified += "." + strings.Join(segments[1:], ".")
	}
	return []string{canonicalPythonSymbolID(binding.module, qualified)}
}

func (r *semanticResolver) localTargetsFromImport(binding importBinding, segments []string) []string {
	var out []string
	if binding.direct {
		moduleID := r.modules[binding.module]
		qualifier := r.directImportQualifier(binding, segments)
		if moduleID == "" || qualifier == "" {
			return nil
		}
		for _, id := range r.lookupQualifiedChildren(moduleID, strings.Split(qualifier, ".")) {
			out = append(out, r.targetsFromLocal(id, nil)...)
		}
		return sortedUnique(out)
	}
	if moduleID := r.modules[binding.module]; moduleID != "" {
		for _, id := range r.children[moduleID][binding.name] {
			out = append(out, r.targetsFromLocal(id, segments[1:])...)
		}
		if len(out) > 0 {
			return sortedUnique(out)
		}
	}
	if submoduleID := r.modules[binding.module+"."+binding.name]; submoduleID != "" && len(segments) > 1 {
		for _, id := range r.lookupQualifiedChildren(submoduleID, segments[1:]) {
			out = append(out, r.targetsFromLocal(id, nil)...)
		}
	}
	return sortedUnique(out)
}

func (r *semanticResolver) localSymbolsFromImport(binding importBinding, segments []string) []string {
	if binding.direct {
		if moduleID := r.modules[binding.module]; moduleID != "" {
			qualifier := r.directImportQualifier(binding, segments)
			if qualifier == "" {
				return []string{moduleID}
			}
			return r.lookupQualifiedChildren(moduleID, strings.Split(qualifier, "."))
		}
		return nil
	}
	if moduleID := r.modules[binding.module]; moduleID != "" {
		return r.lookupQualifiedChildren(moduleID, append([]string{binding.name}, segments[1:]...))
	}
	if submoduleID := r.modules[binding.module+"."+binding.name]; submoduleID != "" {
		if len(segments) == 1 {
			return []string{submoduleID}
		}
		return r.lookupQualifiedChildren(submoduleID, segments[1:])
	}
	return nil
}

func importRest(binding importBinding, segments []string) []string {
	if binding.direct {
		qualifier := strings.Split(binding.module, ".")
		if binding.alias == "" && len(segments) >= len(qualifier) {
			match := true
			for i := range qualifier {
				if segments[i] != qualifier[i] {
					match = false
					break
				}
			}
			if match {
				return segments[len(qualifier):]
			}
		}
		return segments[1:]
	}
	return segments[1:]
}

func (r *semanticResolver) directImportQualifier(binding importBinding, segments []string) string {
	rest := importRest(binding, segments)
	return strings.Join(rest, ".")
}

func (r *semanticResolver) methodsForType(typ pythonType, rest []string) []string {
	if len(rest) == 0 {
		return nil
	}
	if typ.classID != "" {
		return r.lookupMethods(typ.classID, rest, map[string]bool{})
	}
	if typ.module == "" || typ.qualified == "" {
		return nil
	}
	return []string{canonicalPythonSymbolID(typ.module, typ.qualified+"."+strings.Join(rest, "."))}
}

func (r *semanticResolver) lookupMethods(classID string, path []string, seen map[string]bool) []string {
	if classID == "" || len(path) == 0 || seen[classID] {
		return nil
	}
	seen[classID] = true
	direct := r.lookupQualifiedChildren(classID, path)
	if len(direct) > 0 {
		return direct
	}
	var inherited []string
	for _, base := range r.bases[classID] {
		inherited = append(inherited, r.lookupMethods(base, path, seen)...)
	}
	return sortedUnique(inherited)
}

func (r *semanticResolver) lookupQualifiedChildren(parent string, path []string) []string {
	current := []string{parent}
	for _, name := range path {
		var next []string
		for _, id := range current {
			next = append(next, r.children[id][name]...)
		}
		current = sortedUnique(next)
		if len(current) == 0 {
			break
		}
	}
	return current
}

func (r *semanticResolver) lookupLexical(scopeID, name string) []string {
	for _, scope := range r.scopeChain(scopeID) {
		if children := r.children[scope][name]; len(children) > 0 {
			return children
		}
	}
	return nil
}

func (r *semanticResolver) lookupImports(scopeID, name string) []importBinding {
	for _, scope := range r.scopeChain(scopeID) {
		if bindings := r.imports[scope][name]; len(bindings) > 0 {
			return bindings
		}
	}
	return nil
}

func (r *semanticResolver) receiverTypes(scopeID, name string) []pythonType {
	for _, scope := range r.scopeChain(scopeID) {
		if types := r.receivers[scope][name]; len(types) > 0 {
			return types
		}
	}
	return nil
}

func (r *semanticResolver) scopeChain(scopeID string) []string {
	var chain []string
	seen := map[string]bool{}
	for scopeID != "" && !seen[scopeID] {
		seen[scopeID] = true
		chain = append(chain, scopeID)
		scopeID = r.symbols[scopeID].ParentID
	}
	return chain
}

func (r *semanticResolver) enclosingClass(scopeID string) string {
	for _, id := range r.scopeChain(scopeID) {
		if r.symbols[id].Kind == SymbolClass {
			return id
		}
	}
	return ""
}

func (r *semanticResolver) absoluteImportModule(scopeID, module string, level int) (string, bool) {
	if level == 0 {
		return module, module != ""
	}
	scope, ok := r.symbols[scopeID]
	if !ok {
		return "", false
	}
	parts := strings.Split(scope.Module, ".")
	moduleFile := ""
	for _, item := range r.document.Modules {
		if item.Name == scope.Module {
			moduleFile = item.File
			break
		}
	}
	if !strings.HasSuffix(moduleFile, "/__init__.py") && moduleFile != "__init__.py" {
		parts = parts[:len(parts)-1]
	}
	drop := level - 1
	if drop > len(parts) {
		return "", false
	}
	parts = parts[:len(parts)-drop]
	if module != "" {
		parts = append(parts, strings.Split(module, ".")...)
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, "."), true
}

func (r *semanticResolver) addGap(kind GapKind, symbolID, detail string, pos Position) {
	r.gaps = append(r.gaps, CoverageGap{Kind: kind, SymbolID: symbolID, Detail: detail, Pos: pos})
}

func canonicalGaps(gaps []CoverageGap) []CoverageGap {
	sort.Slice(gaps, func(i, j int) bool {
		left, right := factKey(gaps[i].Pos, string(gaps[i].Kind), gaps[i].SymbolID+":"+gaps[i].Detail), factKey(gaps[j].Pos, string(gaps[j].Kind), gaps[j].SymbolID+":"+gaps[j].Detail)
		return left < right
	})
	out := gaps[:0]
	for _, gap := range gaps {
		if len(out) > 0 && out[len(out)-1] == gap {
			continue
		}
		out = append(out, gap)
	}
	return out
}

func sortedUnique(values []string) []string {
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if value == "" || len(out) > 0 && out[len(out)-1] == value {
			continue
		}
		out = append(out, value)
	}
	return out
}

func uniqueTypes(values []pythonType) []pythonType {
	sort.Slice(values, func(i, j int) bool {
		left := values[i].module + ":" + values[i].qualified + ":" + values[i].classID
		right := values[j].module + ":" + values[j].qualified + ":" + values[j].classID
		return left < right
	})
	out := values[:0]
	for _, value := range values {
		if len(out) > 0 && out[len(out)-1] == value {
			continue
		}
		out = append(out, value)
	}
	return out
}

func hasExternalCandidate(candidates []string, symbols map[string]Symbol) bool {
	for _, candidate := range candidates {
		if _, local := symbols[candidate]; !local {
			return true
		}
	}
	return false
}

func canonicalPythonSymbolID(module, qualified string) string {
	return "python:" + module + ":" + qualified
}

var builtinCallables = map[string]bool{
	"abs": true, "all": true, "any": true, "bool": true, "bytes": true, "callable": true,
	"dict": true, "enumerate": true, "filter": true, "float": true, "frozenset": true,
	"getattr": true, "hasattr": true, "hash": true, "int": true, "isinstance": true,
	"issubclass": true, "iter": true, "len": true, "list": true, "map": true, "max": true,
	"min": true, "next": true, "object": true, "open": true, "print": true, "range": true,
	"repr": true, "reversed": true, "round": true, "set": true, "slice": true, "sorted": true,
	"str": true, "sum": true, "super": true, "tuple": true, "type": true, "zip": true,
}
