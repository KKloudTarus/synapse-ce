package jsprogram

import (
	"fmt"
	"path"
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
// retain every conservative candidate but make a negative (not-reached) proof incomplete.
type CallResolutionStatus string

const (
	CallResolved   CallResolutionStatus = "resolved"
	CallExternal   CallResolutionStatus = "external"
	CallAmbiguous  CallResolutionStatus = "ambiguous"
	CallUnresolved CallResolutionStatus = "unresolved"
)

// ResolvedCall connects a source call fact to its deterministic semantic candidates.
type ResolvedCall struct {
	CallID   string               `json:"call_id"`
	CallerID string               `json:"caller_id"`
	Callees  []string             `json:"callees,omitempty"`
	Status   CallResolutionStatus `json:"status"`
	Pos      Position             `json:"position"`
}

// Resolution is the pure JS/TS call-graph result. It is the twin of pythonprogram.Resolution: Graph is
// useful for POSITIVE (reached) evidence even when Complete is false, but a caller must require Complete
// before treating the absence of a path as a negative proof. Complete is false whenever the extractor left
// a coverage gap (a dynamic construct: computed member, eval/Function, dynamic import, with, an unresolved
// or ambiguous call), which is what keeps a JS negative sound in the presence of dynamic dispatch.
type Resolution struct {
	Graph    callgraph.Graph `json:"-"`
	Calls    []ResolvedCall  `json:"calls"`
	Gaps     []CoverageGap   `json:"coverage_gaps"`
	Complete bool            `json:"complete"`
}

type importBinding struct {
	kind       ImportKind
	module     string // the resolved in-document module name for a first-party relative specifier, else the raw specifier
	name       string // the imported export name (a named import's original name, or "default")
	local      string
	firstParty bool // the specifier is a relative path resolvable to an in-document module
}

type jsType struct {
	classID string
}

type semanticResolver struct {
	document  Document
	symbols   map[string]Symbol
	modules   map[string]string                     // module name -> module symbol id
	children  map[string]map[string][]string        // parent id -> child name -> child ids
	imports   map[string]map[string][]importBinding // scope id -> local name -> bindings
	receivers map[string]map[string][]jsType        // owner scope id -> local/attr name -> constructed types
	bases     map[string][]string                   // class id -> base class ids (extends)
	subclass  map[string][]string                   // class id -> direct subclass ids (reverse of bases)
	gaps      []CoverageGap
}

// Resolve builds a deterministic, conservative JS/TS call graph from the source-only facts, with no
// filesystem or interpreter I/O. It mirrors pythonprogram.Resolve: it resolves what is unambiguous
// (lexical functions, class methods via receiver typing and this/super, first-party relative imports) and
// records a coverage gap for anything it cannot pin (an ambiguous or unresolved callee), so the Complete
// flag stays false unless every call was resolved over a fully-parsed tree.
func Resolve(document Document) (Resolution, error) {
	if err := document.Validate(); err != nil {
		return Resolution{}, fmt.Errorf("resolve js facts: %w", err)
	}
	r := newSemanticResolver(document)
	r.indexImports()
	r.indexBases()
	r.indexReceivers()

	edges := make(map[string]map[string]bool)
	resolved := make([]ResolvedCall, 0, len(document.Calls))
	edgeCount := 0
	for _, call := range document.Calls {
		candidates, external := r.resolveReference(call.CallerID, call.Callee, call.New)
		candidates = sortedUnique(candidates)
		// A first-party function/class passed as a call argument escapes: a higher-order callee (a library
		// map/forEach/then, or a first-party dispatcher) may invoke it through a path this graph does not
		// model. Record a coverage gap so a NEGATIVE is never claimed over that hole; positive edges are
		// unaffected. This is the JS "call/apply/callback" incompleteness stated in EPIC #1042 3.4.
		if r.argumentEscapesFirstParty(call) {
			r.addGap(GapUnresolvedCall, call.CallerID, "callback_escape", call.Pos)
		}
		status := CallResolved
		switch {
		case len(candidates) == 0 && external:
			// A recognized third-party (or otherwise-external) callee is a resolved LEAF, not an analysis
			// hole: it reaches no in-document symbol and must not defeat Complete.
			status = CallExternal
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
			CallID: call.ID, CallerID: call.CallerID, Callees: candidates, Status: status, Pos: call.Pos,
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

	// A first-party callable stored into a property (`obj.handler = vuln`) can be invoked through that holder
	// out of view of the graph, so it makes a not-reached conclusion for that callable unsafe.
	for _, assignment := range document.Assignments {
		if r.assignmentEscapesFirstParty(assignment) {
			r.addGap(GapUnresolvedValue, assignment.ScopeID, "property_escape", assignment.Pos)
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
		receivers: map[string]map[string][]jsType{},
		bases:     map[string][]string{},
		subclass:  map[string][]string{},
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
		local := item.Alias
		if local == "" {
			local = item.Name
		}
		if item.Kind == ImportReexport || local == "" {
			// A re-export introduces no local callable binding in this module; the whole-namespace forms
			// carry no single-name binding we can follow. Nothing to index (a call through them stays
			// unresolved and gap-flagged rather than mis-bound).
			continue
		}
		module, firstParty := r.resolveSpecifier(item.ScopeID, item.Module)
		if r.imports[item.ScopeID] == nil {
			r.imports[item.ScopeID] = map[string][]importBinding{}
		}
		r.imports[item.ScopeID][local] = append(r.imports[item.ScopeID][local], importBinding{
			kind: item.Kind, module: module, name: item.Name, local: local, firstParty: firstParty,
		})
	}
}

// resolveSpecifier maps an import specifier to an in-document module name. A first-party relative specifier
// ("./util", "../lib/x") resolves against the importer's directory and strips a JS/TS extension, mirroring
// the module names the extractor emits. A bare or scoped package ("express", "@scope/pkg") is third-party:
// it is returned unchanged and firstParty=false, so calls through it resolve to no in-document symbol.
func (r *semanticResolver) resolveSpecifier(scopeID, specifier string) (string, bool) {
	if !strings.HasPrefix(specifier, "./") && !strings.HasPrefix(specifier, "../") {
		return specifier, false
	}
	importer := r.symbols[scopeID].Module
	resolved := path.Join(path.Dir(importer), stripModuleExt(specifier))
	return resolved, true
}

func stripModuleExt(spec string) string {
	for _, ext := range []string{".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"} {
		if strings.HasSuffix(spec, ext) {
			return spec[:len(spec)-len(ext)]
		}
	}
	return spec
}

func (r *semanticResolver) indexBases() {
	for _, symbol := range r.document.Symbols {
		if symbol.Kind != SymbolClass {
			continue
		}
		for _, base := range symbol.Bases {
			types := r.resolveClassReference(symbol.ParentID, base)
			localCount := 0
			for _, typ := range types {
				if typ.classID != "" && typ.classID != symbol.ID {
					r.bases[symbol.ID] = append(r.bases[symbol.ID], typ.classID)
					localCount++
				}
			}
			if localCount == 0 {
				r.addGap(GapUnresolvedValue, symbol.ID, "unresolved_base", symbol.Pos)
			} else if localCount > 1 || len(types) > localCount {
				r.addGap(GapUnresolvedValue, symbol.ID, "ambiguous_base", symbol.Pos)
			}
		}
		r.bases[symbol.ID] = sortedUnique(r.bases[symbol.ID])
	}
	// Reverse index: base class -> direct subclasses, for downward-closure virtual dispatch.
	for classID, bases := range r.bases {
		for _, base := range bases {
			r.subclass[base] = append(r.subclass[base], classID)
		}
	}
	for base := range r.subclass {
		r.subclass[base] = sortedUnique(r.subclass[base])
	}
}

// dispatchMethods resolves a virtual method call on a statically-typed class to a SOUND over-approximation:
// the class's own or inherited implementation of the path, plus a directly-declared override on any subclass
// (transitively). Without the downward closure, `this.m()` on a base type would resolve only to the base's
// method and miss a subclass override, wrongly reporting the override unreached with a "complete" proof.
func (r *semanticResolver) dispatchMethods(classID string, path []string) []string {
	out := r.lookupMethods(classID, path, map[string]bool{})
	for _, sub := range r.allSubclasses(classID) {
		out = append(out, r.lookupQualifiedChildren(sub, path)...)
	}
	return sortedUnique(out)
}

// allSubclasses returns every transitive subclass of classID (excluding itself), following the reverse of
// the extends graph. It carries a visited set so a (malformed) class cycle terminates.
func (r *semanticResolver) allSubclasses(classID string) []string {
	seen := map[string]bool{classID: true}
	var out []string
	queue := append([]string(nil), r.subclass[classID]...)
	for len(queue) > 0 {
		next := queue[0]
		queue = queue[1:]
		if seen[next] {
			continue
		}
		seen[next] = true
		out = append(out, next)
		queue = append(queue, r.subclass[next]...)
	}
	return sortedUnique(out)
}

// derivedEntrypoints treats every module top-level scope as an entrypoint (its top-level statements run on
// import) plus the extractor's framework/application entrypoint hints. Unlike the Python twin it does NOT
// promote every public function to an entrypoint: JS has no leading-underscore privacy convention, and
// over-promoting would make an uncalled module-level function look reached. A reachable-via-export fixture
// is expressed by a top-level driver call, exactly as an application runs.
func (r *semanticResolver) derivedEntrypoints() map[string]bool {
	entrypoints := map[string]bool{}
	for _, symbol := range r.document.Symbols {
		if symbol.Kind == SymbolModule {
			entrypoints[symbol.ID] = true
		}
	}
	return entrypoints
}

func (r *semanticResolver) indexReceivers() {
	// A small fixed point handles chains such as `const alias = Service; const s = new alias()`. Only a
	// `new Class()` binding contributes a receiver type; unknown assignments stay conservative and surface
	// when their member calls fail to resolve.
	for pass := 0; pass < 4; pass++ {
		changed := false
		for _, assignment := range r.document.Assignments {
			if assignment.Value.Kind != ReferenceCall || len(assignment.Value.Segments) == 0 {
				continue
			}
			types := r.constructedTypes(assignment.ScopeID, assignment.Value)
			if len(types) == 0 {
				continue
			}
			for _, target := range assignment.Targets {
				ownerID := assignment.ScopeID
				name := ""
				switch {
				case target.Kind == ReferenceName && len(target.Segments) == 1:
					name = target.Segments[0]
				case target.Kind == ReferenceAttribute && len(target.Segments) == 2 && target.Segments[0] == "this":
					ownerID = r.enclosingClass(assignment.ScopeID)
					name = target.Segments[1]
				}
				if ownerID == "" || name == "" {
					continue
				}
				if r.receivers[ownerID] == nil {
					r.receivers[ownerID] = map[string][]jsType{}
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

// constructedTypes returns the class types a `new X()` / `new ns.X()` value expression constructs. Only a
// ReferenceCall whose callee names a resolvable class contributes a type.
func (r *semanticResolver) constructedTypes(scopeID string, ref Reference) []jsType {
	if ref.Kind != ReferenceCall || len(ref.Segments) == 0 {
		return nil
	}
	return r.resolveClassReference(scopeID, Reference{Kind: ReferenceName, Segments: ref.Segments})
}

func (r *semanticResolver) resolveReference(scopeID string, ref Reference, isNew bool) ([]string, bool) {
	// A ReferenceCall callee is invoking the RESULT of another call (`f()()`, `factory().handler()`). Its
	// target is the callee's return value, which this graph does not track, so it must not be mis-resolved to
	// the inner function; return no candidate so it becomes an unresolved-call gap (incomplete). A `new X()`
	// is unaffected: its callee is the class name (ReferenceName) with Call.New set, not a ReferenceCall.
	if len(ref.Segments) == 0 || ref.Kind == ReferenceUnknown || ref.Kind == ReferenceLiteral || ref.Kind == ReferenceExpression || (ref.Kind == ReferenceCall && !isNew) {
		return nil, false
	}
	segments := ref.Segments
	if isNew {
		// A `new X()` / `new ns.X()` call targets the class constructor (or the class itself when it has no
		// explicit constructor).
		var candidates []string
		for _, typ := range r.resolveClassReference(scopeID, Reference{Kind: ReferenceName, Segments: segments}) {
			candidates = append(candidates, r.constructorOrClass(typ.classID)...)
		}
		return sortedUnique(candidates), false
	}
	// this.method(): virtual dispatch on the enclosing class, resolved by downward closure (the class's
	// own/inherited method PLUS every subclass override), so a template-method call `this.step()` on a base
	// type reaches an override in a subclass instead of being wrongly pinned to the base implementation.
	if segments[0] == "this" && len(segments) > 1 {
		if classID := r.enclosingClass(scopeID); classID != "" {
			return r.dispatchMethods(classID, segments[1:]), false
		}
	}
	// super.method(): resolves to the BASE implementation, skipping the enclosing class's own override. It
	// dispatches up the extends chain only (never to the current class or a sibling subclass).
	if segments[0] == "super" && len(segments) > 1 {
		if classID := r.enclosingClass(scopeID); classID != "" {
			var candidates []string
			for _, base := range r.bases[classID] {
				candidates = append(candidates, r.lookupMethods(base, segments[1:], map[string]bool{})...)
			}
			return sortedUnique(candidates), false
		}
	}
	// receiver.method(): the receiver's constructed type decides the class, again closed downward over
	// subclass overrides.
	if len(segments) > 1 {
		var candidates []string
		for _, typ := range r.receiverTypes(scopeID, segments[0]) {
			candidates = append(candidates, r.dispatchMethods(typ.classID, segments[1:])...)
		}
		if len(candidates) > 0 {
			return sortedUnique(candidates), false
		}
	}
	// A bare name: a lexically visible function/class (constructor) in scope.
	if local := r.lookupLexical(scopeID, segments[0]); len(local) > 0 && len(segments) == 1 {
		var candidates []string
		for _, id := range local {
			candidates = append(candidates, r.targetsFromLocal(id)...)
		}
		return sortedUnique(candidates), false
	}
	// An imported binding: resolve a first-party relative import to the defining module's symbol.
	if bindings := r.lookupImports(scopeID, segments[0]); len(bindings) > 0 {
		var candidates []string
		external := false
		for _, binding := range bindings {
			ids, ext := r.targetsFromImport(binding, segments)
			candidates = append(candidates, ids...)
			external = external || ext
		}
		return sortedUnique(candidates), external
	}
	return nil, false
}

func (r *semanticResolver) resolveClassReference(scopeID string, ref Reference) []jsType {
	if len(ref.Segments) == 0 {
		return nil
	}
	segments := ref.Segments
	if local := r.lookupLexical(scopeID, segments[0]); len(local) > 0 && len(segments) == 1 {
		var out []jsType
		for _, id := range local {
			if r.symbols[id].Kind == SymbolClass {
				out = append(out, jsType{classID: id})
			}
		}
		return uniqueTypes(out)
	}
	if bindings := r.lookupImports(scopeID, segments[0]); len(bindings) > 0 {
		var out []jsType
		for _, binding := range bindings {
			for _, id := range r.localSymbolsFromImport(binding, segments) {
				if r.symbols[id].Kind == SymbolClass {
					out = append(out, jsType{classID: id})
				}
			}
		}
		return uniqueTypes(out)
	}
	return nil
}

// targetsFromLocal returns the call targets of a bare local reference: a function/arrow/method is itself; a
// class is its constructor (or the class symbol when it declares none).
func (r *semanticResolver) targetsFromLocal(id string) []string {
	symbol, ok := r.symbols[id]
	if !ok {
		return nil
	}
	if symbol.Kind == SymbolClass {
		return r.constructorOrClass(id)
	}
	if symbol.Kind == SymbolFunction || symbol.Kind == SymbolArrow || symbol.Kind == SymbolMethod {
		return []string{id}
	}
	return nil
}

func (r *semanticResolver) constructorOrClass(classID string) []string {
	if classID == "" {
		return nil
	}
	if ctors := r.lookupMethods(classID, []string{"constructor"}, map[string]bool{}); len(ctors) > 0 {
		return ctors
	}
	return []string{classID}
}

// targetsFromImport resolves a call whose base name is an imported binding. A first-party relative import to
// an in-document module yields a resolved in-document target. A third-party (bare/scoped) package yields a
// canonical EXTERNAL node (the twin of pythonprogram's canonicalPythonSymbolID): first-party code calling
// into the package is precisely what makes the package's export reachable, so the call graph carries an edge
// caller -> package-export. The external node is a leaf (no outgoing edge) and lives only in edges, never in
// Positions, so it grows the reachable set without changing any first-party reachability; the call keeps
// status CallExternal (a resolved leaf, not a gap), so Complete is unchanged.
func (r *semanticResolver) targetsFromImport(binding importBinding, segments []string) ([]string, bool) {
	if !binding.firstParty {
		if id := externalImportID(binding, segments); id != "" {
			return []string{id}, true
		}
		return nil, true
	}
	moduleID := r.resolveModuleID(binding.module)
	if moduleID == "" {
		// A first-party relative import that resolves to no in-document module is a HOLE, not an external
		// leaf: the file may exist (a directory/index form, an unscanned first-party file) and carry edges we
		// cannot see. Returning external=false makes it an unresolved-call gap so Complete drops to false,
		// rather than silently letting the target read as present_unreached.
		return nil, false
	}
	switch binding.kind {
	case ImportNamed, ImportDefault:
		// `import {work} from './helper'` / `import work from './helper'`: a bare call `work()` targets the
		// module-level export named `binding.name`. A member call `work.x()` is not a module-level function.
		if len(segments) != 1 {
			return nil, false
		}
		exportName := binding.name
		if binding.kind == ImportDefault {
			exportName = "default"
		}
		var out []string
		for _, id := range r.children[moduleID][exportName] {
			out = append(out, r.targetsFromLocal(id)...)
		}
		return sortedUnique(out), false
	case ImportNamespace, ImportRequire:
		// `import * as h from './helper'; h.work()` or `const h = require('./helper'); h.work()`: the member
		// names the export.
		if len(segments) < 2 {
			return nil, false
		}
		var out []string
		for _, id := range r.children[moduleID][segments[1]] {
			out = append(out, r.targetsFromLocal(id)...)
		}
		return sortedUnique(out), false
	}
	return nil, false
}

// externalSymbolPrefix namespaces third-party (npm) call-target node ids. It is deliberately distinct from
// the first-party "js:" prefix (facts.go canonicalSymbolID) so an external leaf can never collide with an
// in-document symbol id.
const externalSymbolPrefix = "jsnpm:"

// ExternalSymbolID is the canonical call-graph node id for a third-party export a first-party call targets:
// "jsnpm:" + import specifier + ":" + export path. A consumer (a reachability analyzer) reconstructs it, or
// matches ExternalSymbolPrefix, to ask whether first-party code reaches a call into that package.
func ExternalSymbolID(specifier, export string) string {
	return externalSymbolPrefix + specifier + ":" + export
}

// ExternalSymbolPrefix is the id prefix shared by every external node for one import specifier, so a consumer
// can match all calls into a package without reconstructing each export path.
func ExternalSymbolPrefix(specifier string) string {
	return externalSymbolPrefix + specifier + ":"
}

// externalImportID builds the external node id for a call into a third-party import binding, encoding the
// package specifier and the export the call names. It mirrors the first-party export resolution: a
// named/default import binds one export (its name); a namespace/require binding names the export by the
// member read. It returns "" for a shape that names no export (a bare call of a whole-namespace binding),
// leaving that call an external leaf with no node rather than inventing an export.
func externalImportID(binding importBinding, segments []string) string {
	var export string
	switch {
	case binding.kind == ImportNamed || binding.kind == ImportDefault ||
		(binding.kind == ImportRequire && binding.name != ""):
		// A named/default import, OR a destructured require (`const {template} = require('lodash')`, which the
		// extractor emits as an ImportRequire carrying the binding name): the local binds one export, named by
		// binding.name. A bare call names that export; a member call adds the member path.
		export = binding.name
		if binding.kind == ImportDefault || export == "" {
			export = "default"
		}
		if len(segments) > 1 {
			export += "." + strings.Join(segments[1:], ".")
		}
	case binding.kind == ImportNamespace || binding.kind == ImportRequire:
		// A whole-namespace binding (`import * as ns` / `const ns = require(...)`): the export is named by the
		// member read. A bare call of the namespace binding names no single export.
		if len(segments) < 2 {
			return ""
		}
		export = strings.Join(segments[1:], ".")
	default:
		return ""
	}
	return ExternalSymbolID(binding.module, export)
}

// resolveModuleID maps a first-party relative module name to its in-document module symbol, trying the
// exact name then the Node directory-import form (`./helper` -> `helper/index` when `helper.js` is absent).
// An empty result means the module is not in the analyzed set.
func (r *semanticResolver) resolveModuleID(module string) string {
	if id := r.modules[module]; id != "" {
		return id
	}
	if id := r.modules[module+"/index"]; id != "" {
		return id
	}
	return ""
}

func (r *semanticResolver) localSymbolsFromImport(binding importBinding, segments []string) []string {
	if !binding.firstParty {
		return nil
	}
	moduleID := r.resolveModuleID(binding.module)
	if moduleID == "" {
		return nil
	}
	switch binding.kind {
	case ImportNamed, ImportDefault:
		if len(segments) != 1 {
			return nil
		}
		exportName := binding.name
		if binding.kind == ImportDefault {
			exportName = "default"
		}
		return r.children[moduleID][exportName]
	case ImportNamespace, ImportRequire:
		if len(segments) < 2 {
			return nil
		}
		return r.children[moduleID][segments[1]]
	}
	return nil
}

func (r *semanticResolver) lookupMethods(classID string, path []string, seen map[string]bool) []string {
	if classID == "" || len(path) == 0 || seen[classID] {
		return nil
	}
	seen[classID] = true
	if direct := r.lookupQualifiedChildren(classID, path); len(direct) > 0 {
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

func (r *semanticResolver) receiverTypes(scopeID, name string) []jsType {
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

// argumentEscapesFirstParty reports whether any argument of the call is a reference that resolves to a
// first-party callable. Such a value can be invoked by the callee out of view of the static graph, so its
// presence makes a not-reached conclusion unsafe.
func (r *semanticResolver) argumentEscapesFirstParty(call Call) bool {
	for _, arg := range call.Arguments {
		if r.referenceIsFirstPartyCallable(call.CallerID, arg.Value) {
			return true
		}
	}
	return false
}

// assignmentEscapesFirstParty reports whether the assignment stores a first-party callable into a MEMBER
// (property) target, e.g. `bus.handler = vuln`. The holder may be an external object that later invokes the
// callable, out of view of the static graph, so a not-reached conclusion for that callable is unsafe. A
// plain local binding (`const f = vuln`) is not flagged here: a later `f()` fails to resolve the alias and
// already forces incompleteness.
func (r *semanticResolver) assignmentEscapesFirstParty(a Assignment) bool {
	if !r.referenceIsFirstPartyCallable(a.ScopeID, a.Value) {
		return false
	}
	for _, target := range a.Targets {
		if len(target.Segments) == 0 {
			continue
		}
		// A property write (attribute) onto any holder escapes. The extractor collapses a member-write target
		// `bus.handler = fn` to its base name, so also treat a write whose base name is an imported (external)
		// object, or a module-export / global sink, as an escape: external code can invoke the callable
		// through that holder. A plain new local binding (`const f = fn`) is not flagged; an unresolvable
		// later use of it already forces incompleteness.
		if target.Kind == ReferenceAttribute {
			return true
		}
		base := target.Segments[0]
		if len(r.lookupImports(a.ScopeID, base)) > 0 {
			return true
		}
		switch base {
		case "exports", "module", "window", "globalThis", "global", "self":
			return true
		}
	}
	return false
}

// referenceIsFirstPartyCallable reports whether a bare or member reference resolves, in scope, to a
// first-party function, arrow, method, or class.
func (r *semanticResolver) referenceIsFirstPartyCallable(scopeID string, ref Reference) bool {
	if ref.Kind != ReferenceName && ref.Kind != ReferenceAttribute {
		return false
	}
	// A bare name that is a first-party callable (function/arrow/method/class), locally or via a first-party
	// import.
	if len(ref.Segments) == 1 {
		for _, id := range r.lookupLexical(scopeID, ref.Segments[0]) {
			switch r.symbols[id].Kind {
			case SymbolFunction, SymbolArrow, SymbolMethod, SymbolClass:
				return true
			}
		}
		for _, binding := range r.lookupImports(scopeID, ref.Segments[0]) {
			if binding.firstParty {
				if ids := r.localSymbolsFromImport(binding, ref.Segments); len(ids) > 0 {
					return true
				}
			}
		}
		return false
	}
	// A member reference (`this.handler`, `super.handler`, `receiver.handler`) resolved the same way a member
	// call would.
	segments := ref.Segments
	switch segments[0] {
	case "this":
		if classID := r.enclosingClass(scopeID); classID != "" && len(r.dispatchMethods(classID, segments[1:])) > 0 {
			return true
		}
	case "super":
		if classID := r.enclosingClass(scopeID); classID != "" {
			for _, base := range r.bases[classID] {
				if len(r.lookupMethods(base, segments[1:], map[string]bool{})) > 0 {
					return true
				}
			}
		}
	default:
		for _, typ := range r.receiverTypes(scopeID, segments[0]) {
			if len(r.dispatchMethods(typ.classID, segments[1:])) > 0 {
				return true
			}
		}
	}
	return false
}

func (r *semanticResolver) addGap(kind GapKind, symbolID, detail string, pos Position) {
	r.gaps = append(r.gaps, CoverageGap{Kind: kind, SymbolID: symbolID, Detail: detail, Pos: pos})
}

func canonicalGaps(gaps []CoverageGap) []CoverageGap {
	sort.Slice(gaps, func(i, j int) bool {
		left := factKey(gaps[i].Pos, string(gaps[i].Kind), gaps[i].SymbolID+":"+gaps[i].Detail)
		right := factKey(gaps[j].Pos, string(gaps[j].Kind), gaps[j].SymbolID+":"+gaps[j].Detail)
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

func uniqueTypes(values []jsType) []jsType {
	sort.Slice(values, func(i, j int) bool { return values[i].classID < values[j].classID })
	out := values[:0]
	for _, value := range values {
		if len(out) > 0 && out[len(out)-1] == value {
			continue
		}
		out = append(out, value)
	}
	return out
}
