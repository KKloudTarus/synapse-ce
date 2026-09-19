package jsreach

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/jssymbols"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachproof"
)

// maxInterprocWitnessNodes caps the call-path witness so a pathological graph cannot emit an unbounded
// proof; beyond it the reachable verdict still stands, only the path is summarized.
const maxInterprocWitnessNodes = 64

// jsFactsProvider yields the source-only JS/TS facts the interprocedural resolver consumes.
// ports.JsFactsProvider (the synapse-ast sidecar) satisfies it; the taint engine uses the same seam.
type jsFactsProvider interface {
	JsFacts(ctx context.Context, root string) (jsprogram.Document, bool, error)
}

// InterprocAnalyzer answers npm affected-export reachability from the INTERPROCEDURAL call graph
// (jsprogram.Resolve), the twin of pyreach's Tier-2 analyzer. Where the lexical SymbolAnalyzer proves an
// export is REFERENCED at module scope (an import-path witness), this proves a first-party CALL into the
// package's export is REACHED from an entrypoint through first-party call chains (a call-path witness), so
// it recovers a reachable verdict the lexical model leaves opaque (a whole-module binding that escapes into
// a reached function) and yields a call-chain proof.
//
// It answers BOTH directions. A subject is reachable when it can exhibit a concrete call path from an
// entrypoint to the package's external node; a proven path is sound regardless of the resolver's Complete flag
// (an incomplete graph can still contain a real path). A subject is not-reachable when no such path exists,
// but that negative is only SOUND when the resolver's graph is Complete: whenever it is not, every gap
// (a dynamic construct, an escaping first-party callable, an unresolved or ambiguous call) is surfaced as an
// analysis-wide blind construct so the coordinator taints every not-reachable verdict and none can suppress a
// finding (#1139). The recorder wires it RAISE-ONLY by default (#1058's "JS stays raise-only by default"), so
// the negatives are inert unless the suppressing direction is explicitly enabled.
type InterprocAnalyzer struct {
	provider  jsFactsProvider
	cached    *interprocEvidence
	cachedDir string
	cachedErr error
}

// NewInterprocAnalyzer validates and returns the analyzer.
func NewInterprocAnalyzer(provider jsFactsProvider) (*InterprocAnalyzer, error) {
	if provider == nil {
		return nil, fmt.Errorf("%w: jsreach interprocedural analyzer needs a facts provider", shared.ErrValidation)
	}
	return &InterprocAnalyzer{provider: provider}, nil
}

// FirstPartySymbolSubject constructs the separate local-source query form consumed by InterprocAnalyzer.
// It is intentionally not a purl and is never passed through npm export normalization: source locators name
// an analyzed module and its symbol directly, whereas external npm subjects require package/version handling.
func FirstPartySymbolSubject(modulePath, symbol string) (string, bool) {
	modulePath = strings.ReplaceAll(strings.TrimSpace(modulePath), "\\", "/")
	isSourceModule := false
	for _, extension := range []string{".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"} {
		if strings.HasSuffix(modulePath, extension) {
			modulePath = strings.TrimSuffix(modulePath, extension)
			isSourceModule = true
			break
		}
	}
	modulePath = path.Clean(modulePath)
	if !isSourceModule || modulePath == "" || modulePath == "." || strings.HasPrefix(modulePath, "/") || modulePath == ".." || strings.HasPrefix(modulePath, "../") ||
		strings.ContainsAny(modulePath, ":\r\n\t") || strings.TrimSpace(symbol) == "" || strings.ContainsAny(symbol, "/\\:\r\n\t") {
		return "", false
	}
	return jsprogram.CanonicalSymbolID(modulePath, symbol), true
}

type interprocEvidence struct {
	resolution jsprogram.Resolution
	// externalNodes is every third-party call-target node present in the graph (id "jsnpm:<specifier>:<export>"),
	// pre-split so a per-subject match is a scan of a small slice, not a re-parse of every edge.
	externalNodes []externalNode
	// escapedSpecifiers is the set of import specifiers whose binding is used as a VALUE (passed as a call
	// argument, stored in an assignment, or returned) rather than only as a direct call base. Such a binding
	// can be invoked out of view of the static call graph (a higher-order library callee that calls its
	// argument, a holder external code later reads), which the resolver's Complete flag does NOT capture for a
	// third-party binding. A not-reachable verdict for one of these packages is therefore tainted so it can
	// never suppress a finding (#1139 soundness); positives are unaffected.
	escapedSpecifiers []string
}

type externalNode struct {
	id        string
	specifier string
	export    string
}

// Analyze reports, for each `pkg:npm/name@version#export` subject symbol, whether first-party source reaches
// a CALL into that package's export from an entrypoint. A reachable symbol carries its call-path proof; an
// unreachable one carries a Reachable=false verdict (sound only under a Complete graph, which the blind
// constructs below enforce). An unparseable symbol yields NO result, leaving it unknown, so a subject that
// mixes a parseable and an unparseable symbol is never concluded not-reachable. When the resolver's graph is
// incomplete, every gap is surfaced as an analysis-wide blind construct that taints every not-reachable
// verdict, so absence of a path can never suppress a finding on an incomplete graph.
func (a *InterprocAnalyzer) Analyze(ctx context.Context, dir string, symbols []string) (*reachability.Analysis, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: jsreach interprocedural analysis requires a context", shared.ErrValidation)
	}
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("%w: jsreach interprocedural analysis requires a target directory", shared.ErrValidation)
	}
	if len(symbols) == 0 {
		return &reachability.Analysis{}, nil
	}
	evidence, err := a.evidenceFor(ctx, dir)
	if err != nil {
		return nil, err
	}

	results := make([]reachability.Result, 0, len(symbols))
	seen := make(map[string]bool, len(symbols))
	for _, subject := range symbols {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if seen[subject] {
			continue
		}
		seen[subject] = true

		if strings.HasPrefix(subject, "js:") {
			// First-party symbols are a distinct production-capture query surface. They are accepted only when
			// they are actual positioned source symbols in this resolution, so an external npm node can never be
			// mistaken for a local one and the npm/version-aware contract below remains unchanged.
			if _, firstParty := evidence.resolution.Graph.Positions[subject]; firstParty {
				if path := evidence.resolution.Graph.PathTo(subject); len(path) > 0 {
					results = append(results, reachability.Result{Symbol: subject, Reachable: true, Path: firstPartyWitness(path, subject)})
				}
			}
			continue
		}
		purl, export, ok := jssymbols.ParseSubject(subject)
		if !ok {
			continue // not a component-purl-with-export subject; leave it unknown for another tier
		}
		name, _, ok := jsresolution.ParseNPMPURL(purl)
		if !ok {
			continue
		}
		result := reachability.Result{Symbol: subject}
		if node, path, reached := evidence.reach(name, export); reached {
			result.Reachable = true
			result.Path = witness(path, node, subject)
		} else if evidence.packageEscapes(name) {
			// The package's binding escapes as a value (see escapedImportSpecifiers): a call into the affected
			// export could happen out of view of the resolved graph, so this negative is NOT a sound proof of
			// absence. Tainting it with a per-symbol blind construct keeps ProvedNotReachable false, so it can
			// never suppress the finding even on an otherwise-Complete graph.
			result.BlindConstructs = []string{"jsprogram:import_escape"}
		} else if evidence.exportCalledSomewhere(name, export) {
			// The affected export IS called in first-party code but no path reaches it from a DECLARED entry
			// point. The declared entry points (module top level, main/handler) under-approximate a library's
			// real entry surface: the caller could be an EXPORTED wrapper a consumer or framework invokes
			// (`export function wrap(){ vuln() }`), which would make the export reachable. A call site not
			// reached from a declared entry point is therefore not a sound proof of absence; taint it. Only an
			// affected export with NO first-party call site at all is a sound not-reachable.
			result.BlindConstructs = []string{"jsprogram:export_call_unreached"}
		}
		// A Reachable=false result is a candidate not-reachable verdict; it only becomes a SOUND proof of
		// absence when neither the analysis (Complete) nor this symbol (no escape) carries a blind construct.
		results = append(results, result)
	}

	entrypoints := append([]string(nil), evidence.resolution.Graph.Entrypoints...)
	sort.Strings(entrypoints)
	analysis := &reachability.Analysis{Results: results, Entrypoints: entrypoints}
	if !evidence.resolution.Complete {
		// The graph is incomplete: a dynamic construct, an escaping first-party callable, or an unresolved or
		// ambiguous call left a hole a real call path could pass through. Surface every such gap as an
		// analysis-wide blind construct so the coordinator folds it into every not-reachable claim, which
		// keeps ProvedNotReachable false and forbids suppression. Positives are unaffected (a proven path
		// stands on an incomplete graph).
		analysis.BlindConstructs = gapConstructs(evidence.resolution.Gaps)
	}
	return analysis, nil
}

// gapConstructs summarizes the resolver's coverage gaps into distinct, sorted blind-construct labels. An
// incomplete graph with no explicit gap (a truncated extraction) still returns a generic marker, so a
// not-reachable verdict is never treated as sound on an incomplete graph.
func gapConstructs(gaps []jsprogram.CoverageGap) []string {
	if len(gaps) == 0 {
		return []string{"jsprogram:incomplete"}
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(gaps))
	for _, gap := range gaps {
		label := "jsprogram:" + string(gap.Kind)
		if !seen[label] {
			seen[label] = true
			out = append(out, label)
		}
	}
	sort.Strings(out)
	return out
}

// evidenceFor resolves the interprocedural call graph for dir at most once per analyzer (the analyzer is
// constructed per pass), so the union of subjects shares one facts extraction and one resolve.
func (a *InterprocAnalyzer) evidenceFor(ctx context.Context, dir string) (interprocEvidence, error) {
	if a.cached != nil && a.cachedDir == dir {
		return *a.cached, a.cachedErr
	}
	evidence, err := a.gather(ctx, dir)
	a.cached, a.cachedDir, a.cachedErr = &evidence, dir, err
	return evidence, err
}

func (a *InterprocAnalyzer) gather(ctx context.Context, dir string) (interprocEvidence, error) {
	document, available, err := a.provider.JsFacts(ctx, dir)
	if err != nil {
		return interprocEvidence{}, fmt.Errorf("jsreach interprocedural facts (no coverage - prior tier stands): %w", err)
	}
	if !available {
		return interprocEvidence{}, fmt.Errorf("%w: jsreach interprocedural facts sidecar is unavailable", shared.ErrNotFound)
	}
	resolution, err := jsprogram.Resolve(document)
	if err != nil {
		return interprocEvidence{}, fmt.Errorf("jsreach interprocedural resolution (no coverage - prior tier stands): %w", err)
	}
	return interprocEvidence{
		resolution:        resolution,
		externalNodes:     externalNodesOf(resolution),
		escapedSpecifiers: escapedImportSpecifiers(document),
	}, nil
}

// escapedImportSpecifiers returns the sorted set of import specifiers whose local binding is used as a VALUE
// somewhere in the document: passed as a call argument, stored as an assignment value, or returned. Such a
// binding can be invoked out of view of the resolved call graph (a higher-order callee that calls its
// argument, a holder read by code we do not model), and the resolver keeps the graph Complete for a
// third-party binding in these shapes, so this is the guard the Complete flag does not provide. Matching is by
// the reference's base segment against the import's local alias, so only the affected binding itself (not an
// unrelated identifier) marks its package escaped. The check is intentionally over-approximate: a binding
// merely passed to a first-party function that never invokes it is still marked, which at worst forgoes a
// suppression (raise-only), never an unsound one.
func escapedImportSpecifiers(doc jsprogram.Document) []string {
	aliasToSpecifier := make(map[string]string, len(doc.Imports))
	escaped := map[string]bool{}
	for _, imp := range doc.Imports {
		if imp.Kind == jsprogram.ImportReexport {
			// `export { vuln } from 'pkg'` / `export * from 'pkg'` re-exports the package's surface through this
			// module. A consumer of this module can call the re-exported symbol, so its export is reachable
			// beyond what the module's own call graph shows; a not-reachable verdict for it must not suppress.
			escaped[imp.Module] = true
			continue
		}
		alias := imp.Alias
		if alias == "" {
			alias = imp.Name
		}
		if alias != "" {
			aliasToSpecifier[alias] = imp.Module
		}
	}
	if len(aliasToSpecifier) == 0 && len(escaped) == 0 {
		return nil
	}
	mark := func(ref jsprogram.Reference) {
		if len(ref.Segments) == 0 {
			return
		}
		if specifier, ok := aliasToSpecifier[ref.Segments[0]]; ok {
			escaped[specifier] = true
		}
	}
	for _, call := range doc.Calls {
		for _, arg := range call.Arguments {
			mark(arg.Value)
		}
	}
	for _, assignment := range doc.Assignments {
		mark(assignment.Value)
	}
	for _, ret := range doc.Returns {
		mark(ret.Value)
	}
	// A value slot that references the binding by name (or member) catches an escape the top-level
	// argument/assignment/return references miss: an affected binding nested inside an escaping object or array
	// literal (`const o = { h: vuln }`, `[vuln]`) surfaces as a name-reference Value. A call callee is a
	// call-kind value, not a name reference, so a resolved call into the binding is not mistaken for an escape.
	for _, value := range doc.Values {
		if value.Ref.Kind == jsprogram.ReferenceName || value.Ref.Kind == jsprogram.ReferenceAttribute {
			mark(value.Ref)
		}
	}
	if len(escaped) == 0 {
		return nil
	}
	out := make([]string, 0, len(escaped))
	for specifier := range escaped {
		out = append(out, specifier)
	}
	sort.Strings(out)
	return out
}

// packageEscapes reports whether any escaped import specifier belongs to the npm package name (the bare
// specifier or a subpath), so a not-reachable verdict for that package must be tainted.
func (e interprocEvidence) packageEscapes(name string) bool {
	for _, specifier := range e.escapedSpecifiers {
		if specifierMatchesPackage(specifier, name) {
			return true
		}
	}
	return false
}

// externalNodesOf collects the distinct third-party call-target nodes present as edge callees, pre-splitting
// each id into (specifier, export) so per-subject matching is cheap.
func externalNodesOf(res jsprogram.Resolution) []externalNode {
	seen := map[string]bool{}
	var out []externalNode
	for _, edge := range res.Graph.Edges {
		for _, callee := range edge.Callees {
			if seen[callee] {
				continue
			}
			specifier, export, ok := splitExternalID(callee)
			if !ok {
				continue // not a "jsnpm:<specifier>:<export>" external node
			}
			seen[callee] = true
			out = append(out, externalNode{id: callee, specifier: specifier, export: export})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// splitExternalID parses "jsnpm:<specifier>:<export>" into its specifier and export. The specifier may
// contain "/" (a subpath or a scope) but not ":", so the FIRST ":" after the prefix separates them.
func splitExternalID(id string) (string, string, bool) {
	const prefix = "jsnpm:"
	if !strings.HasPrefix(id, prefix) {
		return "", "", false
	}
	rest := id[len(prefix):]
	i := strings.IndexByte(rest, ':')
	if i <= 0 || i == len(rest)-1 {
		return "", "", false
	}
	return rest[:i], rest[i+1:], true
}

// reach reports whether a call into package `name`'s affected `export` is reachable from an entrypoint,
// returning the reached external node and the call path. An advisory that names an export requires the node
// export to relate to it (an exact match, a "default."-qualified CommonJS member, or a dotted-member suffix);
// an advisory with no export matches any reached call into the package. Matching is generous only WITHIN the
// package, which is raise-only-safe: a coarse match can at worst raise the package's own finding, never
// suppress one and never cross to another package.
func (e interprocEvidence) reach(name, export string) (string, []string, bool) {
	for _, node := range e.externalNodes {
		if !specifierMatchesPackage(node.specifier, name) {
			continue
		}
		if export != "" && !exportMatches(node.export, export) {
			continue
		}
		if path := e.resolution.Graph.PathTo(node.id); len(path) > 0 {
			return node.id, path, true
		}
	}
	return "", nil, false
}

// exportCalledSomewhere reports whether a call into package `name`'s affected `export` EXISTS anywhere in the
// resolved graph, regardless of whether a declared entry point reaches it. A call site that exists but is not
// reached from an entry point is not a sound proof of absence (its caller could be an exported wrapper a
// consumer invokes), so the caller taints such a negative. It mirrors reach's matching but skips the PathTo.
func (e interprocEvidence) exportCalledSomewhere(name, export string) bool {
	for _, node := range e.externalNodes {
		if !specifierMatchesPackage(node.specifier, name) {
			continue
		}
		if export != "" && !exportMatches(node.export, export) {
			continue
		}
		return true
	}
	return false
}

// specifierMatchesPackage reports whether an import specifier belongs to the npm package `name`: the bare
// package specifier, or a subpath import ("lodash/fp" for "lodash").
func specifierMatchesPackage(specifier, name string) bool {
	return specifier == name || strings.HasPrefix(specifier, name+"/")
}

// exportMatches reports whether an external node's export path corresponds to the advisory's affected
// export. It matches EXACTLY, with one modeled alias: a CommonJS default-object member (`import axios from
// 'axios'; axios.get()` records the export as "default.get") matches the bare advisory export "get". It
// deliberately does NOT match a deeper dotted member by suffix: `safeObj.vuln()` (export "safeObj.vuln")
// must not be read as reaching a top-level affected export "vuln", which would raise the wrong finding.
func exportMatches(nodeExport, want string) bool {
	return nodeExport == want || nodeExport == "default."+want
}

// witness renders the reachable proof: the call path (entrypoint -> ... -> package export node), capped, with
// the subject appended so the sealed proof names what was proven reachable.
func witness(path []string, node, subject string) []string {
	if len(path) > maxInterprocWitnessNodes {
		return []string{"jsprogram:reachable:witness-budget-exceeded", node, subject}
	}
	out := append([]string(nil), path...)
	return append(out, subject)
}

func firstPartyWitness(path []string, subject string) []string {
	if len(path) > maxInterprocWitnessNodes {
		return []string{"jsprogram:reachable:witness-budget-exceeded", subject}
	}
	return append([]string(nil), path...)
}

// InterprocRecorder wires the interprocedural analyzer into the reachability pass. By default it is
// RAISE-ONLY: it mints only a REACHABLE Tier-2 judgment (with a call-path proof) the lexical Tier-1/Tier-2
// missed, never a not-reachable one, so it can never suppress a finding. WithSuppression enables the
// SUPPRESSING direction (#1139, opt-in): the recorder then also mints a not-reachable Tier-2 judgment for a
// subject whose affected export is unreached in a COMPLETE graph with entry points present, which can drive an
// OpenVEX not_affected. It satisfies ports.ReachabilityRecorder and composes alongside the other recorders via
// Service.AddReachabilityRecorder.
type InterprocRecorder struct {
	provider  jsFactsProvider
	judgments recorderPort
	audit     ports.AuditLogger
	clock     ports.Clock
	suppress  bool
}

// NewInterprocRecorder validates and returns the recorder, raise-only by default.
func NewInterprocRecorder(provider jsFactsProvider, judgments recorderPort, audit ports.AuditLogger, clock ports.Clock) (*InterprocRecorder, error) {
	if provider == nil || judgments == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: jsreach interprocedural recorder is missing a dependency", shared.ErrValidation)
	}
	return &InterprocRecorder{provider: provider, judgments: judgments, audit: audit, clock: clock}, nil
}

// WithSuppression turns the suppressing interprocedural direction on or off and returns the recorder. It is
// off by default; enabling it (behind SYNAPSE_JSREACH_INTERPROC_TIER2_ENABLED) lets a proven not-reachable
// npm export drive a not_affected suppression. Soundness is enforced by the analyzer's Complete-gated blind
// constructs and the coordinator's entry-points-present guard, so a suppression only stands on a complete
// graph analysed from real entry points.
func (r *InterprocRecorder) WithSuppression(enabled bool) *InterprocRecorder {
	r.suppress = enabled
	return r
}

// Record analyses the target and mints raise-only Tier-2 JavaScript reachability judgments for the subjects
// whose affected export is proven reached through the first-party call graph.
//
// It is fed the RAW reachability subjects (a package purl plus the advisory's affected symbols) that the SCA
// pass hands every recorder on the shared reachability slot. The reachproof coordinator flattens each
// subject to a bare []string before the analyzer sees it, which discards the package purl, so this recorder
// first RE-ENCODES each npm subject's raw symbols into the `pkg:npm/name@version#export` form the analyzer
// parses (keeping the finding id), the same encoding the lexical Tier-2 subject builder uses. A non-npm
// subject, or a raw symbol that does not normalize to an export, is dropped: raise-only, so a dropped
// subject only forgoes a positive and never suppresses.
func (r *InterprocRecorder) Record(ctx context.Context, engagementID shared.ID, targetRef string, subjects []ports.ReachabilitySubject) (int, error) {
	encoded := encodeNPMSubjects(subjects)
	if len(encoded) == 0 {
		return 0, nil
	}
	analyzer, err := NewInterprocAnalyzer(r.provider)
	if err != nil {
		return 0, err
	}
	coordinator, err := reachproof.NewCoordinatorForLanguage(analyzer, r.judgments, r.audit, r.clock, judgment.Tier2, reachproof.LanguageJavaScript)
	if err != nil {
		return 0, err
	}
	if !r.suppress {
		return coordinator.WithRaiseOnly().Record(ctx, engagementID, targetRef, encoded)
	}
	// Suppressing direction (opt-in): the coordinator may mint a not-reachable Tier-2 claim, gated by its
	// entry-points-present guard and the analyzer's Complete-gated blind constructs; a proven not-reachable
	// export can then suppress its finding.
	return coordinator.Record(ctx, engagementID, targetRef, encoded)
}

// EncodeNPMSubjects converts exact npm package identities and affected exports into the
// interprocedural subject encoding, skipping inputs whose identity is ambiguous or invalid.
func EncodeNPMSubjects(subjects []ports.ReachabilitySubject) []ports.ReachabilitySubject {
	return encodeNPMSubjects(subjects)
}

// encodeNPMSubjects converts the raw (PackagePURL + affected symbols) subjects the SCA pass produces into the
// `pkg:npm/name@version#export` subjects the interprocedural analyzer parses. Only an npm package with at
// least one normalizable affected symbol yields a subject; the finding id is preserved so the coordinator's
// per-finding supersession still holds.
func encodeNPMSubjects(subjects []ports.ReachabilitySubject) []ports.ReachabilitySubject {
	// A first-party import specifier ("lodash") carries no version, so the call graph cannot say WHICH
	// installed version of a package a reached call resolves to. When two versions of one package each have a
	// finding (npm allows several versions side by side), attributing the reached call to either would raise a
	// version that may not be the one imported. Detect that ambiguity and skip the package entirely (the
	// version-exact lexical Tier-1/Tier-2, which resolves the import against the SBOM, still stands): a skipped
	// package only forgoes a raise, never suppresses.
	versionsByName := map[string]map[string]bool{}
	for _, s := range subjects {
		name, _, ok := jsresolution.ParseNPMPURL(s.PackagePURL)
		if !ok {
			continue
		}
		if versionsByName[name] == nil {
			versionsByName[name] = map[string]bool{}
		}
		if canonical, ok := jsresolution.CanonicalNPMPURL(s.PackagePURL); ok {
			versionsByName[name][canonical] = true
		}
	}

	var out []ports.ReachabilitySubject
	for _, s := range subjects {
		name, _, ok := jsresolution.ParseNPMPURL(s.PackagePURL)
		if !ok {
			continue // not an npm finding (Go/PyPI/etc): another recorder answers it
		}
		if len(versionsByName[name]) > 1 {
			continue // version-ambiguous: the call graph cannot pick which version was reached
		}
		canonical, ok := jsresolution.CanonicalNPMPURL(s.PackagePURL)
		if !ok {
			continue
		}
		encoded := make([]string, 0, len(s.Symbols))
		seen := map[string]bool{}
		for _, raw := range s.Symbols {
			export, ok := jssymbols.NormalizeAffectedSymbol(name, raw)
			if !ok || seen[export] {
				continue
			}
			subject, ok := jssymbols.Subject(canonical, export)
			if !ok {
				continue
			}
			seen[export] = true
			encoded = append(encoded, subject)
		}
		if len(encoded) > 0 {
			out = append(out, ports.ReachabilitySubject{FindingID: s.FindingID, Symbols: encoded})
		}
	}
	return out
}

var _ ports.ReachabilityRecorder = (*InterprocRecorder)(nil)
