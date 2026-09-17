package jsreach

import (
	"context"
	"fmt"
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
// It is POSITIVE-ONLY by construction: it reports a subject reachable only when it can exhibit a concrete
// call path from an entrypoint to the package's external node, and reports nothing otherwise. A proven path
// is sound regardless of the resolver's Complete flag (an incomplete graph can still contain a real path),
// so unlike a suppressing analyzer it never needs completeness and never emits a negative. The recorder
// wires it raise-only, matching #1058's "JS stays raise-only by default".
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

type interprocEvidence struct {
	resolution jsprogram.Resolution
	// externalNodes is every third-party call-target node present in the graph (id "jsnpm:<specifier>:<export>"),
	// pre-split so a per-subject match is a scan of a small slice, not a re-parse of every edge.
	externalNodes []externalNode
}

type externalNode struct {
	id        string
	specifier string
	export    string
}

// Analyze reports, for each `pkg:npm/name@version#export` subject symbol, whether first-party source
// reaches a CALL into that package's export from an entrypoint. It returns a result only for a reachable
// symbol; an unreachable or unparseable symbol yields no positive, which the raise-only coordinator reads as
// "nothing to mint" (the prior tier stands). It never returns a not-reachable verdict.
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

		purl, export, ok := jssymbols.ParseSubject(subject)
		if !ok {
			continue // not a component-purl-with-export subject; positive-only, so leave it to another tier
		}
		name, _, ok := jsresolution.ParseNPMPURL(purl)
		if !ok {
			continue
		}
		if node, path, reached := evidence.reach(name, export); reached {
			results = append(results, reachability.Result{Symbol: subject, Reachable: true, Path: witness(path, node, subject)})
		}
	}

	entrypoints := append([]string(nil), evidence.resolution.Graph.Entrypoints...)
	sort.Strings(entrypoints)
	return &reachability.Analysis{Results: results, Entrypoints: entrypoints}, nil
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
	return interprocEvidence{resolution: resolution, externalNodes: externalNodesOf(resolution)}, nil
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

// InterprocRecorder wires the interprocedural analyzer into the reachability pass, RAISE-ONLY: it mints only
// a REACHABLE Tier-2 judgment and never a not-reachable one, so it can only add a reachable verdict (with a
// call-path proof) the lexical Tier-1/Tier-2 missed, never suppress a finding. It satisfies
// ports.ReachabilityRecorder and composes alongside the other recorders via Service.AddReachabilityRecorder.
type InterprocRecorder struct {
	provider  jsFactsProvider
	judgments recorderPort
	audit     ports.AuditLogger
	clock     ports.Clock
}

// NewInterprocRecorder validates and returns the recorder.
func NewInterprocRecorder(provider jsFactsProvider, judgments recorderPort, audit ports.AuditLogger, clock ports.Clock) (*InterprocRecorder, error) {
	if provider == nil || judgments == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: jsreach interprocedural recorder is missing a dependency", shared.ErrValidation)
	}
	return &InterprocRecorder{provider: provider, judgments: judgments, audit: audit, clock: clock}, nil
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
	return coordinator.WithRaiseOnly().Record(ctx, engagementID, targetRef, encoded)
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
