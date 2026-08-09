package jsreach

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/jssymbols"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

// SymbolAnalyzer answers the Tier-2 question: does first-party source reach a SPECIFIC affected export
// of an imported npm package?
//
// It is strictly narrower than Tier-1 and strictly more dangerous. Concluding that a package is imported
// but its vulnerable export is never touched SUPPRESSES a real vulnerability if the analysis missed one
// reference, so the rules are arranged so that anything unobservable produces UNKNOWN — which the caller
// drops, leaving the weaker Tier-1 judgment standing — rather than a negative.
//
// The evidence is the import binding plus what the module then does with it:
//
//   - a named import binds one export exactly (`import {template} from 'lodash'`);
//   - a whole-module binding (`import * as _`, a default import, `const _ = require(...)`) reaches an
//     export only through an observable property read, so it is answerable only when EVERY reference to
//     that local was seen — one escaping reference and the package becomes unanswerable;
//   - a re-export republishes the whole module, and a JSX module desugars into calls this scanner does
//     not see, so both are treated as escaping.
type SymbolAnalyzer struct {
	scanner  importScanner
	resolver importResolver
	sboms    sbomProvider
	// cached is this analyzer's ONE view of the target. The analyzer is constructed per pass, so
	// memoising here does two things: it removes three redundant full lexes of the source tree, and it
	// guarantees the subject filter and the verdict are computed from the SAME snapshot — otherwise a
	// subject admitted as answerable could be decided on evidence that changed underneath it.
	cached    *symbolEvidence
	cachedDir string
	cachedErr error
}

// NewSymbolAnalyzer validates and returns the Tier-2 analyzer.
func NewSymbolAnalyzer(scanner importScanner, resolver importResolver, sboms sbomProvider) (*SymbolAnalyzer, error) {
	if scanner == nil || resolver == nil || sboms == nil {
		return nil, fmt.Errorf("%w: jsreach symbol analyzer needs a scanner, a resolver and an sbom provider", shared.ErrValidation)
	}
	return &SymbolAnalyzer{scanner: scanner, resolver: resolver, sboms: sboms}, nil
}

// Analyze reports, for each `pkg:npm/name@version#symbol` subject, whether first-party source reaches
// that export.
//
// Every subject reaching this point has already been filtered by answerableSubjects, so a subject whose
// verdict is unknown must not appear here. If one does it is reported as REACHABLE rather than not:
// over-approximating toward reachable is the acceptable error, and the coordinator reads a missing
// result as not-reachable.
func (a *SymbolAnalyzer) Analyze(ctx context.Context, dir string, subjects []string) (*reachability.Analysis, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: jsreach symbol analysis requires a context", shared.ErrValidation)
	}
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("%w: jsreach symbol analysis requires a target directory", shared.ErrValidation)
	}
	if len(subjects) == 0 {
		return &reachability.Analysis{}, nil
	}

	evidence, err := a.evidenceFor(ctx, dir)
	if err != nil {
		return nil, err
	}

	results := make([]reachability.Result, 0, len(subjects))
	seen := make(map[string]bool, len(subjects))
	for _, subject := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if seen[subject] {
			continue
		}
		seen[subject] = true

		purl, symbol, ok := jssymbols.ParseSubject(subject)
		if !ok {
			return nil, fmt.Errorf("%w: jsreach symbol subject %q is not a component purl with an export", shared.ErrValidation, subject)
		}
		canonical, ok := jsresolution.CanonicalNPMPURL(purl)
		if !ok {
			return nil, fmt.Errorf("%w: jsreach symbol subject %q does not carry a canonical component identity", shared.ErrValidation, subject)
		}
		decision := jssymbols.Decide(symbol, evidence.uses[canonical])

		result := reachability.Result{Symbol: subject}
		switch decision.Verdict {
		case jssymbols.VerdictNotReachable:
			// Leave Reachable false: every reference to the package was observed and none reaches this
			// export.
		case jssymbols.VerdictReachable:
			result.Reachable = true
			result.Path = evidence.prover.proofForModules(decision.Modules, symbol, subject)
		default:
			// Unknown should have been filtered out. Reaching it means the caller minted a claim this
			// analyzer cannot answer, and the safe answer is the one that suppresses nothing.
			result.Reachable = true
			result.Path = []string{"reachability could not be determined for this export; treated as reachable", subject}
		}
		results = append(results, result)
	}

	roots := append([]string(nil), evidence.roots...)
	sort.Strings(roots)
	return &reachability.Analysis{Results: results, Entrypoints: roots}, nil
}

// symbolEvidence is one scan's Tier-2 view: what every module does with every imported package, plus
// the document and resolution the subjects must be checked against.
type symbolEvidence struct {
	uses       map[string][]jssymbols.Use
	prover     *pathProver
	roots      []string
	doc        *sbom.SBOM
	resolution jsresolution.Result
}

// evidenceFor returns the analyzer's single view of dir, computing it at most once.
func (a *SymbolAnalyzer) evidenceFor(ctx context.Context, dir string) (symbolEvidence, error) {
	if a.cached != nil && a.cachedDir == dir {
		return *a.cached, a.cachedErr
	}
	evidence, err := a.gather(ctx, dir)
	a.cached, a.cachedDir, a.cachedErr = &evidence, dir, err
	return evidence, err
}

// gather scans, resolves and joins. It refuses — returning a no-coverage error that leaves any prior
// tier standing — whenever anything could hide a use.
func (a *SymbolAnalyzer) gather(ctx context.Context, dir string) (symbolEvidence, error) {
	doc, err := a.sboms.SBOMFor(ctx, dir)
	if err != nil {
		return symbolEvidence{}, fmt.Errorf("jsreach: sbom unavailable (no coverage - prior tier stands): %w", err)
	}
	if doc == nil {
		return symbolEvidence{}, fmt.Errorf("%w: jsreach has no sbom for the target (no coverage)", shared.ErrNotFound)
	}
	graph, err := a.scanner.Scan(ctx, dir)
	if err != nil {
		return symbolEvidence{}, fmt.Errorf("jsreach: javascript import scan (no coverage - prior tier stands): %w", err)
	}
	if len(graph.Coverage) > 0 {
		return symbolEvidence{}, fmt.Errorf("%w: module graph has %d coverage issue(s) - javascript symbol reachability is inconclusive (no coverage)",
			shared.ErrValidation, len(graph.Coverage))
	}
	resolution, err := a.resolver.Resolve(ctx, dir, graph, doc)
	if err != nil {
		return symbolEvidence{}, fmt.Errorf("jsreach: package resolution (no coverage - prior tier stands): %w", err)
	}
	if !resolution.Complete {
		return symbolEvidence{}, fmt.Errorf("%w: package resolution is incomplete - javascript symbol reachability is inconclusive (no coverage)",
			shared.ErrValidation)
	}
	if len(resolution.GraphCoverage) > 0 {
		return symbolEvidence{}, fmt.Errorf("%w: resolution reports %d graph coverage issue(s) - javascript symbol reachability is inconclusive (no coverage)",
			shared.ErrValidation, len(resolution.GraphCoverage))
	}

	// The symbol evidence is a SEPARATE completeness question from the import graph's. A nil evidence
	// block means it was never collected, and a coverage entry means some module's references could not
	// be enumerated; in both cases "no reference to this export" is not a fact.
	if !graph.SymbolEvidence.Complete() {
		return symbolEvidence{}, fmt.Errorf("%w: symbol evidence is incomplete - javascript symbol reachability is inconclusive (no coverage)",
			shared.ErrValidation)
	}

	declarationOnly := make(map[string]bool, len(graph.Modules))
	for _, module := range graph.Modules {
		if module.DeclarationOnly {
			declarationOnly[module.Path] = true
		}
	}
	jsx := make(map[string]bool, len(graph.SymbolEvidence.JSXModules))
	for _, module := range graph.SymbolEvidence.JSXModules {
		jsx[module] = true
	}

	return symbolEvidence{
		uses:       collectSymbolUses(graph, resolution, declarationOnly, jsx),
		prover:     newPathProver(graph, declarationOnly),
		roots:      graph.Roots,
		doc:        doc,
		resolution: resolution,
	}, nil
}

// collectSymbolUses joins the import edges (which name the package and the local bindings) with the
// module's own references to those locals (which name the exports actually read).
func collectSymbolUses(graph modulegraph.Graph, resolution jsresolution.Result,
	declarationOnly map[string]bool, jsx map[string]bool) map[string][]jssymbols.Use {
	// Index the resolved package identity by (module, specifier); an edge carries the specifier, the
	// resolution carries the PURL.
	purlOf := make(map[[2]string]string, len(resolution.Imports))
	for _, imp := range resolution.Imports {
		if imp.Status != jsresolution.StatusComponent || imp.Package.PURL == "" {
			continue
		}
		if !jsresolution.IsRuntimeImport(imp, declarationOnly) {
			continue
		}
		if canonical, ok := jsresolution.CanonicalNPMPURL(imp.Package.PURL); ok {
			purlOf[[2]string{imp.From, imp.Specifier}] = canonical
		}
	}

	// Index the module's references to its locals.
	localUses := make(map[[2]string][]modulegraph.LocalUse, len(graph.SymbolEvidence.Uses))
	for _, use := range graph.SymbolEvidence.Uses {
		key := [2]string{use.Module, use.Local}
		localUses[key] = append(localUses[key], use)
	}

	out := map[string][]jssymbols.Use{}
	add := func(use jssymbols.Use) { out[use.PURL] = append(out[use.PURL], use) }

	for _, edge := range graph.Edges {
		if edge.TypeOnly || declarationOnly[edge.From] {
			// A type-only import and a declaration module never execute, so neither can reach an export
			// at runtime.
			continue
		}
		purl, ok := purlOf[[2]string{edge.From, edge.Specifier}]
		if !ok {
			continue
		}

		// A re-export republishes whatever the package exports, under names this scanner cannot
		// enumerate, so it reaches everything.
		if edge.Kind == modulegraph.ImportReExport {
			add(jssymbols.Use{Module: edge.From, PURL: purl, Kind: jssymbols.UseOpaque,
				Reason: "the module re-exports the package"})
			continue
		}
		// A module-loading form with no binding clause at all — a bare `require('pkg')` or a dynamic
		// import whose result is not bound — still executes the module and may reach anything.
		if len(edge.Bindings) == 0 {
			add(jssymbols.Use{Module: edge.From, PURL: purl, Kind: jssymbols.UseOpaque,
				Reason: "the package is loaded without a binding this scanner can follow"})
			continue
		}

		for _, binding := range edge.Bindings {
			if binding.TypeOnly {
				continue
			}
			// A binding whose imported name is literally "default" binds the module's default export,
			// which for a CommonJS package IS the module object — `const {default: axios} =
			// require('axios')` then reaches every export through it. The Default FLAG is not set on that
			// shape, so the name has to be tested too.
			if binding.Imported != "" && binding.Imported != "default" && !binding.Namespace && !binding.Default {
				add(jssymbols.Use{Module: edge.From, PURL: purl, Symbol: binding.Imported, Kind: jssymbols.UseNamed})
				continue
			}
			// Everything else binds the WHOLE module object: a namespace import, and a default import,
			// which for a CommonJS package IS the module object.
			local := strings.TrimSpace(binding.Local)
			if local == "" {
				add(jssymbols.Use{Module: edge.From, PURL: purl, Kind: jssymbols.UseOpaque,
					Reason: "the package is bound without a local name"})
				continue
			}
			// JSX desugars into calls on the runtime binding — createElement, jsx, Fragment — that this
			// scanner never sees as source tokens, so a whole-module binding in a JSX module cannot be
			// enumerated by its visible property reads.
			// The test is whether the module ACTUALLY contains JSX, not what its extension is: JSX is
			// routine in .js under Babel, CRA and Next, and keying on the extension would leave every
			// such module narrowable by its visible property reads alone.
			if jsx[edge.From] {
				add(jssymbols.Use{Module: edge.From, PURL: purl, Kind: jssymbols.UseOpaque,
					Reason: "the module contains JSX, which desugars into calls this scanner does not observe"})
				continue
			}
			references := localUses[[2]string{edge.From, local}]
			if len(references) == 0 {
				// "Every reference was enumerated and none names this export" and "the binding was never
				// mentioned again" are different facts, and only the first permits a negative. A
				// whole-module binding with no observed reference is therefore opaque, not silence:
				// otherwise a second module's named import would be the only evidence and would decide
				// the verdict for a package this module holds in full.
				add(jssymbols.Use{Module: edge.From, PURL: purl, Kind: jssymbols.UseOpaque,
					Reason: "no reference to the whole-module binding was enumerated"})
				continue
			}
			for _, use := range references {
				switch use.Kind {
				case modulegraph.LocalUseProperty:
					add(jssymbols.Use{Module: edge.From, PURL: purl, Symbol: use.Property, Kind: jssymbols.UseMember})
				case modulegraph.LocalUseOpaque:
					add(jssymbols.Use{Module: edge.From, PURL: purl, Kind: jssymbols.UseOpaque, Reason: use.Detail})
				}
			}
		}
	}

	for purl := range out {
		uses := out[purl]
		sort.Slice(uses, func(i, j int) bool {
			if uses[i].Module != uses[j].Module {
				return uses[i].Module < uses[j].Module
			}
			if uses[i].Kind != uses[j].Kind {
				return uses[i].Kind < uses[j].Kind
			}
			return uses[i].Symbol < uses[j].Symbol
		})
		out[purl] = uses
	}
	return out
}

// proofForModules builds a path from a structural root to one of the modules that reaches the export.
func (p *pathProver) proofForModules(modules []string, symbol, subject string) []string {
	if len(modules) == 0 {
		return []string{"uses " + symbol, subject}
	}
	targets := make(map[string]importSite, len(modules))
	for _, module := range modules {
		if _, exists := targets[module]; !exists {
			targets[module] = importSite{module: module}
		}
	}
	if path, _, ok := p.shortestPathToAny(targets); ok {
		return append(append([]string(nil), path...), "uses "+symbol, subject)
	}
	sorted := append([]string(nil), modules...)
	sort.Strings(sorted)
	return []string{sorted[0], "uses " + symbol, subject}
}

// answerableSymbolSubjects drops every subject this analyzer cannot answer, BEFORE the coordinator mints
// a claim for it.
//
// A subject is answerable only when it is a component of the analyzed SBOM, a declared direct dependency
// (a first-party import graph can never prove a transitive package unused), and its export produces a
// decision other than unknown. The coordinator mints a claim for everything it is handed and reads a
// missing result as not-reachable, so an unanswerable subject reaching it would be sealed as a false
// negative at full confidence.
func (a *SymbolAnalyzer) answerableSymbolSubjects(ctx context.Context, dir string, subjects []ports.ReachabilitySubject) ([]ports.ReachabilitySubject, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: jsreach symbol analysis requires a context", shared.ErrValidation)
	}
	evidence, err := a.evidenceFor(ctx, dir)
	if err != nil {
		return nil, err
	}

	out := make([]ports.ReachabilitySubject, 0, len(subjects))
	for _, subject := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		symbols := make([]string, 0, len(subject.Symbols))
		for _, raw := range subject.Symbols {
			purl, symbol, ok := jssymbols.ParseSubject(raw)
			if !ok {
				continue
			}
			if subjectsAnswerable([]string{purl}, evidence.doc, evidence.resolution) != nil {
				continue
			}
			canonical, ok := jsresolution.CanonicalNPMPURL(purl)
			if !ok {
				continue
			}
			if jssymbols.Decide(symbol, evidence.uses[canonical]).Verdict == jssymbols.VerdictUnknown {
				continue
			}
			symbols = append(symbols, raw)
		}
		if len(symbols) > 0 {
			out = append(out, ports.ReachabilitySubject{FindingID: subject.FindingID, Symbols: symbols})
		}
	}
	return out, nil
}
