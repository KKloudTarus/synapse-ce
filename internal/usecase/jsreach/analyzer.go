// Package jsreach implements deterministic Tier-1 reachability for npm components: does first-party
// JavaScript or TypeScript source actually import a given package?
//
// SAFETY: a not-reachable verdict can suppress a real vulnerability downstream, so this analyzer REFUSES
// a conclusion — returning a no-coverage error, which leaves any prior tier standing — whenever anything
// could hide an import. That includes a failed scan, a module graph with any coverage issue (a dynamic
// loader, an unreadable file, a budget breach), incomplete package resolution, or an ambiguous component
// identity. Only a completely observed project can produce a negative result.
//
// It follows the Python Tier-1 analyzer's model, with two differences. The canonical subject is an EXACT
// component package URL rather than a distribution name, because npm routinely installs several versions
// of the same package and a name alone would not say which one was reached. And it answers only for
// DIRECT dependencies: the module graph is first-party only, so for a transitive package the absence of a
// first-party import proves nothing — that package is loaded by its parent, not by this source tree.
package jsreach

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

// Narrow consumer-side interfaces; ports.JSImportScanner and ports.JSImportResolver satisfy them.
type (
	importScanner interface {
		Scan(ctx context.Context, root string) (modulegraph.Graph, error)
	}
	importResolver interface {
		Resolve(ctx context.Context, root string, graph modulegraph.Graph, doc *sbom.SBOM) (jsresolution.Result, error)
	}
	// sbomProvider supplies the SBOM whose components are the analysis subjects. Package identity is
	// only meaningful against a specific SBOM, and Analyze's signature is fixed by the reachability
	// analyzer contract, so the document is fetched rather than passed.
	sbomProvider interface {
		SBOMFor(ctx context.Context, targetRef string) (*sbom.SBOM, error)
	}
)

// Analyzer implements the reachproof analyzer contract over a JavaScript/TypeScript import scan.
type Analyzer struct {
	scanner  importScanner
	resolver importResolver
	sboms    sbomProvider
}

// New validates and returns the analyzer.
func New(scanner importScanner, resolver importResolver, sboms sbomProvider) (*Analyzer, error) {
	if scanner == nil || resolver == nil || sboms == nil {
		return nil, fmt.Errorf("%w: jsreach analyzer needs a scanner, a resolver and an sbom provider", shared.ErrValidation)
	}
	return &Analyzer{scanner: scanner, resolver: resolver, sboms: sboms}, nil
}

// Analyze reports, for each subject component PURL, whether first-party source imports it.
//
// dir is the workspace directory to scan. Every subject must be an exact npm component PURL; a subject
// of another ecosystem is a caller error rather than a silent non-result, because interpreting it as an
// npm package would answer a question nobody asked.
func (a *Analyzer) Analyze(ctx context.Context, dir string, subjects []string) (*reachability.Analysis, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: jsreach analysis requires a context", shared.ErrValidation)
	}
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("%w: jsreach analysis requires a target directory", shared.ErrValidation)
	}

	wanted, err := normalizeSubjects(subjects)
	if err != nil {
		return nil, err
	}
	if len(wanted) == 0 {
		return &reachability.Analysis{}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	doc, err := a.sboms.SBOMFor(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("jsreach: sbom unavailable (no coverage - prior tier stands): %w", err)
	}
	if doc == nil {
		return nil, fmt.Errorf("%w: jsreach has no sbom for the target (no coverage)", shared.ErrNotFound)
	}

	graph, err := a.scanner.Scan(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("jsreach: javascript import scan (no coverage - prior tier stands): %w", err)
	}
	// A graph coverage issue means some module load was unobservable, so "no edge" is not proof of
	// absence for ANY subject. Refuse the whole analysis rather than risk a false not-reachable.
	if len(graph.Coverage) > 0 {
		return nil, fmt.Errorf("%w: module graph has %d coverage issue(s) - javascript reachability is inconclusive (no coverage)",
			shared.ErrValidation, len(graph.Coverage))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	resolution, err := a.resolver.Resolve(ctx, dir, graph, doc)
	if err != nil {
		return nil, fmt.Errorf("jsreach: package resolution (no coverage - prior tier stands): %w", err)
	}
	if !resolution.Complete {
		// An unresolved, ambiguous or unsupported identity could BE the subject, so no negative
		// conclusion is safe for any of them.
		return nil, fmt.Errorf("%w: package resolution is incomplete - javascript reachability is inconclusive (no coverage)",
			shared.ErrValidation)
	}
	// The resolver may surface graph limitations its own snapshot did not carry; the domain contract
	// says a caller must consider both.
	if len(resolution.GraphCoverage) > 0 {
		return nil, fmt.Errorf("%w: resolution reports %d graph coverage issue(s) - javascript reachability is inconclusive (no coverage)",
			shared.ErrValidation, len(resolution.GraphCoverage))
	}

	// Every subject must be locatable in the very SBOM being reasoned over, and must be a package
	// first-party source could import DIRECTLY. Either gap makes a negative meaningless: an absent
	// component means the subject came from a different document, and a transitive package is loaded by
	// its parent rather than by this source tree.
	if err := subjectsAnswerable(wanted, doc, resolution); err != nil {
		return nil, err
	}

	declarationOnly := make(map[string]bool, len(graph.Modules))
	for _, module := range graph.Modules {
		if module.DeclarationOnly {
			declarationOnly[module.Path] = true
		}
	}
	importers := runtimeImportersByPURL(declarationOnly, resolution)
	prover := newPathProver(graph, declarationOnly)

	results := make([]reachability.Result, 0, len(wanted))
	for _, purl := range wanted {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result := reachability.Result{Symbol: purl}
		// Match on the CANONICAL identity: the subject and the component may be encoded differently
		// ("%40scope" versus "@scope"), and a byte comparison would read that as "not imported".
		canonical, _ := jsresolution.CanonicalNPMPURL(purl)
		if sites := importers[canonical]; len(sites) > 0 {
			result.Reachable = true
			result.Path = prover.proofFor(sites, purl)
		}
		results = append(results, result)
	}

	roots := append([]string(nil), graph.Roots...)
	sort.Strings(roots)
	return &reachability.Analysis{Results: results, Entrypoints: roots}, nil
}

// assertSubjectsAnswerable refuses the analysis unless every subject is a component of the supplied SBOM
// AND a declared direct dependency of first-party code.
//
// Without the first check a subject minted from a different document would silently miss every import
// and be sealed as not-reachable. Without the second, a transitive package — the majority of npm
// findings — would be declared unreachable merely because the first-party graph never names it, which is
// true of every transitive package and proves nothing.
func subjectsAnswerable(subjects []string, doc *sbom.SBOM, resolution jsresolution.Result) error {
	inSBOM := make(map[string]bool, len(doc.Components))
	for _, component := range doc.Components {
		if canonical, ok := jsresolution.CanonicalNPMPURL(component.PURL); ok {
			inSBOM[canonical] = true
		}
	}
	declared := make(map[string]bool, len(resolution.DeclaredDependencies))
	for _, name := range resolution.DeclaredDependencies {
		declared[strings.ToLower(name)] = true
	}

	for _, subject := range subjects {
		canonical, ok := jsresolution.CanonicalNPMPURL(subject)
		if !ok {
			return fmt.Errorf("%w: jsreach subject %q is not a valid npm component purl", shared.ErrValidation, subject)
		}
		if !inSBOM[canonical] {
			return fmt.Errorf("%w: subject %q is not a component of the analyzed sbom - javascript reachability is inconclusive (no coverage)",
				shared.ErrValidation, subject)
		}
		name, _, _ := jsresolution.ParseNPMPURL(subject)
		if !declared[strings.ToLower(name)] {
			return fmt.Errorf("%w: %q is not a declared direct dependency, so a first-party import graph cannot prove it unused (no coverage)",
				shared.ErrValidation, name)
		}
	}
	return nil
}

// normalizeSubjects validates and deduplicates the subjects, preserving both input order and the
// caller's EXACT strings.
//
// It never trims or case-folds a subject. The coordinator looks each result up by the caller's original
// string, so a rewritten key would be missed there and sealed as not-reachable at full confidence — a
// silent false negative. A subject that is not already canonical is a caller error instead.
func normalizeSubjects(subjects []string) ([]string, error) {
	out := make([]string, 0, len(subjects))
	seen := make(map[string]bool, len(subjects))
	for _, subject := range subjects {
		if strings.TrimSpace(subject) == "" {
			return nil, fmt.Errorf("%w: jsreach subject is blank", shared.ErrValidation)
		}
		if subject != strings.TrimSpace(subject) {
			return nil, fmt.Errorf("%w: jsreach subject %q has surrounding whitespace", shared.ErrValidation, subject)
		}
		if _, _, ok := jsresolution.ParseNPMPURL(subject); !ok {
			return nil, fmt.Errorf("%w: jsreach subject %q is not a valid npm component purl", shared.ErrValidation, subject)
		}
		if seen[subject] {
			continue
		}
		seen[subject] = true
		out = append(out, subject)
	}
	return out, nil
}

// importSite is one first-party module importing a component, with the specifier it used.
type importSite struct {
	module      string
	packageName string
}

// runtimeImportersByPURL indexes, per CANONICAL component PURL, the first-party modules that import it
// at runtime. The runtime-versus-type-only rule itself lives in the domain, so this and any other
// consumer cannot drift apart.
func runtimeImportersByPURL(declarationOnly map[string]bool, resolution jsresolution.Result) map[string][]importSite {
	out := map[string][]importSite{}
	for _, imp := range resolution.Imports {
		if imp.Status != jsresolution.StatusComponent || imp.Package.PURL == "" {
			continue
		}
		if !jsresolution.IsRuntimeImport(imp, declarationOnly) {
			continue
		}
		canonical, ok := jsresolution.CanonicalNPMPURL(imp.Package.PURL)
		if !ok {
			continue
		}
		// The proof carries the RESOLVED package name, never the raw source specifier: a specifier is
		// attacker-controlled text that would otherwise reach a sealed, hash-chained judgment rationale,
		// and the name has already been through the domain's strict charset validation.
		out[canonical] = append(out[canonical], importSite{module: imp.From, packageName: imp.Package.Name})
	}
	for purl := range out {
		sites := out[purl]
		sort.Slice(sites, func(i, j int) bool {
			if sites[i].module != sites[j].module {
				return sites[i].module < sites[j].module
			}
			return sites[i].packageName < sites[j].packageName
		})
		out[purl] = sites
	}
	return out
}

// pathProver builds a deterministic, cycle-safe proof path from a structural graph root to an importing
// module. Structural roots are provenance only — they are modules with no incoming first-party edge, not
// verified runtime entrypoints — so the proof states a source-to-component relationship, not an
// execution guarantee.
type pathProver struct {
	// adjacency maps a module to its resolved first-party runtime targets, sorted.
	adjacency map[string][]string
	roots     []string
}

func newPathProver(graph modulegraph.Graph, declarationOnly map[string]bool) *pathProver {
	adjacency := map[string][]string{}
	for _, edge := range graph.Edges {
		if edge.To == "" || edge.TypeOnly {
			continue
		}
		// A declaration module never executes, so a path through one is not a runtime route and must
		// not be presented as evidence.
		if declarationOnly[edge.From] || declarationOnly[edge.To] {
			continue
		}
		adjacency[edge.From] = append(adjacency[edge.From], edge.To)
	}
	for from := range adjacency {
		targets := adjacency[from]
		sort.Strings(targets)
		adjacency[from] = dedupeStrings(targets)
	}
	roots := append([]string(nil), graph.Roots...)
	sort.Strings(roots)
	return &pathProver{adjacency: adjacency, roots: roots}
}

// proofFor returns the shortest deterministic path ending at the component. When no structural root
// reaches an importing module — a cyclic graph has no roots at all — it falls back to the direct proof
// "importer → import specifier → component", which is still explainable evidence.
func (p *pathProver) proofFor(sites []importSite, purl string) []string {
	targets := make(map[string]importSite, len(sites))
	for _, site := range sites {
		if _, exists := targets[site.module]; !exists {
			targets[site.module] = site
		}
	}

	if path, site, ok := p.shortestPathToAny(targets); ok {
		return append(append([]string(nil), path...), "import "+site.packageName, purl)
	}
	// Deterministic fallback: the first importing module in sorted order.
	site := sites[0]
	return []string{site.module, "import " + site.packageName, purl}
}

// shortestPathToAny runs a breadth-first search from the structural roots, visiting neighbours in sorted
// order so the shortest path is also the deterministic one. Visited tracking makes it cycle-safe.
func (p *pathProver) shortestPathToAny(targets map[string]importSite) ([]string, importSite, bool) {
	if len(targets) == 0 || len(p.roots) == 0 {
		return nil, importSite{}, false
	}
	// Track only each node's PARENT and rebuild the one winning path on success. Copying a full path
	// per enqueued node would be O(V^2) memory, which a 50k-module repository turns into gigabytes in
	// this in-process analyzer.
	parent := make(map[string]string, len(p.adjacency))
	visited := make(map[string]bool, len(p.adjacency))
	queue := make([]string, 0, len(p.roots))
	for _, root := range p.roots {
		if visited[root] {
			continue
		}
		visited[root] = true
		queue = append(queue, root)
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if site, ok := targets[current]; ok {
			return buildPath(parent, current), site, true
		}
		for _, next := range p.adjacency[current] {
			if visited[next] {
				continue
			}
			visited[next] = true
			parent[next] = current
			queue = append(queue, next)
		}
	}
	return nil, importSite{}, false
}

// buildPath walks the parent chain back to the root and returns the path in forward order.
func buildPath(parent map[string]string, end string) []string {
	var reversed []string
	for node := end; ; {
		reversed = append(reversed, node)
		previous, ok := parent[node]
		if !ok {
			break
		}
		node = previous
	}
	path := make([]string, 0, len(reversed))
	for i := len(reversed) - 1; i >= 0; i-- {
		path = append(path, reversed[i])
	}
	return path
}

func dedupeStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

// answerableSubjects returns the subset of subjects this analyzer can answer for: every symbol must be a
// component of the analyzed SBOM and a declared direct dependency. A subject that fails either test is
// dropped, because the caller mints a claim for everything it passes on and would otherwise seal an
// unanswerable subject as not-reachable.
//
// A subject-level drop is not a coverage failure — the analysis of the remaining subjects is still sound
// — so this reports an error only when the scan or resolution itself could not be completed.
func (a *Analyzer) answerableSubjects(ctx context.Context, dir string, subjects []ports.ReachabilitySubject) ([]ports.ReachabilitySubject, error) {
	doc, err := a.sboms.SBOMFor(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("jsreach: sbom unavailable (no coverage - prior tier stands): %w", err)
	}
	if doc == nil {
		return nil, fmt.Errorf("%w: jsreach has no sbom for the target (no coverage)", shared.ErrNotFound)
	}
	graph, err := a.scanner.Scan(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("jsreach: javascript import scan (no coverage - prior tier stands): %w", err)
	}
	resolution, err := a.resolver.Resolve(ctx, dir, graph, doc)
	if err != nil {
		return nil, fmt.Errorf("jsreach: package resolution (no coverage - prior tier stands): %w", err)
	}

	out := make([]ports.ReachabilitySubject, 0, len(subjects))
	for _, subject := range subjects {
		symbols := make([]string, 0, len(subject.Symbols))
		for _, symbol := range subject.Symbols {
			if subjectsAnswerable([]string{symbol}, doc, resolution) == nil {
				symbols = append(symbols, symbol)
			}
		}
		if len(symbols) > 0 {
			out = append(out, ports.ReachabilitySubject{FindingID: subject.FindingID, Symbols: symbols})
		}
	}
	return out, nil
}
