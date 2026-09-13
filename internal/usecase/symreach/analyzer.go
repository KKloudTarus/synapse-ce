// Package symreach implements deterministic, RAISE-ONLY symbol-level reachability for the source ecosystems
// whose vulnerable symbols come from the curated DB: PHP (Composer), Ruby (RubyGems), and .NET (NuGet). It
// answers "does first-party source REFERENCE the specific vulnerable function an advisory names", not merely
// "is the package imported" (that is srcreach's Tier-1 job).
//
// It is one PARAMETERIZED analyzer over a per-language symbol-reference scanner and the shared symbolcanon
// canonicalizer: the same canonicalization runs on the observed reference and the advisory subject, so the
// two sides compare symmetrically. It is RAISE-ONLY by construction: it mints a reachable verdict only for a
// PROVEN qualified reference and is physically incapable of emitting a not-reachable one, so a symbol it
// cannot prove reached is simply absent from the output (the coordinator leaves the prior tier standing).
// Its worst case is over-prioritizing a finding, never hiding one, and its proof actors are excluded from
// the deterministic-reachability set so a verdict here can never become an OpenVEX not_affected.
package symreach

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/symbolcanon"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

// SymbolReferenceScanner observes fully-qualified symbol references in first-party source for one language.
// It is source-only and returns what it can PROVE a reference to (qualified calls / instantiations),
// omitting what it cannot (dynamic dispatch, reflection, string-built names) rather than guessing.
type SymbolReferenceScanner interface {
	ScanSymbolRefs(ctx context.Context, dir string) ([]string, error)
}

// Analyzer is the parameterized raise-only symbol-reachability analyzer for one ecosystem.
type Analyzer struct {
	lang     symbolcanon.Language
	purlType string
	scanner  SymbolReferenceScanner
}

// New returns an analyzer for a purl type ("composer"/"gem"/"nuget") canonicalized under lang. A nil scanner
// or empty parameters are a programming error.
func New(purlType string, lang symbolcanon.Language, scanner SymbolReferenceScanner) (*Analyzer, error) {
	if scanner == nil {
		return nil, fmt.Errorf("%w: symreach analyzer needs a symbol scanner", shared.ErrValidation)
	}
	if strings.TrimSpace(purlType) == "" || strings.TrimSpace(string(lang)) == "" {
		return nil, fmt.Errorf("%w: symreach analyzer needs a purl type and language", shared.ErrValidation)
	}
	return &Analyzer{lang: lang, purlType: purlType, scanner: scanner}, nil
}

// Analyzeable reports the package-URL type this analyzer answers for.
func (a *Analyzer) Analyzeable() string { return a.purlType }

// Analyze reports, for each affected-symbol subject, whether first-party source references it. It returns a
// reachable verdict ONLY for a proven qualified reference (tail-matched by its immediate owner + member);
// every other subject is left out, which the raise-only coordinator treats as no verdict.
func (a *Analyzer) Analyze(ctx context.Context, dir string, subjects []string) (*reachability.Analysis, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: symreach analysis requires a context", shared.ErrValidation)
	}
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("%w: symreach analysis requires a target directory", shared.ErrValidation)
	}
	refs, err := a.scanner.ScanSymbolRefs(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("symreach: %s symbol scan (no coverage, prior tier stands): %w", a.purlType, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	observed := make([]symbolcanon.Symbol, 0, len(refs))
	for _, r := range refs {
		c := symbolcanon.Canonicalize(a.lang, r)
		if len(c.Segments) >= 2 { // an owner+member reference; a bare leaf is not a sound identity
			observed = append(observed, c)
		}
	}
	results := make([]reachability.Result, 0, len(subjects))
	seen := map[string]bool{}
	for _, subject := range subjects {
		if strings.TrimSpace(subject) == "" || seen[subject] {
			continue
		}
		seen[subject] = true
		want := symbolcanon.Canonicalize(a.lang, subject)
		if len(want.Segments) < 2 {
			continue // never match on a bare function name (a same-named local); tie it to its owner
		}
		if p, ok := tailMatchAny(want, observed); ok {
			results = append(results, reachability.Result{Symbol: subject, Reachable: true, Path: []string{a.purlType + " qualified reference " + p.String()}})
		}
	}
	return &reachability.Analysis{Results: results}, nil
}

// tailMatchAny reports whether any observed symbol shares the last TWO segments with want (a function
// qualified by its immediate owner), so a bare same-named local never matches. Canonicalization is
// symbolcanon's job and runs symmetrically on both sides. Matching the owner+member tail (rather than the
// full path) is a deliberate recall choice shared with rustsymreach: an observed reference and the advisory
// symbol often differ in leading namespace depth. Its cost is a possible cross-package collision (a local
// `App\Parser::parse` tail-matching a vulnerable `Vendor\Pkg\Parser::parse`), which is raise-only-safe: it
// can only over-raise urgency, never suppress a finding or emit a not_affected.
func tailMatchAny(want symbolcanon.Symbol, observed []symbolcanon.Symbol) (symbolcanon.Symbol, bool) {
	for _, o := range observed {
		if symbolcanon.TailMatch(want, o, 2) {
			return o, true
		}
	}
	return symbolcanon.Symbol{}, false
}
