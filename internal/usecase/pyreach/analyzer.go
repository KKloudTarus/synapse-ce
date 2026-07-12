// Package pyreach answers Tier-1 Python reachability by IMPORT: a vulnerable PyPI package is "reachable"
// iff first-party code imports it. It is the deterministic, source-only analogue of the Go call-graph
// reachability prover — weaker (import-level, not a reached call path, hence Tier-1 not Tier-2) but still
// a real deterministic signal: a declared dependency that is never imported is a dead dependency, a sound
// basis for an OpenVEX not_reachable justification.
//
// SAFETY: a not-reachable verdict must never be a false negative (it can suppress a real vuln downstream).
// So the analyzer REFUSES a conclusion (returns a no-coverage error → the coordinator mints nothing and the
// prior tier stands) when the target has no Python source or uses DYNAMIC imports (importlib/__import__),
// under which a package could be imported invisibly. Candidate import names are generous (a package matches
// on any plausible name), biasing an uncertain case toward the safe "reachable".
package pyreach

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

// importScanner is the narrow first-party-import read the analyzer needs (ports.PyImportScanner satisfies it).
type importScanner interface {
	ScanImports(ctx context.Context, dir string) (ports.PyImportGraph, error)
}

// Analyzer implements the reachproof analyzer contract (Analyze → *reachability.Analysis) over a Python
// import scan. Injected into reachproof.NewCoordinatorForTier(..., Tier1) from the composition root.
type Analyzer struct {
	scanner importScanner
}

// New validates and returns the analyzer.
func New(s importScanner) (*Analyzer, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: pyreach analyzer needs an import scanner", shared.ErrValidation)
	}
	return &Analyzer{scanner: s}, nil
}

// Analyze scans dir's first-party Python imports once and resolves each queried PyPI DISTRIBUTION name to a
// reachability Result (Reachable iff first-party code imports it under ANY of its candidate import names).
// The dist→import mapping lives HERE (not in the SCA caller), so the caller passes only the package name.
// It returns a no-coverage error — so the caller falls back to a lower tier, NEVER a false not-reachable —
// when there is no Python source or the code uses dynamic imports.
func (a *Analyzer) Analyze(ctx context.Context, dir string, symbols []string) (*reachability.Analysis, error) {
	g, err := a.scanner.ScanImports(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("python import scan (no coverage – prior tier stands): %w", err)
	}
	if g.DynamicImports {
		// A dynamically-imported package leaves no static import statement, so "not imported" would be an
		// unsafe false negative. Refuse the whole analysis (no coverage) rather than risk suppressing a vuln.
		return nil, fmt.Errorf("%w: target uses dynamic imports – python reachability is inconclusive (no coverage)", shared.ErrValidation)
	}
	// Match case-INSENSITIVELY: a package imported as "PIL" must match the candidate "pil". Python import
	// names are technically case-sensitive, but folding case here only ever OVER-matches, biasing toward
	// the safe "reachable" — never a false not-reachable.
	imported := make(map[string]bool, len(g.ImportedModules))
	for _, m := range g.ImportedModules {
		imported[strings.ToLower(m)] = true
	}
	out := make([]reachability.Result, 0, len(symbols))
	seen := map[string]bool{}
	for _, sym := range symbols { // sym is the PyPI DISTRIBUTION name (from the SCA finding's component)
		if sym == "" || seen[sym] {
			continue
		}
		seen[sym] = true
		r := reachability.Result{Symbol: sym}
		for _, cand := range ImportCandidates(sym) { // reachable iff ANY plausible import name is imported
			if imported[cand] {
				r.Reachable = true
				r.Path = []string{"import " + cand} // the proof: a first-party module imports this package
				break
			}
		}
		out = append(out, r)
	}
	return &reachability.Analysis{Results: out, Entrypoints: g.FirstPartyModules}, nil
}

// curatedImports maps well-known PyPI DISTRIBUTION names to their real top-level IMPORT name, where the two
// differ (the common cases static normalization alone would miss). Keys are lowercased distribution names.
// A generous, additive table: a missing entry falls back to the normalized candidates, and over-inclusion
// only biases toward the safe "reachable".
var curatedImports = map[string][]string{
	"pyyaml":                 {"yaml"},
	"beautifulsoup4":         {"bs4"},
	"scikit-learn":           {"sklearn"},
	"pillow":                 {"pil"},
	"python-dateutil":        {"dateutil"},
	"opencv-python":          {"cv2"},
	"opencv-python-headless": {"cv2"},
	"msgpack-python":         {"msgpack"},
	"protobuf":               {"google"},
	"pycryptodome":           {"crypto"},
	"pycryptodomex":          {"cryptodome"},
	"python-jose":            {"jose"},
	"pyjwt":                  {"jwt"},
	"pymysql":                {"pymysql"},
	"mysqlclient":            {"mysqldb"},
	"psycopg2-binary":        {"psycopg2"},
	"setuptools":             {"setuptools", "pkg_resources"},
	"typing-extensions":      {"typing_extensions"},
}

// ImportCandidates returns the plausible top-level import names for a PyPI distribution name — the curated
// mapping when known, always PLUS the normalized forms (lowercased; separators → "_" and separators
// removed). Generous by design: matching on any candidate biases an uncertain package toward "reachable"
// (safe), so a not-reachable verdict requires that NONE of these names is imported. Import names are
// compared case-insensitively downstream via the lowercased scan set, so all candidates are lowercased.
func ImportCandidates(dist string) []string {
	d := strings.ToLower(strings.TrimSpace(dist))
	if d == "" {
		return nil
	}
	set := map[string]bool{}
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" {
			set[s] = true
		}
	}
	for _, c := range curatedImports[d] {
		add(strings.ToLower(c))
	}
	// Normalized fallbacks: PyPI treats "-", "_", "." as equivalent in a distribution name.
	repl := strings.NewReplacer("-", "_", ".", "_")
	add(repl.Replace(d))                                           // foo-bar → foo_bar
	add(strings.NewReplacer("-", "", ".", "", "_", "").Replace(d)) // foo-bar → foobar
	add(d)                                                         // verbatim
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	return out
}
