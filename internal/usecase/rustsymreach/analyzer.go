// Package rustsymreach implements deterministic TIER-2 symbol-level reachability for Rust (crates.io)
// findings: does first-party Rust source reference the specific vulnerable function an advisory names
// (RustSec publishes affected functions as fully-qualified "crate::path::func"), not merely import the
// crate?
//
// It is RAISE-ONLY by construction: it mints a reachable verdict when it can PROVE a reference, and never a
// not-reachable one. A source scan cannot resolve types, so a method call (`x.foo()`) or a macro-hidden
// reference cannot be tied to a crate; those are left unknown rather than guessed. A reachable verdict is
// therefore backed by a qualified path reference ("crate::…::func") or a `use` of the function followed by a
// call, both of which a reader can check against the source. Because it never suppresses, its worst case is
// over-prioritizing a finding, never hiding one, so it stays on the safe side of the no-false-positive bar.
package rustsymreach

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/symbolcanon"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

type symbolScanner interface {
	ScanSymbols(ctx context.Context, dir string) (ports.RustSymbolIndex, error)
}

// Analyzer implements the reachproof analyzer contract for Rust affected-function reachability.
type Analyzer struct{ scanner symbolScanner }

// New returns a Rust symbol-reachability analyzer. A nil scanner is a programming error.
func New(scanner symbolScanner) (*Analyzer, error) {
	if scanner == nil {
		return nil, fmt.Errorf("%w: rustsymreach analyzer needs a symbol scanner", shared.ErrValidation)
	}
	return &Analyzer{scanner: scanner}, nil
}

// Analyzeable reports the package-URL type this analyzer answers for.
func (a *Analyzer) Analyzeable() string { return "cargo" }

// Analyze reports, for each affected-function symbol, whether first-party Rust source references it. It
// returns a reachable verdict only for a proven reference; every other symbol is left Reachable=false, which
// the raise-only coordinator drops rather than turning into a suppressing not-reachable claim.
func (a *Analyzer) Analyze(ctx context.Context, dir string, subjects []string) (*reachability.Analysis, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: rustsymreach analysis requires a context", shared.ErrValidation)
	}
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("%w: rustsymreach analysis requires a target directory", shared.ErrValidation)
	}
	idx, err := a.scanner.ScanSymbols(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("rustsymreach: rust symbol scan (no coverage, prior tier stands): %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Pre-canonicalize the observed qualified references once (shared symbolcanon: the SAME
	// canonicalizer runs on the advisory subject below, so the two sides compare symmetrically).
	qualified := make([]symbolcanon.Symbol, 0, len(idx.Qualified))
	for _, r := range idx.Qualified {
		qualified = append(qualified, symbolcanon.Canonicalize(symbolcanon.Rust, r))
	}
	// use-resolved calls: a leaf bound by `use crate::…::leaf` and actually called as leaf(...).
	usedPaths := make([]symbolcanon.Symbol, 0, len(idx.Uses))
	for leaf, path := range idx.Uses {
		if idx.Called[leaf] {
			usedPaths = append(usedPaths, symbolcanon.Canonicalize(symbolcanon.Rust, path))
		}
	}

	results := make([]reachability.Result, 0, len(subjects))
	seen := map[string]bool{}
	for _, subject := range subjects {
		if strings.TrimSpace(subject) == "" || seen[subject] {
			continue
		}
		seen[subject] = true
		// Only a PROVEN reference is appended, and always Reachable=true. The analyzer is physically
		// incapable of emitting a not-reachable result, so it cannot suppress a finding even if a caller
		// forgot the raise-only wrapper: a symbol it cannot prove reached is simply absent from the output
		// (which the coordinator treats as no verdict, leaving the finding's prior tier standing).
		want := symbolcanon.Canonicalize(symbolcanon.Rust, subject)
		if len(want.Segments) < 2 {
			continue
		}
		if p, ok := tailMatchAny(want, qualified); ok {
			results = append(results, reachability.Result{Symbol: subject, Reachable: true, Path: []string{"rust qualified reference " + p.String()}})
		} else if p, ok := tailMatchAny(want, usedPaths); ok {
			results = append(results, reachability.Result{Symbol: subject, Reachable: true, Path: []string{"rust use + call of " + p.String()}})
		}
	}
	return &reachability.Analysis{Results: results}, nil
}

// tailMatchAny reports whether any observed symbol shares the last TWO segments with want (a function
// qualified by its immediate owner). Requiring two trailing segments, not one, keeps a bare function
// name (a same-named local `parse()`) from matching, so a reachable verdict always ties the function
// to its qualifier. Canonicalization (hyphen-normalization, generic-stripping) is symbolcanon's job.
func tailMatchAny(want symbolcanon.Symbol, observed []symbolcanon.Symbol) (symbolcanon.Symbol, bool) {
	for _, o := range observed {
		if symbolcanon.TailMatch(want, o, 2) {
			return o, true
		}
	}
	return symbolcanon.Symbol{}, false
}
