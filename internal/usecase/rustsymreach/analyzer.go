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

	// Pre-split the observed qualified references once.
	qualified := make([][]string, 0, len(idx.Qualified))
	for _, r := range idx.Qualified {
		qualified = append(qualified, splitNorm(r))
	}
	// use-resolved calls: a leaf bound by `use crate::…::leaf` and actually called as leaf(...).
	usedPaths := make([][]string, 0, len(idx.Uses))
	for leaf, path := range idx.Uses {
		if idx.Called[leaf] {
			usedPaths = append(usedPaths, splitNorm(path))
		}
	}

	results := make([]reachability.Result, 0, len(subjects))
	seen := map[string]bool{}
	for _, subject := range subjects {
		if strings.TrimSpace(subject) == "" || seen[subject] {
			continue
		}
		seen[subject] = true
		want := splitNorm(subject)
		res := reachability.Result{Symbol: subject}
		if len(want) >= 2 {
			if p, ok := matchTail(want, qualified); ok {
				res.Reachable = true
				res.Path = []string{"rust qualified reference " + strings.Join(p, "::")}
			} else if p, ok := matchTail(want, usedPaths); ok {
				res.Reachable = true
				res.Path = []string{"rust use + call of " + strings.Join(p, "::")}
			}
		}
		results = append(results, res)
	}
	return &reachability.Analysis{Results: results}, nil
}

// matchTail reports whether any observed path shares the last TWO segments with the wanted symbol (a
// function name qualified by its immediate owner: a module or a type). Requiring two trailing segments,
// not one, keeps a bare function name (e.g. a same-named local `parse()`) from matching, so a reachable
// verdict always ties the function to its qualifier. Segments are hyphen-normalized (a RustSec crate name
// may be hyphenated where Rust source uses underscores).
func matchTail(want []string, observed [][]string) ([]string, bool) {
	w := want[len(want)-2:]
	for _, o := range observed {
		if len(o) < 2 {
			continue
		}
		if o[len(o)-1] == w[1] && o[len(o)-2] == w[0] {
			return o, true
		}
	}
	return nil, false
}

// splitNorm splits a Rust path into hyphen-normalized, case-preserved segments.
func splitNorm(p string) []string {
	var out []string
	for _, s := range strings.Split(strings.TrimPrefix(strings.TrimSpace(p), "::"), "::") {
		s = strings.ReplaceAll(strings.TrimSpace(s), "-", "_")
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
