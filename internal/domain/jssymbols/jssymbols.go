// Package jssymbols holds the decision rules for Tier-2 JavaScript and TypeScript reachability: given
// what first-party source statically does with an imported npm package, can a specific AFFECTED SYMBOL
// of that package be reached?
//
// Tier-1 answers "is this package imported at all". Tier-2 is strictly narrower and strictly more
// dangerous: concluding that a package IS imported but the vulnerable export is never touched suppresses
// a real vulnerability if the analysis missed a single reference. Every rule here is therefore written to
// fail towards UNKNOWN, and the package is pure domain code — no filesystem, parser, resolver or
// judgment work happens in it, so the rules can be read and tested on their own.
//
// The central idea is OPACITY. A named import (`import {template} from 'lodash'`) tells us exactly which
// export is bound. A namespace import (`import * as _ from 'lodash'`), a default import of a CommonJS
// module, or `const _ = require('lodash')` binds the WHOLE module object; the symbols actually used are
// then only knowable if every reference to that local is an observable property read. The moment such a
// local escapes — passed to a function, spread, indexed with a computed key, re-exported — any export
// could be reached, and this package says so rather than guessing.
package jssymbols

import (
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// UseKind classifies how first-party source touches an imported package.
type UseKind string

const (
	// UseNamed is a binding that names one export: `import {template}`, `export {template} from`,
	// `const {template} = require(...)`. The symbol is known exactly.
	UseNamed UseKind = "named"
	// UseMember is a property read on a whole-module local: `_.template`. The symbol is known exactly,
	// but only because every other reference to that local was also observed.
	UseMember UseKind = "member"
	// UseOpaque is a reference to a whole-module local that could reach ANY export: the local is passed
	// somewhere, indexed with a computed key, re-exported, or used in a form this analysis does not
	// model. It carries no symbol, and its presence alone makes the package unanswerable.
	UseOpaque UseKind = "opaque"
)

// Valid reports whether k is a known use kind.
func (k UseKind) Valid() bool {
	switch k {
	case UseNamed, UseMember, UseOpaque:
		return true
	}
	return false
}

// Use is one statically observed interaction between a first-party module and an imported package.
type Use struct {
	// Module is the normalized repository-relative path of the first-party module.
	Module string
	// PURL is the canonical package URL of the imported component.
	PURL string
	// Symbol is the export named by the use. It is empty for UseOpaque, and MUST be empty for it: an
	// opaque reference is precisely one whose symbol is unknown.
	Symbol string
	Kind   UseKind
	// Reason explains an opaque use in words a reader can act on ("namespace passed as an argument").
	// It never carries source text, which is untrusted input on its way to a sealed judgment rationale.
	Reason string
}

// Validate reports whether u is internally consistent.
func (u Use) Validate() error {
	if strings.TrimSpace(u.Module) == "" {
		return fmt.Errorf("%w: a symbol use needs the module that made it", shared.ErrValidation)
	}
	if strings.TrimSpace(u.PURL) == "" {
		return fmt.Errorf("%w: a symbol use needs the package it touches", shared.ErrValidation)
	}
	if !u.Kind.Valid() {
		return fmt.Errorf("%w: %q is not a known symbol use kind", shared.ErrValidation, u.Kind)
	}
	if u.Kind == UseOpaque && strings.TrimSpace(u.Symbol) != "" {
		return fmt.Errorf("%w: an opaque use cannot name a symbol - its symbol is what is unknown", shared.ErrValidation)
	}
	if u.Kind != UseOpaque && strings.TrimSpace(u.Symbol) == "" {
		return fmt.Errorf("%w: a %s use must name the symbol it binds", shared.ErrValidation, u.Kind)
	}
	return nil
}

// Verdict is the Tier-2 answer for one (package, symbol) pair.
type Verdict string

const (
	// VerdictReachable means first-party source binds or reads the affected symbol.
	VerdictReachable Verdict = "reachable"
	// VerdictNotReachable means every reference to the package was observed and none of them can reach
	// the affected symbol. This is the only conclusion that can suppress a finding, so it is issued only
	// when nothing opaque was seen.
	VerdictNotReachable Verdict = "not-reachable"
	// VerdictUnknown means something could hide a use. It is NOT a negative: the caller must leave any
	// weaker existing judgment standing rather than record an absence of proof as proof of absence.
	VerdictUnknown Verdict = "unknown"
)

// Decision is a verdict plus the evidence a reader needs to check it.
type Decision struct {
	Verdict Verdict
	// Modules are the first-party modules that justify the verdict: the ones that reach the symbol for
	// a positive, the ones holding an opaque reference for an unknown. Sorted and deduplicated.
	Modules []string
	// Reason explains a non-positive verdict.
	Reason string
}

// Decide answers whether symbol can be reached, given every observed use of one package.
//
// The order of the rules is the safety property, not a detail:
//
//  1. a use that names the symbol wins immediately — a positive is always safe to report;
//  2. otherwise ANY opaque reference makes the answer unknown, because the symbol could be reached
//     through it and nothing observed rules that out;
//  3. only when every reference was named and none matched is a negative issued.
//
// Callers must pass EVERY use of the package, not a filtered subset: a caller that filters first and then
// asks would hide exactly the opaque reference this function exists to notice. An empty set means the
// package is not imported at all, which is a Tier-1 question and is reported unknown here rather than
// being answered twice at two different strengths.
func Decide(symbol string, uses []Use) Decision {
	wanted := strings.TrimSpace(symbol)
	if wanted == "" {
		return Decision{Verdict: VerdictUnknown, Reason: "no affected symbol was supplied"}
	}
	if len(uses) == 0 {
		return Decision{
			Verdict: VerdictUnknown,
			Reason:  "no observed use of the package: package-level absence is a tier-1 conclusion, not a symbol-level one",
		}
	}

	var reaching, opaque []string
	opaqueReason := ""
	for _, use := range uses {
		switch use.Kind {
		case UseOpaque:
			opaque = append(opaque, use.Module)
			if opaqueReason == "" {
				opaqueReason = use.Reason
			}
		case UseNamed, UseMember:
			if use.Symbol == wanted {
				reaching = append(reaching, use.Module)
			}
		}
	}

	if len(reaching) > 0 {
		return Decision{Verdict: VerdictReachable, Modules: sortedUnique(reaching)}
	}
	if len(opaque) > 0 {
		reason := "the package is bound as a whole module and that binding escapes observation, so any export could be reached"
		if opaqueReason != "" {
			reason = "the package is bound as a whole module and " + opaqueReason + ", so any export could be reached"
		}
		return Decision{Verdict: VerdictUnknown, Modules: sortedUnique(opaque), Reason: reason}
	}
	return Decision{
		Verdict: VerdictNotReachable,
		Reason:  "every reference to the package names an export, and none of them is the affected symbol",
	}
}

// NormalizeAffectedSymbol maps an advisory's affected-symbol string onto the export name this analysis
// can reason about, for a package with the given npm name.
//
// Advisories write the same export in several shapes: a bare export (`template`), a
// package-qualified one (`lodash.template`), or a scoped package's (`@scope/pkg.method`). Anything
// else — a deep import path (`lodash/template`), a prototype or instance path (`Class.prototype.m`), an
// empty or wildcard entry — returns ok=false.
//
// A false return means the SUBJECT is unanswerable and the caller must drop it. That is deliberate: a
// symbol this function cannot place would otherwise be compared against export names it can never equal,
// and would come back not-reachable for every package — a systematic false negative.
func NormalizeAffectedSymbol(packageName, raw string) (string, bool) {
	symbol := strings.TrimSpace(raw)
	if symbol == "" {
		return "", false
	}
	// The package prefix is stripped BEFORE the shape check, because a scoped package's own name
	// contains the characters the check rejects (`@scope/pkg.method`). It is stripped only when the
	// prefix really is this package's name; stripping any dotted prefix would turn `foo.bar` into `bar`
	// for an unrelated package.
	if pkg := strings.TrimSpace(packageName); pkg != "" && strings.HasPrefix(symbol, pkg+".") {
		symbol = strings.TrimPrefix(symbol, pkg+".")
	}
	if symbol == "" || strings.Contains(symbol, ".") {
		// A remaining dot is a nested path (`Class.prototype.method`). Reaching the outer binding says
		// nothing about the nested one, so the subject is not answerable at this granularity.
		return "", false
	}
	if !isIdentifier(symbol) {
		return "", false
	}
	return symbol, true
}

// isIdentifier reports whether s is a plain JavaScript identifier-shaped name. It is deliberately
// stricter than the language: an exotic but legal identifier is refused (unanswerable) rather than
// admitted into a comparison whose outcome could suppress a finding.
func isIdentifier(s string) bool {
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_', r == '$':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return s != ""
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	deduped := out[:1]
	for _, value := range out[1:] {
		if value != deduped[len(deduped)-1] {
			deduped = append(deduped, value)
		}
	}
	return deduped
}
