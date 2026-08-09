package jssymbols

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const purl = "pkg:npm/lodash@4.17.15"

func named(module, symbol string) Use {
	return Use{Module: module, PURL: purl, Symbol: symbol, Kind: UseNamed}
}

func member(module, symbol string) Use {
	return Use{Module: module, PURL: purl, Symbol: symbol, Kind: UseMember}
}

func opaque(module, reason string) Use {
	return Use{Module: module, PURL: purl, Kind: UseOpaque, Reason: reason}
}

func TestDecide(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		symbol  string
		uses    []Use
		want    Verdict
		modules []string
	}{
		{
			name:    "a named import of the affected symbol is reachable",
			symbol:  "template",
			uses:    []Use{named("src/a.ts", "template")},
			want:    VerdictReachable,
			modules: []string{"src/a.ts"},
		},
		{
			name:    "a member read of the affected symbol is reachable",
			symbol:  "template",
			uses:    []Use{member("src/b.ts", "template")},
			want:    VerdictReachable,
			modules: []string{"src/b.ts"},
		},
		{
			name:   "named imports of other symbols only are not reachable",
			symbol: "template",
			uses:   []Use{named("src/a.ts", "merge"), member("src/b.ts", "cloneDeep")},
			want:   VerdictNotReachable,
		},
		{
			// The safety rule that matters most: an opaque reference could reach the affected symbol, so
			// the absence of a matching named use proves nothing.
			name:    "an opaque reference makes a non-match unknown, never negative",
			symbol:  "template",
			uses:    []Use{named("src/a.ts", "merge"), opaque("src/c.ts", "the namespace is passed as an argument")},
			want:    VerdictUnknown,
			modules: []string{"src/c.ts"},
		},
		{
			// A positive is always safe, so it wins even when something else is unobservable.
			name:    "a positive wins over an opaque reference",
			symbol:  "template",
			uses:    []Use{opaque("src/c.ts", "spread"), named("src/a.ts", "template")},
			want:    VerdictReachable,
			modules: []string{"src/a.ts"},
		},
		{
			name:   "no observed use is a tier-1 question, answered unknown here",
			symbol: "template",
			uses:   nil,
			want:   VerdictUnknown,
		},
		{
			name:   "a blank symbol is unknown, not a negative",
			symbol: "  ",
			uses:   []Use{named("src/a.ts", "merge")},
			want:   VerdictUnknown,
		},
		{
			name:    "reaching modules are deduplicated and sorted",
			symbol:  "template",
			uses:    []Use{named("src/z.ts", "template"), named("src/a.ts", "template"), named("src/z.ts", "template")},
			want:    VerdictReachable,
			modules: []string{"src/a.ts", "src/z.ts"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := Decide(test.symbol, test.uses)
			if got.Verdict != test.want {
				t.Fatalf("Decide(%q) = %q (%s), want %q", test.symbol, got.Verdict, got.Reason, test.want)
			}
			if len(test.modules) > 0 {
				if len(got.Modules) != len(test.modules) {
					t.Fatalf("modules = %v, want %v", got.Modules, test.modules)
				}
				for i := range test.modules {
					if got.Modules[i] != test.modules[i] {
						t.Fatalf("modules = %v, want %v", got.Modules, test.modules)
					}
				}
			}
			if got.Verdict != VerdictReachable && got.Reason == "" {
				t.Fatal("a non-positive verdict must explain itself: an unexplained unknown is indistinguishable from a bug")
			}
		})
	}
}

// The symbol comparison must be exact. A case-insensitive or prefix match would let `Template` satisfy a
// query for `template`, or worse, let `templateSettings` mask it.
func TestSymbolMatchingIsExact(t *testing.T) {
	t.Parallel()

	for _, bound := range []string{"Template", "templateSettings", "tem", "template2"} {
		if got := Decide("template", []Use{named("src/a.ts", bound)}); got.Verdict != VerdictNotReachable {
			t.Fatalf("binding %q must not satisfy a query for template, got %q", bound, got.Verdict)
		}
	}
}

func TestNormalizeAffectedSymbol(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pkg, raw string
		want     string
		ok       bool
	}{
		{"lodash", "template", "template", true},
		{"lodash", "lodash.template", "template", true},
		{"@scope/pkg", "@scope/pkg.method", "method", true},
		{"lodash", "  template  ", "template", true},
		{"lodash", "$", "$", true},
		{"lodash", "_private", "_private", true},
		// A deep import path is a different module, not an export of this one.
		{"lodash", "lodash/template", "", false},
		// A nested path: reaching the outer binding says nothing about the nested member.
		{"lodash", "Class.prototype.method", "", false},
		{"lodash", "a.b", "", false},
		// A prefix that is NOT this package's name must not be stripped, or foo.bar would become bar for
		// an unrelated package.
		{"lodash", "other.template", "", false},
		{"lodash", "", "", false},
		{"lodash", "*", "", false},
		{"lodash", "fn()", "", false},
		{"lodash", "1abc", "", false},
		{"lodash", "with space", "", false},
	}

	for _, test := range tests {
		got, ok := NormalizeAffectedSymbol(test.pkg, test.raw)
		if ok != test.ok || got != test.want {
			t.Fatalf("NormalizeAffectedSymbol(%q, %q) = (%q, %v), want (%q, %v)", test.pkg, test.raw, got, ok, test.want, test.ok)
		}
	}
}

func TestUseValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		use  Use
		ok   bool
	}{
		{"named use", named("src/a.ts", "template"), true},
		{"opaque use", opaque("src/a.ts", "spread"), true},
		{"no module", Use{PURL: purl, Symbol: "x", Kind: UseNamed}, false},
		{"no package", Use{Module: "src/a.ts", Symbol: "x", Kind: UseNamed}, false},
		{"unknown kind", Use{Module: "src/a.ts", PURL: purl, Symbol: "x", Kind: "guess"}, false},
		// An opaque use that names a symbol is a contradiction: its symbol is exactly what is unknown.
		{"opaque with a symbol", Use{Module: "src/a.ts", PURL: purl, Symbol: "x", Kind: UseOpaque}, false},
		{"named without a symbol", Use{Module: "src/a.ts", PURL: purl, Kind: UseNamed}, false},
	}

	for _, test := range tests {
		err := test.use.Validate()
		if test.ok && err != nil {
			t.Fatalf("%s: unexpected error %v", test.name, err)
		}
		if !test.ok {
			if err == nil {
				t.Fatalf("%s: expected a validation error", test.name)
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("%s: error %v must wrap ErrValidation", test.name, err)
			}
		}
	}
}

// TestDecideTreatsAnUninterpretableUseAsOpaque locks that Decide is TOTAL. A use it cannot interpret must
// contribute opacity, not silence: silence is what turns an unknown into a negative, and a negative is
// what suppresses a finding.
func TestDecideTreatsAnUninterpretableUseAsOpaque(t *testing.T) {
	t.Parallel()

	invalid := []Use{
		{Module: "src/a.ts", PURL: purl, Kind: "a-kind-added-later"},
		{Module: "src/a.ts", PURL: purl, Kind: UseMember},                     // member use naming no symbol
		{Module: "src/a.ts", PURL: purl, Kind: UseOpaque, Symbol: "template"}, // opaque naming a symbol
	}
	for _, use := range invalid {
		got := Decide("template", append([]Use{named("src/b.ts", "merge")}, use))
		if got.Verdict != VerdictUnknown {
			t.Fatalf("use %+v must make the answer unknown, got %q", use, got.Verdict)
		}
	}
}

func TestSubjectRoundTrip(t *testing.T) {
	t.Parallel()

	subject, ok := Subject("pkg:npm/lodash@4.17.15", "template")
	if !ok {
		t.Fatal("a valid component and export must be mintable")
	}
	gotPURL, gotSymbol, ok := ParseSubject(subject)
	if !ok || gotPURL != "pkg:npm/lodash@4.17.15" || gotSymbol != "template" {
		t.Fatalf("round trip gave (%q, %q, %v)", gotPURL, gotSymbol, ok)
	}
	// The writer refuses exactly what the reader refuses.
	for _, bad := range []struct{ purl, symbol string }{
		{"pkg:pypi/flask@1.0", "run"}, {"not-a-purl", "x"}, {"pkg:npm/lodash@1.0.0", "a.b"},
		{"pkg:npm/lodash@1.0.0", ""}, {"pkg:npm/lodash@1.0.0", "with space"},
	} {
		if _, ok := Subject(bad.purl, bad.symbol); ok {
			t.Fatalf("Subject(%q, %q) must be refused", bad.purl, bad.symbol)
		}
	}
	for _, malformed := range []string{"pkg:npm/lodash@1.0.0", "#x", "pkg:npm/lodash@1.0.0#", "pkg:npm/lodash@1.0.0#a.b"} {
		if _, _, ok := ParseSubject(malformed); ok {
			t.Fatalf("%q must not parse as a subject", malformed)
		}
	}
}
