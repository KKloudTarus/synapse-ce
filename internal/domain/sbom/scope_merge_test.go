package sbom

import "testing"

// TestMergeScopeEveryPair checks the merge rule on every pair of scopes, in both orders. The class column is
// the rule written out by hand: production beats every other scope, a scope the gate does not exempt beats a
// background scope, a background scope beats an empty or unknown one, and a tie keeps the earlier copy.
func TestMergeScopeEveryPair(t *testing.T) {
	const (
		none = iota
		background
		gating
		production
	)
	class := map[string]int{
		"":                 none,
		ScopeUnknown:       none,
		ScopeTest:          background,
		ScopeExample:       background,
		ScopeFixture:       background,
		ScopeBenchmark:     background,
		ScopeDocumentation: background,
		ScopeVendored:      background,
		ScopeDevelopment:   gating,
		"provided":         gating, // a value no producer here emits: the gate does not exempt it, so it must not lose to a background scope
		ScopeProduction:    production,
	}
	for earlier, ce := range class {
		for later, cl := range class {
			want := earlier
			if cl > ce {
				want = later
			}
			if got := MergeScope(earlier, later); got != want {
				t.Errorf("MergeScope(%q, %q) = %q, want %q", earlier, later, got, want)
			}
		}
	}
}

// The cases issue #1692 is about, spelled out: the order two manifests were read in must not decide whether a
// component ships, and a background scope survives only when every copy is background.
func TestMergeScopeIsOrderIndependentAcrossShippingAndBackground(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		{ScopeTest, ScopeProduction, ScopeProduction},
		{ScopeTest, ScopeDevelopment, ScopeDevelopment},
		{ScopeDevelopment, ScopeProduction, ScopeProduction},
		{ScopeExample, ScopeDevelopment, ScopeDevelopment},
		{ScopeUnknown, ScopeTest, ScopeTest},
		{"", ScopeTest, ScopeTest},
	} {
		if got := MergeScope(tc.a, tc.b); got != tc.want {
			t.Errorf("MergeScope(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
		if got := MergeScope(tc.b, tc.a); got != tc.want {
			t.Errorf("MergeScope(%q, %q) = %q, want %q", tc.b, tc.a, got, tc.want)
		}
	}
	if got := MergeScope(ScopeTest, ScopeExample); got != ScopeTest {
		t.Errorf("two background copies keep the earlier scope, got %q", got)
	}
}
