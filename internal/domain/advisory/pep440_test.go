package advisory

import "testing"

// TestComparePEP440Ordering walks a strictly-ascending PEP 440 chain (drawn from the spec's ordering
// examples) and asserts comparePEP440 agrees for every pair: dev < pre(a<b<rc) < final < post, with epoch
// dominating and dev/post nesting inside a release.
func TestComparePEP440Ordering(t *testing.T) {
	ascending := []string{
		"1.0.dev1",       // dev of the final 1.0 – sorts below any pre-release of 1.0
		"1.0a1.dev1",     // dev of alpha1 – below alpha1
		"1.0a1",          // alpha 1
		"1.0a2",          // alpha 2 > alpha 1
		"1.0b1",          // beta > alpha
		"1.0rc1",         // rc > beta
		"1.0",            // final > any pre-release
		"1.0.post1.dev1", // dev of post1 – below post1, above final
		"1.0.post1",      // post-release > final
		"1.1",            // higher release
		"2!1.0",          // epoch 2 dominates everything in epoch 0
	}
	for i := range ascending {
		for j := range ascending {
			got := comparePEP440(ascending[i], ascending[j])
			if want := cmpInt(i, j); got != want {
				t.Errorf("comparePEP440(%q, %q) = %d, want %d", ascending[i], ascending[j], got, want)
			}
		}
	}
}

// TestComparePEP440Equalities pins the normalizations: trailing-zero release, pre-release spellings, implicit
// post, default pre/post numbers, leading v, and ignored local versions all compare equal.
func TestComparePEP440Equalities(t *testing.T) {
	eq := [][2]string{
		{"1.0", "1.0.0"},          // trailing-zero release
		{"1.0a1", "1.0alpha1"},    // alpha == a
		{"1.0rc1", "1.0c1"},       // c == rc
		{"v1.2.3", "1.2.3"},       // leading v tolerated
		{"1.0.post1", "1.0-1"},    // implicit post-release
		{"1.0b", "1.0b0"},         // default pre number 0
		{"1.0.post", "1.0.post0"}, // default post number 0
		{"1.0", "1.0+ubuntu.1"},   // local version ignored for precedence
	}
	for _, p := range eq {
		if got := comparePEP440(p[0], p[1]); got != 0 {
			t.Errorf("comparePEP440(%q, %q) = %d, want 0 (equal)", p[0], p[1], got)
		}
	}
}

func TestValidPEP440(t *testing.T) {
	valid := []string{"1", "1.0", "1.0.0.0", "1!2.3", "1.0a1", "1.0.post1", "1.0.dev0", "v1.2.3", "2024.1.1", "1.0rc2"}
	for _, v := range valid {
		if !validPEP440(v) {
			t.Errorf("validPEP440(%q) = false, want true", v)
		}
	}
	invalid := []string{"", "latest", "1.2.x", "abc", "~1.0", "1.0 1.0", "1.0.0betax"}
	for _, v := range invalid {
		if validPEP440(v) {
			t.Errorf("validPEP440(%q) = true, want false (fail-closed)", v)
		}
	}
}
