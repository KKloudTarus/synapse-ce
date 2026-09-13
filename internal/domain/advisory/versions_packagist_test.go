package advisory

import "testing"

func TestComparePackagist(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0.0", 0},               // trailing-zero core padding
		{"1.0.0", "1.1.0", -1},            // minor
		{"2.0.0", "1.9.9", 1},             // major dominates
		{"v1.2.3", "1.2.3", 0},            // leading v ignored
		{"1.0.0", "1.0.0.0", 0},           // 4-segment core
		{"1.0.0-alpha", "1.0.0", -1},      // pre-release < stable
		{"1.0.0-alpha", "1.0.0-beta", -1}, // Composer stability order (NOT SemVer alphabetical)
		{"1.0.0-beta", "1.0.0-rc", -1},
		{"1.0.0-rc", "1.0.0", -1},     // RC < stable
		{"1.0.0", "1.0.0-patch1", -1}, // stable < patch
		{"1.0.0-alpha1", "1.0.0-alpha2", -1},
		{"1.0.0-a", "1.0.0-alpha", 0},  // a == alpha alias
		{"1.0.0-b1", "1.0.0-beta1", 0}, // b == beta alias
		{"1.0.0RC1", "1.0.0-rc1", 0},   // separator-optional, RC==rc
		{"1.0.0-stable1", "1.0.0", 0},  // Composer ignores a `stable` suffix number -> equal to plain release
		{"1.0.0-stable", "1.0.0", 0},   // explicit -stable == no suffix
		{"1.2.3", "1.2.3", 0},
	}
	for _, c := range cases {
		if got := sign(comparePackagist(c.a, c.b)); got != c.want {
			t.Errorf("comparePackagist(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
		if got := sign(comparePackagist(c.b, c.a)); got != -c.want { // antisymmetry
			t.Errorf("comparePackagist(%q,%q)=%d want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

// Packagist stability ordering differs from SemVer §11: SemVer would place "rc" before "alpha"/"beta"
// (ASCII 'r' semantics), which is wrong for Composer. This locks the Composer order.
func TestPackagistStabilityBeatsSemver(t *testing.T) {
	if comparePackagist("1.0.0-rc1", "1.0.0-alpha1") <= 0 {
		t.Error("Composer RC must outrank alpha")
	}
	if comparePackagist("1.0.0-rc1", "1.0.0-beta1") <= 0 {
		t.Error("Composer RC must outrank beta")
	}
}

func TestValidPackagistFailsClosed(t *testing.T) {
	for _, bad := range []string{"dev-master", "1.x-dev", "master", "", "not-a-version", "1.0.0-unknownflag", "1.0.0.0.0"} {
		if validPackagist(bad) {
			t.Errorf("validPackagist(%q) must be false (fail closed)", bad)
		}
	}
	for _, good := range []string{"1.0.0", "v2.3.4", "1.0.0-RC1", "1.2", "1.0.0-alpha", "1.0.0-patch2"} {
		if !validPackagist(good) {
			t.Errorf("validPackagist(%q) must be true", good)
		}
	}
}

func TestPackagistTransitive(t *testing.T) {
	vs := []string{"1.0.0-dev", "1.0.0-alpha1", "1.0.0-alpha2", "1.0.0-beta", "1.0.0-rc1", "1.0.0", "1.0.0-patch1", "1.0.1", "1.1.0", "2.0.0"}
	for _, a := range vs {
		for _, b := range vs {
			for _, c := range vs {
				ab, bc, ac := sign(comparePackagist(a, b)), sign(comparePackagist(b, c)), sign(comparePackagist(a, c))
				if ab <= 0 && bc <= 0 && ac > 0 {
					t.Errorf("packagist intransitive: %q<=%q<=%q but %q>%q", a, b, c, a, c)
				}
				if ab >= 0 && bc >= 0 && ac < 0 {
					t.Errorf("packagist intransitive: %q>=%q>=%q but %q<%q", a, b, c, a, c)
				}
			}
		}
	}
}

// TestHexPubPackagistRangeAffected: the full Affected() path for the three ecosystems #1037 adds. Previously
// an ECOSYSTEM range was skipped (silent no-match); now it orders correctly.
func TestHexPubPackagistRangeAffected(t *testing.T) {
	rng := func(introduced, fixed string) []Range {
		return []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: introduced}, {Fixed: fixed}}}}
	}
	// Hex (SemVer)
	if !Affected("Hex", "1.5.0", rng("1.0.0", "2.0.0"), nil) {
		t.Error("Hex 1.5.0 must be affected by [1.0.0, 2.0.0)")
	}
	if Affected("Hex", "2.0.0", rng("1.0.0", "2.0.0"), nil) {
		t.Error("Hex 2.0.0 (the fixed version) must NOT be affected")
	}
	// Pub (SemVer)
	if !Affected("Pub", "0.13.5", rng("0.13.0", "0.14.0"), nil) {
		t.Error("Pub 0.13.5 must be affected by [0.13.0, 0.14.0)")
	}
	if Affected("Pub", "not-a-version", rng("0.13.0", "0.14.0"), nil) {
		t.Error("an unparseable Pub version must fail closed")
	}
	// Packagist (Composer stability)
	if !Affected("Packagist", "1.5.0", rng("1.0.0", "2.0.0"), nil) {
		t.Error("Packagist 1.5.0 must be affected by [1.0.0, 2.0.0)")
	}
	if !Affected("Packagist", "2.0.0-rc1", rng("1.0.0", "2.0.0"), nil) {
		t.Error("Packagist 2.0.0-rc1 (a pre-release below the stable fix) must be affected by [1.0.0, 2.0.0)")
	}
	if Affected("Packagist", "2.0.0", rng("1.0.0", "2.0.0"), nil) {
		t.Error("Packagist 2.0.0 (the fixed version) must NOT be affected")
	}
	if Affected("Packagist", "dev-master", rng("1.0.0", "2.0.0"), nil) {
		t.Error("a Composer branch alias (dev-master) must fail closed, not match")
	}
}
