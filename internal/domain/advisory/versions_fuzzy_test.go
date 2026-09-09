package advisory

import "testing"

func TestOrderableFuzzy(t *testing.T) {
	orderable := []string{"9.0.62.1", "1.2.3.RELEASE", "3.0.0-M4", "2021.01.05", "v1.2.3", "0", "8.5.0-rc1"}
	for _, v := range orderable {
		if !OrderableFuzzy(v) {
			t.Errorf("OrderableFuzzy(%q) = false, want true", v)
		}
	}
	notOrderable := []string{"", "  ", "*", "-", "latest", "main", "RELEASE", "unknown", "vNext", "1.*", "1.x", "1.X", "1-unknown", "1.2+build", "2.0.0-latest"}
	for _, v := range notOrderable {
		if OrderableFuzzy(v) {
			t.Errorf("OrderableFuzzy(%q) = true, want false (no leading numeric)", v)
		}
	}
}

func TestCompareFuzzy(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// 4-part NVD releases: a missing trailing segment is 0, so the 4-part is greater.
		{"9.0.62", "9.0.62.1", -1},
		{"9.0.62.1", "9.0.62", 1},
		{"9.0.62.1", "9.0.62.1", 0},
		// Numeric, not lexical: 10 > 9, 62 > 7.
		{"1.2.10", "1.2.9", 1},
		{"9.0.62", "9.0.7", 1},
		// Pre-release markers sort BELOW the bare release of the same core.
		{"3.0.0-M4", "3.0.0", -1},
		{"3.0.0", "3.0.0-M4", 1},
		{"8.5.0-rc1", "8.5.0", -1},
		{"8.5.0-beta", "8.5.0-rc1", -1}, // beta < rc (alphabetic, both pre-release)
		// Numeric qualifier suffixes compare NUMERICALLY, not lexically (rc10 > rc2).
		{"3.0.0-M4", "3.0.0-M5", -1},
		{"8.5.0-rc10", "8.5.0-rc2", 1},
		{"8.5.0-rc2", "8.5.0-rc1", 1},
		// Release-equivalent markers equal the bare release (no false "below-range" ordering).
		{"1.2.3.RELEASE", "1.2.3", 0},
		{"1.2.3.GA", "1.2.3", 0},
		{"1.2.3-final", "1.2.3", 0},
		// Post-release markers sort ABOVE the bare release (a service pack is not "before" the release).
		{"1.2.3-sp1", "1.2.3", 1},
		{"1.2.3-patch2", "1.2.3", 1},
		// Date-like versions with leading zeros parse numerically.
		{"2021.01.05", "2021.1.4", 1},
		{"2020.12.31", "2021.01.01", -1},
		// A leading v/V is stripped.
		{"v1.2.3", "1.2.3", 0},
		{"V2.0.0", "2.0.0", 0},
		{"1.2.4", "1.2.3.RELEASE", 1},
		// Segment beyond int64 falls back to length-then-lexical, never panics.
		{"99999999999999999999.0", "1.0", 1},
		{"1.0", "99999999999999999999.0", -1},
	}
	for _, c := range cases {
		if got := CompareFuzzy(c.a, c.b); got != c.want {
			t.Errorf("CompareFuzzy(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
		// Antisymmetry: reversing the operands negates the result.
		if got := CompareFuzzy(c.b, c.a); got != -c.want {
			t.Errorf("CompareFuzzy(%q,%q) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}
