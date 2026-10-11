package textsafety

import "testing"

func TestClassification(t *testing.T) {
	cases := []struct {
		r                        rune
		control, bidi, invisible bool
	}{
		{'a', false, false, false},
		{'\t', true, false, false},
		{0x1b, true, false, false},
		{0x7f, true, false, false},
		{0x85, true, false, false},
		{0x202e, false, true, false},
		{0x2066, false, true, false},
		{0x200f, false, true, false},
		{0x061c, false, true, false},
		{0x200b, false, false, true},
		{0xfeff, false, false, true},
		{0x200c, false, false, false}, // zero-width non-joiner is kept
		{0x200d, false, false, false}, // zero-width joiner is kept
		{0x1ec7, false, false, false}, // Vietnamese letter
	}
	for _, tc := range cases {
		if IsControl(tc.r) != tc.control || IsBidiControl(tc.r) != tc.bidi || IsInvisibleSeparator(tc.r) != tc.invisible {
			t.Errorf("U+%04X: control=%v bidi=%v invisible=%v, want %v %v %v", tc.r,
				IsControl(tc.r), IsBidiControl(tc.r), IsInvisibleSeparator(tc.r), tc.control, tc.bidi, tc.invisible)
		}
	}
}
