package agent

import "testing"

func TestSameModelNormalizesCaseAndProviderPrefix(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"gpt-4o", "GPT-4O", true},
		{"openai/gpt-4o", "gpt-4o", true},
		{"router/openai/gpt-4o", "OPENAI/GPT-4O", true},
		{"gpt-4o", "openai/gpt-4o-2024-08-06", true},
		{"gpt-4o", "gpt-4.1", false},
		{"", "", false},
	} {
		if got := SameModel(tc.a, tc.b); got != tc.same {
			t.Errorf("SameModel(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.same)
		}
	}
}
