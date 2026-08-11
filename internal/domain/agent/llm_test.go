package agent

import "testing"

func TestSameModelCanonicalizesAliases(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"gpt-4o", "GPT-4O", true},
		{"openai/gpt-4o", "gpt-4o", true},
		{"router/openai/gpt-4o", "OPENAI/GPT-4O", true},
		{"gpt-4o", "openai/gpt-4o-2024-08-06", true},
		{"anthropic.claude-opus-5", "anthropic/claude-opus-5", true},
		{"us.anthropic.claude-3-haiku-20240307-v1:0", "anthropic.claude-3-haiku-20240307-v1:0", true},
		{"us.anthropic.claude-3-haiku-20240307-v1:0", "anthropic/claude-3-haiku", true},
		{"global.anthropic.claude-sonnet-4-5-20250929-v1:0", "anthropic/claude-sonnet-4-5-20250929", true},
		{"arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-opus-5-v1:0", "claude-opus-5", true},
		{"gpt-4o", "gpt-4.1", false},
		{"anthropic.claude-opus-5-v1:0", "anthropic.claude-sonnet-4-v1:0", false},
		{"custom.model-a", "model-a", false},
		{"", "", false},
	} {
		if got := SameModel(tc.a, tc.b); got != tc.same {
			t.Errorf("SameModel(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.same)
		}
	}
}

// TestCanonicalModelIDScopeDriftFailsClosed pins the fail-closed direction for Bedrock geographic
// scopes. Enumerating region prefixes alone fails OPEN: an unlisted one (ca./jp./au./sa. -- AWS keeps
// adding inference profiles) left the same model looking like an independent verifier, which is exactly
// the separation-of-duties bypass this canonicalization exists to prevent.
func TestCanonicalModelIDScopeDriftFailsClosed(t *testing.T) {
	const base = "anthropic.claude-opus-5-v1:0"
	for _, scope := range []string{"us", "eu", "apac", "global", "ca", "jp", "au", "sa", "unknownregion"} {
		id := scope + "." + base
		if !SameModel(id, base) {
			t.Errorf("scope %q: SameModel=false, canonical=%q -- one model would verify its own proposal", scope, CanonicalModelID(id))
		}
	}
	// The check must still SEPARATE genuinely different families, or collapsing everything would make
	// every configuration look correlated and disable verification outright.
	for _, pair := range [][2]string{
		{"us.anthropic.claude-opus-5", "us.meta.llama3-70b"},
		{"anthropic.claude-opus-5", "amazon.nova-pro-v1:0"},
	} {
		if SameModel(pair[0], pair[1]) {
			t.Errorf("%q and %q must stay distinct", pair[0], pair[1])
		}
	}
}

func TestIndependentLLMsFailsClosed(t *testing.T) {
	tests := []struct {
		name                                    string
		proposerProvider, proposerModel         string
		verifierProvider, verifierModel, policy string
		want                                    bool
	}{
		{"family policy permits one provider with distinct families", "openai", "gpt-4o", "openai", "gpt-4.1", "model_family", true},
		{"provider policy requires both dimensions", "openai", "gpt-4o", "anthropic", "claude-sonnet-4", "provider", true},
		{"provider policy rejects same provider", "openai", "gpt-4o", "OPENAI", "gpt-4.1", "provider", false},
		{"provider policy still rejects aliased family", "bedrock", "us.anthropic.claude-opus-5-v1:0", "anthropic", "claude-opus-5", "provider", false},
		{"missing proposer provider", "", "gpt-4o", "anthropic", "claude-sonnet-4", "model_family", false},
		{"missing verifier provider", "openai", "gpt-4o", "", "claude-sonnet-4", "model_family", false},
		{"missing model", "openai", "", "anthropic", "claude-sonnet-4", "provider", false},
		{"unknown policy", "openai", "gpt-4o", "anthropic", "claude-sonnet-4", "typo", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IndependentLLMs(tc.proposerProvider, tc.proposerModel, tc.verifierProvider, tc.verifierModel, tc.policy); got != tc.want {
				t.Fatalf("IndependentLLMs() = %v, want %v", got, tc.want)
			}
		})
	}
}
