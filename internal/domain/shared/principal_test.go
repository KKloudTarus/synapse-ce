package shared

import "testing"

func TestIsMachineActor(t *testing.T) {
	cases := map[string]bool{
		"": true, "  ": true, "agent:scan": true, "LLM:GPT": true, "mcp:tool": true,
		"system:worker": true, "machine:job": true, "bot:renovate": true, "service:sync": true,
		"alice": false, "alice@example.com": false, "reviewer:alice": false, "human:system:operator": false,
	}
	for actor, want := range cases {
		if got := IsMachineActor(actor); got != want {
			t.Errorf("IsMachineActor(%q)=%v, want %v", actor, got, want)
		}
	}
}
