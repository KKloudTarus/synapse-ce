package advisory

import "testing"

func TestGitHubActionsRangesOrderAsSemVer(t *testing.T) {
	ranges := []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "4.0.0"}, {Fixed: "4.1.3"}}}}
	for version, want := range map[string]bool{"4.1.2": true, "4.0.0": true, "4.1.3": false, "3.9.9": false} {
		if got := Affected("GitHub Actions", version, ranges, nil); got != want {
			t.Errorf("Affected(%q) = %v, want %v", version, got, want)
		}
	}
}
