package finding

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestEmptyDetectionStateOmittedFromJSON: a one-shot scan (e.g. the CLI) leaves DetectionState empty; it
// must be omitted from JSON so consumers don't build logic on a constant blank field. A populated value
// (the continuous-intelligence projection) still serializes.
func TestEmptyDetectionStateOmittedFromJSON(t *testing.T) {
	if b, _ := json.Marshal(Finding{Title: "x"}); strings.Contains(string(b), "DetectionState") {
		t.Fatalf("empty DetectionState must be omitted: %s", b)
	}
	if b, _ := json.Marshal(Finding{Title: "x", DetectionState: "detected"}); !strings.Contains(string(b), "DetectionState") {
		t.Fatalf("populated DetectionState must be present: %s", b)
	}
}
