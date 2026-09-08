package assessmentcycle

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	closuredom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentclosure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestClosureReferenceSetBindsEveryMemberAndEarliestExpiry(t *testing.T) {
	query := ports.AssessmentClosureReferenceQuery{CycleID: "cycle"}
	later, earlier := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC), time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	items := make([]closuredom.Reference, 100_000)
	for i := range items {
		items[i] = closuredom.Reference{Kind: closureReferenceSLADecision, ID: shared.ID(fmt.Sprintf("decision-%06d", i)), Version: 1, ContentHash: strings.Repeat("a", 64), ExpiresAt: &later}
	}
	items[12345].ExpiresAt = &earlier
	got, err := compactClosureReferences(query, items)
	if err != nil || len(got) != 1 || got[0].Kind != closureReferenceSLADecision+"_set" || !got[0].ExpiresAt.Equal(earlier) {
		t.Fatalf("set=%+v err=%v", got, err)
	}
	encoded, err := json.Marshal(got)
	if err != nil || len(encoded) > 1024 || !strings.Contains(string(got[0].Metadata), `"count":100000`) {
		t.Fatalf("bounded metadata bytes=%d err=%v", len(encoded), err)
	}
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
	reordered, err := compactClosureReferences(query, items)
	if err != nil || reordered[0].ContentHash != got[0].ContentHash {
		t.Fatalf("order changed set hash: %v", err)
	}
	items[54321].ContentHash = strings.Repeat("b", 64)
	changed, err := compactClosureReferences(query, items)
	if err != nil || changed[0].ContentHash == got[0].ContentHash {
		t.Fatalf("changed member did not change hash: %v", err)
	}
	removed, err := compactClosureReferences(query, items[1:])
	if err != nil || removed[0].ContentHash == changed[0].ContentHash {
		t.Fatalf("missing member did not change hash: %v", err)
	}
	policy := closuredom.Evaluate(closuredom.PolicyInput{References: got, AsOfAt: earlier})
	foundExpired := false
	for _, blocker := range policy.Blockers {
		if blocker.Code == "decision_expired" && !blocker.Overrideable {
			foundExpired = true
		}
	}
	if !foundExpired || policy.CommitAllowed {
		t.Fatal("expired set did not fail closed")
	}
}
