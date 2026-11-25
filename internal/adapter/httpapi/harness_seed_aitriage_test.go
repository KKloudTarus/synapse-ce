package httpapi

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aitriagereview"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/aitriagereviewuc"
)

// aitriageReview is the id of the one AI-triage review this seed plants for tenantA. Its title carries
// aitriageMarker, so a response built from it can only have come from tenantA's review.
const (
	aitriageReview = shared.ID("aitriage-review-A")
	aitriageMarker = "tenantA-aitriage-marker"
)

func init() {
	// The review queue has no read by id, so this seed declares no read route. It names the review
	// for the two write routes, which the write sweep sends as tenantB and then as tenantA.
	values := map[string]map[string]string{}
	for _, route := range []string{
		"POST /api/v1/ai-triage/reviews/{rid}/claim",
		"POST /api/v1/ai-triage/reviews/{rid}/decision",
	} {
		values[route] = map[string]string{"{rid}": aitriageReview.String()}
	}
	registerHarnessSeed(harnessSeed{
		Name:            "aitriage",
		RoutePathValues: values,
		Run:             seedAITriage,
	})
}

// seedAITriage replaces the fixture's review stand-in with the real review service over the in-memory
// store, and plants one pending tenantA review. The stand-in answers every caller with a review for
// whatever id it is asked about, so a claim or decision by tenantB succeeded against it; that says
// nothing about the route. The real service loads the review by the caller's tenant and id, and that
// lookup is the only thing standing between tenantB and the review: the routes have no guard of their
// own.
func seedAITriage(w *harnessWorld) []string {
	t := w.t
	t.Helper()
	now := time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)
	review, err := aitriagereview.NewPending(aitriagereview.Input{
		ID: aitriageReview, TenantID: "tenantA", EngagementID: "engA", FindingID: "f1", EvidenceRef: "aitriage-evidence-A",
		DedupKey: aitriageMarker, Title: "review " + aitriageMarker, Severity: shared.SeverityHigh,
		ProposerModel: "aitriage-proposer", PromptVersion: "aitriage-prompt-1", PolicyVersion: "fp-gate-v3",
		PolicyReason: "held for human review", ReviewRequired: true,
	}, now)
	if err != nil {
		t.Fatalf("build ai-triage review: %v", err)
	}
	store := memory.NewAITriageReviewStore()
	if err := store.UpsertPending(context.Background(), review); err != nil {
		t.Fatalf("seed ai-triage review: %v", err)
	}
	service, err := aitriagereviewuc.NewService(store, w.engagements, aitriageFindings{}, &fakeAudit{}, fixedClock{t: now}, engIDs{})
	if err != nil {
		t.Fatalf("ai-triage review service: %v", err)
	}
	w.rt.SetAITriageReviews(service)
	return []string{aitriageMarker}
}

// aitriageFindings accepts the finding update a decision makes. It makes no tenant decision: the
// service calls it only after it has loaded the review by the caller's tenant.
type aitriageFindings struct{}

func (aitriageFindings) ApplyAITriageReview(context.Context, string, shared.ID, shared.ID, bool, string) error {
	return nil
}
