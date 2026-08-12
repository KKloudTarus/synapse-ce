package sca

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aitriagereview"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestAIEvaluationFeedbackRejectsBareModelIdentitiesAsApprovers(t *testing.T) {
	review := feedbackReview(aitriagereview.StateAccepted)
	base := feedbackManifest(feedbackCase(review, AIEvaluationFalsePositive))
	approveFeedbackCase(t, review, &base, 0)

	for _, actor := range []string{"model-a", "MODEL-B"} {
		t.Run("privacy_"+actor, func(t *testing.T) {
			manifest := base
			manifest.Cases = append([]AIEvaluationFeedbackCase(nil), base.Cases...)
			manifest.Cases[0].PrivacyReview.Reviewer = actor
			if _, err := CurateAIEvaluationFeedback([]aitriagereview.Review{review}, manifest); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("model privacy reviewer %q must fail validation, got %v", actor, err)
			}
		})
		t.Run("label_"+actor, func(t *testing.T) {
			manifest := base
			manifest.Cases = append([]AIEvaluationFeedbackCase(nil), base.Cases...)
			manifest.Cases[0].LabelQualityReview.Reviewer = actor
			if _, err := CurateAIEvaluationFeedback([]aitriagereview.Review{review}, manifest); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("model label-quality reviewer %q must fail validation, got %v", actor, err)
			}
		})
	}
}
