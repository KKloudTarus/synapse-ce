package hotspot

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestStatus_Reviewed(t *testing.T) {
	tests := []struct {
		status Status
		want   bool
	}{
		{StatusToReview, false},
		{StatusAcknowledged, true},
		{StatusFixed, true},
		{StatusSafe, true},
		{Status("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.Reviewed(); got != tt.want {
				t.Errorf("Reviewed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStatus_CanTransitionTo(t *testing.T) {
	validTransitions := map[Status][]Status{
		StatusToReview:     {StatusAcknowledged, StatusFixed, StatusSafe},
		StatusAcknowledged: {StatusFixed, StatusSafe, StatusToReview},
		StatusFixed:        {StatusToReview},
		StatusSafe:         {StatusToReview},
	}

	allStatuses := []Status{StatusToReview, StatusAcknowledged, StatusFixed, StatusSafe, Status("invalid")}

	for _, from := range allStatuses {
		validTo := validTransitions[from]
		validMap := make(map[Status]bool)
		for _, v := range validTo {
			validMap[v] = true
		}

		for _, to := range allStatuses {
			t.Run(string(from)+"->"+string(to), func(t *testing.T) {
				want := validMap[to]
				if got := from.CanTransitionTo(to); got != want {
					t.Errorf("CanTransitionTo() = %v, want %v", got, want)
				}
			})
		}
	}
}

func TestHotspot_Transition(t *testing.T) {
	baseHotspot := Hotspot{
		ID:        shared.ID("hs1"),
		TenantID:  shared.ID("t1"),
		ProjectID: shared.ID("p1"),
		Status:    StatusToReview,
		Version:   1,
	}

	eventID := shared.ID("evt1")
	now := time.Now()

	tests := []struct {
		name            string
		to              Status
		actor           string
		rationale       string
		expectedVersion int
		wantErr         error
	}{
		{
			name:            "valid transition",
			to:              StatusAcknowledged,
			actor:           "user1",
			rationale:       "Valid rationale here.",
			expectedVersion: 1,
			wantErr:         nil,
		},
		{
			name:            "version mismatch",
			to:              StatusAcknowledged,
			actor:           "user1",
			rationale:       "Valid rationale here.",
			expectedVersion: 2,
			wantErr:         shared.ErrConflict,
		},
		{
			name:            "invalid transition",
			to:              StatusToReview,
			actor:           "user1",
			rationale:       "Valid rationale here.",
			expectedVersion: 1,
			wantErr:         ErrInvalidTransition,
		},
		{
			name:            "empty actor",
			to:              StatusAcknowledged,
			actor:           "   ",
			rationale:       "Valid rationale here.",
			expectedVersion: 1,
			wantErr:         shared.ErrValidation,
		},
		{
			name:            "rationale too short",
			to:              StatusAcknowledged,
			actor:           "user1",
			rationale:       "no",
			expectedVersion: 1,
			wantErr:         shared.ErrValidation,
		},
		{
			name:            "rationale too long",
			to:              StatusAcknowledged,
			actor:           "user1",
			rationale:       strings.Repeat("a", 4001),
			expectedVersion: 1,
			wantErr:         shared.ErrValidation,
		},
		{
			name:            "rationale with invalid control char",
			to:              StatusAcknowledged,
			actor:           "user1",
			rationale:       "Valid rationale\x00here.",
			expectedVersion: 1,
			wantErr:         shared.ErrValidation,
		},
		{
			name:            "rationale with newline and tab is valid",
			to:              StatusAcknowledged,
			actor:           "user1",
			rationale:       "Valid\nrationale\there.",
			expectedVersion: 1,
			wantErr:         nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updated, event, err := baseHotspot.Transition(tt.to, tt.actor, tt.rationale, tt.expectedVersion, eventID, now)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Transition() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Transition() unexpected error: %v", err)
			}

			if updated.Status != tt.to {
				t.Errorf("updated status = %v, want %v", updated.Status, tt.to)
			}
			if updated.Version != baseHotspot.Version+1 {
				t.Errorf("updated version = %d, want %d", updated.Version, baseHotspot.Version+1)
			}
			if updated.LastReviewedBy != strings.TrimSpace(tt.actor) {
				t.Errorf("updated LastReviewedBy = %v, want %v", updated.LastReviewedBy, strings.TrimSpace(tt.actor))
			}
			if updated.LastReviewedAt == nil || !updated.LastReviewedAt.Equal(now) {
				t.Errorf("updated LastReviewedAt = %v, want %v", updated.LastReviewedAt, now)
			}

			if event.ID != eventID {
				t.Errorf("event.ID = %v, want %v", event.ID, eventID)
			}
			if event.Version != updated.Version {
				t.Errorf("event.Version = %v, want %v", event.Version, updated.Version)
			}
			if event.Rationale != strings.TrimSpace(tt.rationale) {
				t.Errorf("event.Rationale = %v, want %v", event.Rationale, strings.TrimSpace(tt.rationale))
			}
		})
	}
}
