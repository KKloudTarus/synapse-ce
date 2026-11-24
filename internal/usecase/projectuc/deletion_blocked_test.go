package projectuc

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type blockedEngagements struct {
	ports.EngagementRepository
	eng *engagement.Engagement
	err error
}

func (s blockedEngagements) GetByProjectID(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error) {
	return s.eng, s.err
}

type blockedEvidence struct {
	ports.EvidenceStore
	head string
	err  error
}

func (s blockedEvidence) Head(context.Context, shared.ID) (string, error) { return s.head, s.err }

// Delete refuses a project whose analyses sealed evidence, because the custody chain is
// append-only. Before this signal the console offered the action anyway and the operator met a 409
// after clicking. The reason is now answerable before the click, by asking exactly what the
// refusal asks: the analysis-context engagement, and whether its chain has a head.
func TestDeletionBlockedReason(t *testing.T) {
	eng := &engagement.Engagement{ID: "eng-1", TenantID: "t1"}
	for name, tc := range map[string]struct {
		engagements ports.EngagementRepository
		evidence    ports.EvidenceStore
		wantBlocked bool
	}{
		"sealed evidence blocks":    {blockedEngagements{eng: eng}, blockedEvidence{head: "abc123"}, true},
		"empty chain does not":      {blockedEngagements{eng: eng}, blockedEvidence{head: ""}, false},
		"no analysis context":       {blockedEngagements{err: shared.ErrNotFound}, blockedEvidence{head: "abc123"}, false},
		"evidence read fails":       {blockedEngagements{eng: eng}, blockedEvidence{err: errors.New("db down")}, false},
		"engagement read fails":     {blockedEngagements{err: errors.New("db down")}, blockedEvidence{head: "abc123"}, false},
		"no evidence store wired":   {blockedEngagements{eng: eng}, nil, false},
		"no engagement store wired": {nil, blockedEvidence{head: "abc123"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			s := &Service{engagements: tc.engagements, evidence: tc.evidence}
			got := s.DeletionBlockedReason(context.Background(), "t1", "p1")
			if (got != "") != tc.wantBlocked {
				t.Fatalf("reason = %q, blocked=%v want blocked=%v", got, got != "", tc.wantBlocked)
			}
			if tc.wantBlocked && got == "" {
				t.Error("a blocked project must carry a reason an operator can read")
			}
		})
	}
}

// A read failure must not claim the project is permanent. The overview is advisory; the delete path
// is what actually refuses, and it refuses correctly whatever this says.
func TestDeletionBlockedReasonFailsOpenOnAReadError(t *testing.T) {
	s := &Service{
		engagements: blockedEngagements{eng: &engagement.Engagement{ID: "eng-1"}},
		evidence:    blockedEvidence{err: errors.New("transient")},
	}
	if got := s.DeletionBlockedReason(context.Background(), "t1", "p1"); got != "" {
		t.Fatalf("a transient read error must not report the project as undeletable, got %q", got)
	}
}
