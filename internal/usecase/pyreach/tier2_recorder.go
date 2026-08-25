package pyreach

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachproof"
)

type pythonReachabilitySubject = ports.ReachabilitySubject

type tier2RecorderPort interface {
	Propose(ctx context.Context, proposer string, engagementID shared.ID, capability judgment.Capability, subjectKind judgment.SubjectKind, subjectID shared.ID, claim judgment.Claim) (judgment.Judgment, error)
	Verify(ctx context.Context, verifier string, engagementID, judgmentID shared.ID, score int, rationale string, expectedVersion int) (judgment.Judgment, error)
	List(ctx context.Context, engagementID shared.ID) ([]judgment.Judgment, error)
}

// Tier2Recorder filters unanswerable negatives before using the shared append-only judgment coordinator.
type Tier2Recorder struct {
	provider  semanticFactsProvider
	judgments tier2RecorderPort
	audit     ports.AuditLogger
	clock     ports.Clock
}

func NewTier2Recorder(provider semanticFactsProvider, judgments tier2RecorderPort, audit ports.AuditLogger, clock ports.Clock) (*Tier2Recorder, error) {
	if provider == nil || judgments == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: python tier-2 recorder is missing a dependency", shared.ErrValidation)
	}
	return &Tier2Recorder{provider: provider, judgments: judgments, audit: audit, clock: clock}, nil
}

func (r *Tier2Recorder) Record(ctx context.Context, engagementID shared.ID, targetRef string, subjects []ports.ReachabilitySubject) (int, error) {
	analyzer, err := NewTier2Analyzer(r.provider)
	if err != nil {
		return 0, err
	}
	answerable, err := analyzer.answerableSubjects(ctx, targetRef, subjects)
	if err != nil {
		return 0, err
	}
	if len(answerable) == 0 {
		return 0, nil
	}
	coordinator, err := reachproof.NewCoordinatorForLanguage(analyzer, r.judgments, r.audit, r.clock, judgment.Tier2, reachproof.LanguagePython)
	if err != nil {
		return 0, err
	}
	return coordinator.Record(ctx, engagementID, targetRef, answerable)
}

var _ ports.ReachabilityRecorder = (*Tier2Recorder)(nil)
