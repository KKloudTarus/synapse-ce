package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// JudgmentStore is the in-memory judgment repository (dev/tests). It mirrors the Postgres adapter
// to come: SetScoreState is the ONLY score/state mover and is guarded by optimistic concurrency
// (expectedVersion → shared.ErrConflict on mismatch), the same discipline as the finding repo's
// SetEvidenceScore. The score mover is deliberately not exposed on a broad read port.
type JudgmentStore struct {
	mu           sync.Mutex
	byEng        map[shared.ID][]judgment.Judgment
	pendingAudit map[judgmentAuditKey]ports.PendingJudgmentAudit
}

type judgmentAuditKey struct {
	kind       ports.JudgmentAuditKind
	judgmentID shared.ID
	version    int
}

// NewJudgmentStore returns an empty in-memory judgment store.
func NewJudgmentStore() *JudgmentStore {
	return &JudgmentStore{byEng: map[shared.ID][]judgment.Judgment{}, pendingAudit: map[judgmentAuditKey]ports.PendingJudgmentAudit{}}
}

var (
	_ ports.JudgmentStore      = (*JudgmentStore)(nil)
	_ ports.JudgmentAuditStore = (*JudgmentStore)(nil)
)

// Save inserts or replaces a judgment within its engagement (idempotent by id).
func (s *JudgmentStore) Save(_ context.Context, j judgment.Judgment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.byEng[j.EngagementID]
	for i := range list {
		if list[i].ID == j.ID {
			return nil // insert-only: mirror postgres ON CONFLICT (id) DO NOTHING – never clobber an existing judgment's score/state
		}
	}
	s.byEng[j.EngagementID] = append(list, j)
	return nil
}

// ListByEngagement returns a copy of the engagement's judgments.
func (s *JudgmentStore) ListByEngagement(_ context.Context, engagementID shared.ID) ([]judgment.Judgment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.byEng[engagementID]
	out := make([]judgment.Judgment, len(src))
	copy(out, src)
	return out, nil
}

// ListBySubject returns the engagement's judgments about a given subject id.
func (s *JudgmentStore) ListBySubject(_ context.Context, engagementID, subjectID shared.ID) ([]judgment.Judgment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []judgment.Judgment
	for _, j := range s.byEng[engagementID] {
		if j.SubjectID == subjectID {
			out = append(out, j)
		}
	}
	return out, nil
}

// SetScoreState moves a judgment's score + state under optimistic concurrency. A version mismatch
// returns shared.ErrConflict (lost-update guard); an unknown id returns shared.ErrNotFound.
func (s *JudgmentStore) SetScoreState(_ context.Context, engagementID, id shared.ID, score int, state judgment.State, expectedVersion int) (judgment.Judgment, error) {
	return s.setScoreState(engagementID, id, score, state, "", "", false, expectedVersion)
}

// SetVerdictState persists a verdict's sealed verifier and rationale with its score transition.
func (s *JudgmentStore) SetVerdictState(_ context.Context, engagementID, id shared.ID, score int, state judgment.State, verifiedBy, verdictRationale string, expectedVersion int) (judgment.Judgment, error) {
	return s.setScoreState(engagementID, id, score, state, verifiedBy, verdictRationale, true, expectedVersion)
}

func (s *JudgmentStore) setScoreState(engagementID, id shared.ID, score int, state judgment.State, verifiedBy, verdictRationale string, setVerdictProvenance bool, expectedVersion int) (judgment.Judgment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.byEng[engagementID]
	for i := range list {
		if list[i].ID == id {
			if list[i].Version != expectedVersion {
				return judgment.Judgment{}, fmt.Errorf("%w: judgment %s version %d != expected %d", shared.ErrConflict, id, list[i].Version, expectedVersion)
			}
			list[i].EvidenceScore = score
			list[i].State = state
			if setVerdictProvenance {
				list[i].VerifiedBy = verifiedBy
				list[i].VerdictRationale = verdictRationale
			}
			list[i].Version++
			s.byEng[engagementID] = list
			return list[i], nil
		}
	}
	return judgment.Judgment{}, fmt.Errorf("judgment %s: %w", id, shared.ErrNotFound)
}

// SaveWithProposalAudit inserts a proposal and its immutable pending audit payload
// under one lock. Exact replays do not duplicate either record.
func (s *JudgmentStore) SaveWithProposalAudit(ctx context.Context, j judgment.Judgment, entry ports.AuditEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.byEng[j.EngagementID]
	for _, existing := range list {
		if existing.ID == j.ID {
			return nil
		}
	}
	s.byEng[j.EngagementID] = append(list, j)
	key := judgmentAuditKey{kind: ports.JudgmentProposalAudit, judgmentID: j.ID, version: j.Version}
	s.pendingAudit[key] = ports.PendingJudgmentAudit{Kind: ports.JudgmentProposalAudit, JudgmentID: j.ID, Version: j.Version, EngagementID: j.EngagementID, Entry: entry}
	return nil
}

// SetVerdictStateWithAudit persists a sealed verdict and its immutable pending audit
// payload together, so a crash can only leave a recoverable pending delivery.
func (s *JudgmentStore) SetVerdictStateWithAudit(ctx context.Context, engagementID, id shared.ID, score int, state judgment.State, verifiedBy, rationale string, expectedVersion int, entry ports.AuditEntry) (judgment.Judgment, error) {
	if err := ctx.Err(); err != nil {
		return judgment.Judgment{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.byEng[engagementID]
	for i := range list {
		if list[i].ID != id {
			continue
		}
		if list[i].Version != expectedVersion {
			return judgment.Judgment{}, fmt.Errorf("%w: judgment %s version %d != expected %d", shared.ErrConflict, id, list[i].Version, expectedVersion)
		}
		list[i].EvidenceScore, list[i].State = score, state
		list[i].VerifiedBy, list[i].VerdictRationale = verifiedBy, rationale
		list[i].Version++
		s.byEng[engagementID] = list
		key := judgmentAuditKey{kind: ports.JudgmentVerdictAudit, judgmentID: id, version: list[i].Version}
		s.pendingAudit[key] = ports.PendingJudgmentAudit{Kind: ports.JudgmentVerdictAudit, JudgmentID: id, Version: list[i].Version, EngagementID: engagementID, Entry: entry}
		return list[i], nil
	}
	return judgment.Judgment{}, fmt.Errorf("judgment %s: %w", id, shared.ErrNotFound)
}

func (s *JudgmentStore) ListPendingJudgmentAudits(ctx context.Context, engagementID shared.ID) ([]ports.PendingJudgmentAudit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ports.PendingJudgmentAudit, 0)
	for _, pending := range s.pendingAudit {
		if pending.EngagementID == engagementID {
			out = append(out, pending)
		}
	}
	return out, nil
}

func (s *JudgmentStore) AcknowledgeJudgmentAudit(ctx context.Context, kind ports.JudgmentAuditKind, judgmentID shared.ID, version int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := judgmentAuditKey{kind: kind, judgmentID: judgmentID, version: version}
	if _, ok := s.pendingAudit[key]; !ok {
		return nil
	}
	delete(s.pendingAudit, key)
	return nil
}
