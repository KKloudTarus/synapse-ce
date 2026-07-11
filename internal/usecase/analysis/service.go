// Package analysis runs the evidence-gated lifecycle for AI "judgments" – the generalized
// twin of the exploitation gate. A judgment is PROPOSED at EvidenceScore 0; a DISTINCT
// verifier's verdict (gated capabilities) or a human's acceptance (ungated) is the only thing that
// confirms it, and the verdict is SEALED into the hash-chained evidence ledger BEFORE the score
// moves (fail-closed). Verify/Accept are NOT agent-callable: this package is on the agent tool
// catalog's forbidden-import list (agenttools/arch_test.go), so the proposing agent has no path to
// confirm its own judgment.
package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Evidence kinds sealed across a judgment's lifecycle.
const (
	ProposedEvidenceKind = "judgment_proposed"
	VerdictEvidenceKind  = "judgment_verdict"
	AcceptedEvidenceKind = "judgment_accepted"
)

// Store is the narrow slice of the judgment repository this use case needs. The score/state MOVER
// (SetScoreState) lives here (and on the concrete repo) – NOT on a broad ports interface – so a
// read-only consumer (the agent tool catalog) cannot move a score. Concrete repos satisfy it.
type Store interface {
	Save(ctx context.Context, j judgment.Judgment) error
	ListByEngagement(ctx context.Context, engagementID shared.ID) ([]judgment.Judgment, error)
	SetScoreState(ctx context.Context, engagementID, id shared.ID, score int, state judgment.State, expectedVersion int) (judgment.Judgment, error)
}

// evidenceSealer seals one link into the engagement's hash-chained evidence ledger.
type evidenceSealer interface {
	Seal(ctx context.Context, engagementID shared.ID, kind string, content []byte, createdBy string) (evidence.Evidence, error)
}

// Service runs the propose→verify/accept→publishable lifecycle for judgments.
type Service struct {
	store    Store
	evidence evidenceSealer
	audit    ports.AuditLogger
	clock    ports.Clock
	ids      ports.IDGenerator
	// threatRecorder (optional) promotes a CONFIRMED threat judgment to a Kind=threat finding,
	// best-effort. Injected from the composition root – never reachable by the agent (R11 stays intact).
	threatRecorder ports.ConfirmedThreatRecorder
	// sastRecorder (optional) promotes a CONFIRMED CapSAST (taint) judgment to a Kind=sast finding,
	// best-effort. Injected from the composition root – never reachable by the agent.
	sastRecorder ports.ConfirmedSASTRecorder
}

// NewService validates dependencies (all required; the sealer is mandatory because a verdict that
// cannot be sealed must never move a score).
func NewService(store Store, ev evidenceSealer, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if store == nil || ev == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: analysis service is missing a dependency", shared.ErrValidation)
	}
	return &Service{store: store, evidence: ev, audit: audit, clock: clock, ids: ids}, nil
}

type sealedProposal struct {
	JudgmentID  string          `json:"judgment_id"`
	Capability  string          `json:"capability"`
	SubjectKind string          `json:"subject_kind"`
	SubjectID   string          `json:"subject_id"`
	ProposedBy  string          `json:"proposed_by"`
	Claim       json.RawMessage `json:"claim"`
}

type sealedVerdict struct {
	JudgmentID string `json:"judgment_id"`
	Verifier   string `json:"verifier"`
	Score      int    `json:"score"`
	Rationale  string `json:"rationale"`
}

type sealedAcceptance struct {
	JudgmentID string `json:"judgment_id"`
	AcceptedBy string `json:"accepted_by"`
}

// Propose records a PROPOSED judgment at EvidenceScore 0, sealing the inert (typed) claim into the
// evidence chain under the proposer (attribution only; confers no power to score). The agent reaches
// this only via a propose-only catalog tool (added per-capability with E28/E38).
func (s *Service) Propose(ctx context.Context, proposer string, engagementID shared.ID, capability judgment.Capability, subjectKind judgment.SubjectKind, subjectID shared.ID, claim judgment.Claim) (judgment.Judgment, error) {
	if proposer == "" {
		return judgment.Judgment{}, fmt.Errorf("%w: proposer is required", shared.ErrValidation)
	}
	if engagementID.IsZero() { // parity with exploitation.Propose (a use-case precondition, before minting an id)
		return judgment.Judgment{}, fmt.Errorf("%w: engagement id is required", shared.ErrValidation)
	}
	j, err := judgment.New(s.ids.NewID(), engagementID, capability, subjectKind, subjectID, claim, proposer, s.clock.Now())
	if err != nil {
		return judgment.Judgment{}, err
	}
	claimJSON, err := judgment.MarshalClaim(j.Claim)
	if err != nil {
		return judgment.Judgment{}, fmt.Errorf("marshal claim: %w", err)
	}
	payload, err := json.Marshal(sealedProposal{
		JudgmentID: j.ID.String(), Capability: string(j.Capability), SubjectKind: string(j.SubjectKind),
		SubjectID: j.SubjectID.String(), ProposedBy: j.ProposedBy, Claim: claimJSON,
	})
	if err != nil {
		return judgment.Judgment{}, fmt.Errorf("marshal judgment proposal: %w", err)
	}
	// Seal the inert claim first (custody), then persist; an orphaned proposal seal on a save
	// failure is harmless (it is score 0, not gating).
	if _, err := s.evidence.Seal(ctx, engagementID, ProposedEvidenceKind, payload, j.ProposedBy); err != nil {
		return judgment.Judgment{}, fmt.Errorf("seal judgment proposal: %w", err)
	}
	if err := s.store.Save(ctx, j); err != nil {
		return judgment.Judgment{}, fmt.Errorf("persist judgment: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: proposer, Action: "judgment.proposed", Target: j.ID.String(),
		Metadata: map[string]string{"engagement": engagementID.String(), "capability": string(j.Capability), "subject": string(j.SubjectKind) + ":" + j.SubjectID.String()},
		At:       s.clock.Now(),
	}); err != nil {
		return judgment.Judgment{}, fmt.Errorf("audit judgment proposal: %w", err)
	}
	return j, nil
}

// Verify applies a DISTINCT verifier's verdict to a GATED judgment. It seals the verdict FIRST
// (fail-closed), then moves the score+state under optimistic concurrency (expectedVersion). A
// verdict that loses the race leaves an orphan sealed verdict with no score move – acceptable (the
// assessment really happened), mirroring the exploitation gate's one-directional provenance.
func (s *Service) Verify(ctx context.Context, verifier string, engagementID, judgmentID shared.ID, score int, rationale string, expectedVersion int) (judgment.Judgment, error) {
	v := verdict.Verdict{Verifier: verifier, Score: score, Rationale: rationale}
	if err := v.Validate(); err != nil {
		return judgment.Judgment{}, err
	}
	cur, err := s.load(ctx, engagementID, judgmentID)
	if err != nil {
		return judgment.Judgment{}, err
	}
	// Pure transition first: re-asserts gated + self-confirm + proposed-state, so an ineligible
	// judgment is rejected WITHOUT writing a spurious evidence link.
	updated, err := cur.ApplyVerdict(v, s.clock.Now())
	if err != nil {
		return judgment.Judgment{}, err
	}
	payload, err := json.Marshal(sealedVerdict{JudgmentID: judgmentID.String(), Verifier: v.Verifier, Score: v.Score, Rationale: v.Rationale})
	if err != nil {
		return judgment.Judgment{}, fmt.Errorf("marshal judgment verdict: %w", err)
	}
	if _, err := s.evidence.Seal(ctx, engagementID, VerdictEvidenceKind, payload, verifier); err != nil {
		return judgment.Judgment{}, fmt.Errorf("seal judgment verdict: %w", err)
	}
	saved, err := s.store.SetScoreState(ctx, engagementID, judgmentID, updated.EvidenceScore, updated.State, expectedVersion)
	if err != nil {
		return judgment.Judgment{}, fmt.Errorf("apply judgment verdict: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: verifier, Action: "judgment.verdict", Target: judgmentID.String(),
		Metadata: map[string]string{"engagement": engagementID.String(), "score": strconv.Itoa(v.Score), "state": string(saved.State), "publishable": strconv.FormatBool(saved.Publishable())},
		At:       s.clock.Now(),
	}); err != nil {
		return judgment.Judgment{}, fmt.Errorf("audit judgment verdict: %w", err)
	}
	// a ratified STRIDE threat auto-emits a Kind=threat finding. Best-effort – the judgment is
	// already confirmed + audited; a failed emit is audited, not rolled back (the finding is a
	// re-derivable projection of the source-of-truth judgment, mirroring the reachproof auto-mint).
	if s.threatRecorder != nil && saved.State == judgment.StateConfirmed && saved.Capability == judgment.CapThreat {
		if rerr := s.threatRecorder.RecordConfirmedThreat(ctx, verifier, saved); rerr != nil {
			_ = s.audit.Record(ctx, ports.AuditEntry{
				Actor: verifier, Action: "threat_finding.emit_failed", Target: judgmentID.String(),
				Metadata: map[string]string{"engagement": engagementID.String()}, At: s.clock.Now(),
			})
		}
	}
	// a verifier-confirmed CapSAST (taint) judgment auto-emits a Kind=sast finding. Best-effort, same
	// contract as the threat promoter – the judgment is already confirmed + audited; a failed emit is
	// audited, not rolled back (the finding is a re-derivable projection of the source-of-truth judgment).
	if s.sastRecorder != nil && saved.State == judgment.StateConfirmed && saved.Capability == judgment.CapSAST {
		if rerr := s.sastRecorder.RecordConfirmedSAST(ctx, verifier, saved); rerr != nil {
			_ = s.audit.Record(ctx, ports.AuditEntry{
				Actor: verifier, Action: "sast_finding.emit_failed", Target: judgmentID.String(),
				Metadata: map[string]string{"engagement": engagementID.String()}, At: s.clock.Now(),
			})
		}
	}
	return saved, nil
}

// SetThreatRecorder wires the optional confirmed-threat → finding promoter. nil ⇒ no finding is
// emitted on confirm. Composition-root only.
func (s *Service) SetThreatRecorder(r ports.ConfirmedThreatRecorder) { s.threatRecorder = r }

// SetSASTRecorder wires the optional confirmed-CapSAST → finding promoter. nil ⇒ no finding is
// emitted on confirm. Composition-root only.
func (s *Service) SetSASTRecorder(r ports.ConfirmedSASTRecorder) { s.sastRecorder = r }

// Accept confirms an UNGATED judgment by human acceptance (no score; there is nothing to refute at
// 75). It seals the acceptance FIRST, then transitions state under optimistic concurrency. The
// acceptor must be a non-proposer human (enforced in the domain).
func (s *Service) Accept(ctx context.Context, by string, engagementID, judgmentID shared.ID, expectedVersion int) (judgment.Judgment, error) {
	cur, err := s.load(ctx, engagementID, judgmentID)
	if err != nil {
		return judgment.Judgment{}, err
	}
	updated, err := cur.Accept(by, s.clock.Now())
	if err != nil {
		return judgment.Judgment{}, err
	}
	payload, err := json.Marshal(sealedAcceptance{JudgmentID: judgmentID.String(), AcceptedBy: by})
	if err != nil {
		return judgment.Judgment{}, fmt.Errorf("marshal judgment acceptance: %w", err)
	}
	if _, err := s.evidence.Seal(ctx, engagementID, AcceptedEvidenceKind, payload, by); err != nil {
		return judgment.Judgment{}, fmt.Errorf("seal judgment acceptance: %w", err)
	}
	saved, err := s.store.SetScoreState(ctx, engagementID, judgmentID, updated.EvidenceScore, updated.State, expectedVersion)
	if err != nil {
		return judgment.Judgment{}, fmt.Errorf("apply judgment acceptance: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: by, Action: "judgment.accepted", Target: judgmentID.String(),
		Metadata: map[string]string{"engagement": engagementID.String(), "capability": string(saved.Capability)},
		At:       s.clock.Now(),
	}); err != nil {
		return judgment.Judgment{}, fmt.Errorf("audit judgment acceptance: %w", err)
	}
	return saved, nil
}

// List returns the engagement's judgments – the read path for the HTTP layer. Tenant isolation is
// enforced at the route (withEngTenant resolves the engagement in the caller's tenant) before this
// is called; the store scopes by engagement.
func (s *Service) List(ctx context.Context, engagementID shared.ID) ([]judgment.Judgment, error) {
	return s.store.ListByEngagement(ctx, engagementID)
}

// load returns one judgment scoped to its engagement (the store lists by engagement, so a single
// get is a scan-and-match – mirrors the exploitation use case).
func (s *Service) load(ctx context.Context, engagementID, id shared.ID) (judgment.Judgment, error) {
	all, err := s.store.ListByEngagement(ctx, engagementID)
	if err != nil {
		return judgment.Judgment{}, fmt.Errorf("load judgment: %w", err)
	}
	for _, j := range all {
		if j.ID == id {
			return j, nil
		}
	}
	return judgment.Judgment{}, fmt.Errorf("judgment %s: %w", id, shared.ErrNotFound)
}
