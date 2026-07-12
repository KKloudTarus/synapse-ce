// Package findings handles the human findings workflow: manual
// authoring, triage status transitions (with optimistic concurrency), assignment,
// and the persisted comment thread. Every change is recorded to the append-only
// audit log; comments are the collaboration record, distinct from
// audit. Triage state survives re-scans (the repositories preserve it on upsert).
package findings

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.ConfirmedThreatRecorder = (*Service)(nil)
var _ ports.ConfirmedSASTRecorder = (*Service)(nil)
var _ ports.ConfirmedDASTRecorder = (*Service)(nil)
var _ ports.FindingWriteupApplier = (*Service)(nil)

// Service lists findings and applies authoring/triage/assignment/comment/retest changes.
type Service struct {
	repo     ports.FindingRepository
	comments ports.CommentRepository
	retests  ports.RetestRepository
	audit    ports.AuditLogger
	clock    ports.Clock
	ids      ports.IDGenerator
}

// NewService wires the findings workflow service.
func NewService(repo ports.FindingRepository, comments ports.CommentRepository, retests ports.RetestRepository, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) *Service {
	return &Service{repo: repo, comments: comments, retests: retests, audit: audit, clock: clock, ids: ids}
}

// List returns an engagement's findings, highest risk first.
func (s *Service) List(ctx context.Context, engagementID shared.ID) ([]finding.Finding, error) {
	return s.repo.ListByEngagement(ctx, engagementID)
}

// RecordConfirmedThreat promotes a human-ratified STRIDE threat judgment to a persisted Kind=threat finding
// (auto-emit on ratify). Idempotent via the threat:<judgmentID> dedup key – a re-confirm updates in
// place. The finding is built DETERMINISTICALLY from the typed claim + subject (no LLM);
// severity starts Unknown so a human triages it through the normal finding workflow. Audited.
func (s *Service) RecordConfirmedThreat(ctx context.Context, verifier string, j judgment.Judgment) error {
	if j.Capability != judgment.CapThreat {
		return fmt.Errorf("%w: not a threat judgment (%s)", shared.ErrValidation, j.Capability)
	}
	tc, ok := j.Claim.(judgment.ThreatClaim)
	if !ok {
		return fmt.Errorf("%w: threat judgment %s carries no ThreatClaim", shared.ErrValidation, j.ID)
	}
	f, err := finding.NewThreat(s.ids.NewID(), j.EngagementID, finding.ThreatInput{
		JudgmentID: j.ID.String(),
		Category:   string(tc.Category),
		Element:    j.SubjectID.String(),
		Asset:      tc.Asset,
	}, s.clock.Now())
	if err != nil {
		return err
	}
	if err := s.repo.Upsert(ctx, []finding.Finding{f}); err != nil {
		return fmt.Errorf("persist threat finding: %w", err)
	}
	// Attribute the promotion to the human VERIFIER who ratified the threat (the trigger), not the agent
	// that originally proposed the judgment – the judgment's own verdict audit already records the proposer.
	return s.record(ctx, verifier, "finding.threat_promoted", j.EngagementID, f.ID,
		map[string]string{"judgment": j.ID.String(), "category": string(tc.Category), "element": j.SubjectID.String()})
}

// RecordConfirmedSAST promotes a verifier-confirmed CapSAST (taint) judgment to a persisted Kind=sast
// finding (auto-emit on confirm). Idempotent via the sast:ai:<judgmentID> dedup key – a re-confirm
// updates in place. The finding is built DETERMINISTICALLY from the typed SASTClaim (no LLM);
// severity starts Unknown so a human triages it through the normal finding workflow. Audited.
func (s *Service) RecordConfirmedSAST(ctx context.Context, verifier string, j judgment.Judgment) error {
	if j.Capability != judgment.CapSAST {
		return fmt.Errorf("%w: not a sast judgment (%s)", shared.ErrValidation, j.Capability)
	}
	sc, ok := j.Claim.(judgment.SASTClaim)
	if !ok {
		return fmt.Errorf("%w: sast judgment %s carries no SASTClaim", shared.ErrValidation, j.ID)
	}
	f, err := finding.NewSAST(s.ids.NewID(), j.EngagementID, finding.SASTInput{
		JudgmentID: j.ID.String(),
		CWE:        sc.CWE,
		Location:   sc.Location,
		Rule:       sc.Rule,
	}, s.clock.Now())
	if err != nil {
		return err
	}
	if err := s.repo.Upsert(ctx, []finding.Finding{f}); err != nil {
		return fmt.Errorf("persist sast finding: %w", err)
	}
	// Attribute the promotion to the VERIFIER who confirmed the taint judgment (the trigger), not the
	// system proposer – the judgment's own verdict audit already records the proposer.
	return s.record(ctx, verifier, "finding.sast_promoted", j.EngagementID, f.ID,
		map[string]string{"judgment": j.ID.String(), "cwe": sc.CWE, "rule": sc.Rule, "location": sc.Location})
}

// RecordConfirmedDAST promotes a RUNTIME-verifier-confirmed CapSAST judgment to a persisted Kind=dast
// finding (auto-emit on runtime confirm). It is the runtime twin of RecordConfirmedSAST — the same
// verifier-confirmed CapSAST judgment, but the confirming verdict came from a safe runtime probe rather
// than a static/LLM verifier, so it projects to a distinct, dynamically-proven Kind=dast finding.
// Idempotent via the dast:ai:<judgmentID> dedup key – a re-confirm updates in place. The finding is built
// DETERMINISTICALLY from the typed SASTClaim (no LLM); severity starts Unknown so a human triages it
// through the normal finding workflow. Audited.
func (s *Service) RecordConfirmedDAST(ctx context.Context, verifier string, j judgment.Judgment) error {
	if j.Capability != judgment.CapSAST {
		return fmt.Errorf("%w: not a sast judgment (%s)", shared.ErrValidation, j.Capability)
	}
	sc, ok := j.Claim.(judgment.SASTClaim)
	if !ok {
		return fmt.Errorf("%w: sast judgment %s carries no SASTClaim", shared.ErrValidation, j.ID)
	}
	f, err := finding.NewDAST(s.ids.NewID(), j.EngagementID, finding.DASTInput{
		JudgmentID: j.ID.String(),
		CWE:        sc.CWE,
		Location:   sc.Location,
		Rule:       sc.Rule,
	}, s.clock.Now())
	if err != nil {
		return err
	}
	if err := s.repo.Upsert(ctx, []finding.Finding{f}); err != nil {
		return fmt.Errorf("persist dast finding: %w", err)
	}
	// Attribute the promotion to the VERIFIER whose runtime probe confirmed the judgment (the trigger), not
	// the system proposer – the judgment's own verdict audit already records the proposer.
	return s.record(ctx, verifier, "finding.dast_promoted", j.EngagementID, f.ID,
		map[string]string{"judgment": j.ID.String(), "cwe": sc.CWE, "rule": sc.Rule, "location": sc.Location})
}

// ApplyWriteupDraft applies an accepted, human-signed-off write-up draft to its finding: it sets the
// finding's authoritative Description from the draft's description + remediation prose. It is the auto-apply
// hook the writeupdraft accept path calls. It VALIDATES the finding belongs to the engagement before mutating
// (loadFinding → ErrNotFound for a cross-engagement / unknown id, so no cross-engagement write), preserves the
// finding's other fields (the upsert keeps triage state, severity, CWE – so the report's per-finding compliance
// mapping is unaffected), and audits. The prose was already trimmed, length-bounded, and credential-redacted
// at the draft's propose/edit edge.
func (s *Service) ApplyWriteupDraft(ctx context.Context, actor string, engagementID, findingID shared.ID, description, remediation string) error {
	if strings.TrimSpace(actor) == "" {
		return fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	f, err := s.loadFinding(ctx, engagementID, findingID)
	if err != nil {
		return err
	}
	f.Description = composeWriteup(description, remediation)
	if err := s.repo.Upsert(ctx, []finding.Finding{f}); err != nil {
		return fmt.Errorf("apply writeup draft: %w", err)
	}
	return s.record(ctx, actor, "finding.writeup_applied", engagementID, findingID, map[string]string{"source": "writeup_draft"})
}

// composeWriteup folds an accepted draft's description + remediation into the finding's single Description
// field (Finding models description-only): the description, then the remediation under a heading when present.
// At least one is non-empty by the draft domain's invariant.
func composeWriteup(description, remediation string) string {
	description = strings.TrimSpace(description)
	remediation = strings.TrimSpace(remediation)
	switch {
	case remediation == "":
		return description
	case description == "":
		return "Remediation:\n" + remediation
	default:
		return description + "\n\nRemediation:\n" + remediation
	}
}

// Create validates and persists a hand-authored (manual) finding. When a CVSS
// vector is supplied it is the authoritative source of severity (derived from the
// computed base score); otherwise the operator's severity is used. Audited.
func (s *Service) Create(ctx context.Context, actor string, engagementID shared.ID, in finding.ManualInput) (finding.Finding, error) {
	if strings.TrimSpace(actor) == "" {
		return finding.Finding{}, fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	if v := strings.TrimSpace(in.CVSSVector); v != "" {
		score, ok := shared.CVSSv3BaseScore(v)
		if !ok {
			return finding.Finding{}, fmt.Errorf("%w: invalid CVSS v3.1 vector", shared.ErrValidation)
		}
		in.Severity = shared.SeverityFromScore(score)
	}
	now := s.clock.Now()
	f, err := finding.NewManual(s.ids.NewID(), engagementID, in, now)
	if err != nil {
		return finding.Finding{}, err
	}
	if err := s.repo.Upsert(ctx, []finding.Finding{f}); err != nil {
		return finding.Finding{}, fmt.Errorf("persist finding: %w", err)
	}
	if err := s.record(ctx, actor, "finding.created", engagementID, f.ID,
		map[string]string{"severity": string(f.Severity), "kind": string(f.Kind)}); err != nil {
		return finding.Finding{}, err
	}
	return f, nil
}

// UpdateStatus validates and applies a triage status change with optimistic
// concurrency (expectedVersion), then audits it. ErrConflict if the finding moved.
func (s *Service) UpdateStatus(ctx context.Context, engagementID, findingID shared.ID, status finding.Status, note, actor string, expectedVersion int) (finding.Finding, error) {
	if strings.TrimSpace(actor) == "" {
		return finding.Finding{}, fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	if !status.Valid() {
		return finding.Finding{}, fmt.Errorf("%w: unknown finding status %q", shared.ErrValidation, status)
	}
	// Evidence gate: an exploitation/AI finding may not be promoted to
	// CONFIRMED until its claim clears the evidence bar (>= 75). SCA/recon/manual
	// findings are not gated (CanPromote returns true for them), so this is a no-op for
	// the existing kinds and the enforcement is in place for when P4 produces
	// exploitation findings. Wires the previously-dead Finding.CanPromote.
	if status == finding.StatusConfirmed {
		// Engage the gate only when the finding loads cleanly; otherwise defer to
		// repo.UpdateStatus's authoritative not-found/conflict result.
		if cur, err := s.loadFinding(ctx, engagementID, findingID); err == nil && !cur.CanPromote() {
			return finding.Finding{}, fmt.Errorf("%w: %s finding cannot be confirmed below the evidence bar (score %d < %d)",
				shared.ErrValidation, cur.Kind, cur.EvidenceScore, finding.EvidenceThreshold)
		}
	}
	f, err := s.repo.UpdateStatus(ctx, engagementID, findingID, status, expectedVersion)
	if err != nil {
		return finding.Finding{}, err
	}
	meta := map[string]string{"status": string(status)}
	if note != "" {
		meta["note"] = note
	}
	if err := s.record(ctx, actor, "finding.status", engagementID, findingID, meta); err != nil {
		return finding.Finding{}, err
	}
	return f, nil
}

// SetAssignee assigns/unassigns a finding with the same optimistic-concurrency
// guard, then audits it.
func (s *Service) SetAssignee(ctx context.Context, engagementID, findingID shared.ID, assignee, actor string, expectedVersion int) (finding.Finding, error) {
	if strings.TrimSpace(actor) == "" {
		return finding.Finding{}, fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	f, err := s.repo.SetAssignee(ctx, engagementID, findingID, strings.TrimSpace(assignee), expectedVersion)
	if err != nil {
		return finding.Finding{}, err
	}
	if err := s.record(ctx, actor, "finding.assigned", engagementID, findingID,
		map[string]string{"assignee": f.Assignee}); err != nil {
		return finding.Finding{}, err
	}
	return f, nil
}

// AddComment appends a comment to a finding's thread (persisted, attributed) and
// audits it. The finding must belong to the engagement (no cross-engagement comment).
func (s *Service) AddComment(ctx context.Context, engagementID, findingID shared.ID, body, actor string) (finding.Comment, error) {
	if ok, err := s.findingInEngagement(ctx, engagementID, findingID); err != nil {
		return finding.Comment{}, err
	} else if !ok {
		return finding.Comment{}, fmt.Errorf("finding %s: %w", findingID, shared.ErrNotFound)
	}
	c, err := finding.NewComment(s.ids.NewID(), engagementID, findingID, actor, body, s.clock.Now())
	if err != nil {
		return finding.Comment{}, err
	}
	if err := s.comments.Add(ctx, c); err != nil {
		return finding.Comment{}, fmt.Errorf("persist comment: %w", err)
	}
	if err := s.record(ctx, actor, "finding.comment", engagementID, findingID, nil); err != nil {
		return finding.Comment{}, err
	}
	return c, nil
}

// Comments returns a finding's comment thread (oldest first), scoped to the engagement.
func (s *Service) Comments(ctx context.Context, engagementID, findingID shared.ID) ([]finding.Comment, error) {
	return s.comments.ListByEngagementFinding(ctx, engagementID, findingID)
}

// RecordRetest appends a retest record and moves the finding to the status
// the outcome implies, under the same optimistic-concurrency guard (expectedVersion).
// The status update is the authoritative in-engagement + version check, so a stale
// or cross-engagement retest is rejected (ErrConflict / ErrNotFound) before the
// record is written. Returns the retest and the updated finding. Audited.
func (s *Service) RecordRetest(ctx context.Context, engagementID, findingID shared.ID, outcome finding.RetestOutcome, note, actor string, expectedVersion int) (finding.Retest, finding.Finding, error) {
	if strings.TrimSpace(actor) == "" {
		return finding.Retest{}, finding.Finding{}, fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	rt, err := finding.NewRetest(s.ids.NewID(), engagementID, findingID, outcome, note, actor, s.clock.Now())
	if err != nil {
		return finding.Retest{}, finding.Finding{}, err
	}
	f, err := s.repo.UpdateStatus(ctx, engagementID, findingID, outcome.ResultingStatus(), expectedVersion)
	if err != nil {
		return finding.Retest{}, finding.Finding{}, err
	}
	if err := s.retests.Add(ctx, rt); err != nil {
		return finding.Retest{}, finding.Finding{}, fmt.Errorf("persist retest: %w", err)
	}
	if err := s.record(ctx, actor, "finding.retest", engagementID, findingID,
		map[string]string{"outcome": string(outcome), "status": string(outcome.ResultingStatus())}); err != nil {
		return finding.Retest{}, finding.Finding{}, err
	}
	return rt, f, nil
}

// Retests returns a finding's retest history (oldest first), scoped to the engagement.
func (s *Service) Retests(ctx context.Context, engagementID, findingID shared.ID) ([]finding.Retest, error) {
	return s.retests.ListByEngagementFinding(ctx, engagementID, findingID)
}

// findingInEngagement reports whether the finding exists within the engagement
// (used to scope comments + writes; no cross-engagement access).
func (s *Service) findingInEngagement(ctx context.Context, engagementID, findingID shared.ID) (bool, error) {
	list, err := s.repo.ListByEngagement(ctx, engagementID)
	if err != nil {
		return false, err
	}
	for _, f := range list {
		if f.ID == findingID {
			return true, nil
		}
	}
	return false, nil
}

// loadFinding returns one finding scoped to its engagement (ErrNotFound otherwise),
// for the evidence-gate check. Reuses the engagement-scoped list (no cross-engagement
// read); the repository has no single-Get and findings-per-engagement are bounded.
func (s *Service) loadFinding(ctx context.Context, engagementID, findingID shared.ID) (finding.Finding, error) {
	list, err := s.repo.ListByEngagement(ctx, engagementID)
	if err != nil {
		return finding.Finding{}, err
	}
	for _, f := range list {
		if f.ID == findingID {
			return f, nil
		}
	}
	return finding.Finding{}, fmt.Errorf("finding %s: %w", findingID, shared.ErrNotFound)
}

// record writes an attributable, append-only audit entry; a failed write is
// surfaced (consistent with the rest of the workflow).
func (s *Service) record(ctx context.Context, actor, action string, engagementID, target shared.ID, md map[string]string) error {
	// Copy into a fresh map so we never mutate the caller's argument.
	entry := map[string]string{"engagement": engagementID.String()}
	for k, v := range md {
		entry[k] = v
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: action, Target: target.String(), Metadata: entry, At: s.clock.Now()}); err != nil {
		return fmt.Errorf("audit %s: %w", action, err)
	}
	return nil
}
