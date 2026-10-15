// Package findings handles the human findings workflow: manual
// authoring, triage status transitions (with optimistic concurrency), assignment,
// and the persisted comment thread. Every change is recorded to the append-only
// audit log; comments are the collaboration record, distinct from
// audit. Triage state survives re-scans (the repositories preserve it on upsert).
package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.ConfirmedThreatRecorder = (*Service)(nil)
var _ ports.ConfirmedSASTRecorder = (*Service)(nil)
var _ ports.ConfirmedDASTRecorder = (*Service)(nil)
var _ ports.FindingWriteupApplier = (*Service)(nil)
var _ ports.AITriageFindingDecision = (*Service)(nil)

// Service lists findings and applies authoring/triage/assignment/comment/retest changes.
type Service struct {
	repo              ports.FindingRepository
	claimer           ports.FindingProjectionClaimer
	engagements       ports.EngagementTenantResolver
	comments          ports.CommentRepository
	retests           ports.RetestRepository
	audit             ports.AuditLogger
	clock             ports.Clock
	ids               ports.IDGenerator
	attributor        ports.FindingAttributor
	assigneeWriter    ports.FindingAssigneeWriter
	shadowTx          ports.TenantTransactionRunner
	shadow            CreatedFindingProjector
	shadowOn          func(string) bool
	notificationTx    ports.TenantTransactionRunner
	notifications     ports.NotificationOutbox
	notificationFacts ports.NotificationFindingFactsReader
	mentionUsers      ports.UserRepository
}

type CreatedFindingProjector interface {
	ProjectCreatedFinding(context.Context, shared.ID, finding.Finding, string) error
}

// NewService wires the findings workflow service.
func NewService(repo ports.FindingRepository, comments ports.CommentRepository, retests ports.RetestRepository, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) *Service {
	claimer, _ := repo.(ports.FindingProjectionClaimer)
	return &Service{repo: repo, claimer: claimer, comments: comments, retests: retests, audit: audit, clock: clock, ids: ids}
}

// SetEngagementTenantResolver wires the internal engagement lookup used to select the RLS tenant.
func (s *Service) SetEngagementTenantResolver(r ports.EngagementTenantResolver) { s.engagements = r }

// SetAttributor wires authoritative asset-to-finding bindings; nil preserves legacy internal callers.
func (s *Service) SetAttributor(a ports.FindingAttributor) { s.attributor = a }

func (s *Service) SetAssigneeWriter(writer ports.FindingAssigneeWriter) { s.assigneeWriter = writer }

// SetMentionUsers enables canonical user-ID validation for native comments.
// Display labels and contacts are deliberately outside this boundary.
func (s *Service) SetMentionUsers(users ports.UserRepository) { s.mentionUsers = users }

// SetNotifications enables finding event capture. The caller must supply the same
// tenant transaction runner used by the repositories, so the finding, audit and
// source record commit together. Engagement ownership is resolved authoritatively
// before the transaction is opened; an ambient tenant cannot select another tenant.
func (s *Service) SetNotifications(tx ports.TenantTransactionRunner, outbox ports.NotificationOutbox, facts ports.NotificationFindingFactsReader) error {
	if tx == nil || outbox == nil || facts == nil || s.engagements == nil {
		return fmt.Errorf("%w: finding notification dependencies are required", shared.ErrValidation)
	}
	s.notificationTx, s.notifications, s.notificationFacts = tx, outbox, facts
	return nil
}

// SetLifecycleShadow makes a newly-authored Finding, its audit/attribution, and
// its shadow lineage Observation one tenant-local transaction.
func (s *Service) SetLifecycleShadow(tx ports.TenantTransactionRunner, projector CreatedFindingProjector, enabled func(string) bool) error {
	if tx == nil || projector == nil || enabled == nil || s.engagements == nil {
		return fmt.Errorf("%w: finding lifecycle shadow dependencies are required", shared.ErrValidation)
	}
	s.shadowTx, s.shadow, s.shadowOn = tx, projector, enabled
	return nil
}

// CreateAttributed requires an explicit asset for a new externally-authored finding.
func (s *Service) CreateAttributed(ctx context.Context, actor string, engagementID, assetID shared.ID, in finding.ManualInput) (finding.Finding, error) {
	if s.attributor == nil {
		return finding.Finding{}, fmt.Errorf("%w: finding attribution is not configured", shared.ErrValidation)
	}
	if err := s.attributor.ValidateAsset(ctx, engagementID, assetID); err != nil {
		return finding.Finding{}, err
	}
	key := attributedManualKey(actor, engagementID, assetID, in)
	var f finding.Finding
	err := s.withCreationBoundary(ctx, engagementID, func(writeCtx context.Context, tenantID shared.ID, project bool) error {
		var err error
		f, err = s.findByDedupKey(writeCtx, engagementID, key)
		if err != nil {
			return err
		}
		created := f.ID.IsZero()
		if created {
			if v := strings.TrimSpace(in.CVSSVector); v != "" {
				score, ok := shared.CVSSv3BaseScore(v)
				if !ok {
					return fmt.Errorf("%w: invalid CVSS v3.1 vector", shared.ErrValidation)
				}
				in.Severity = shared.SeverityFromScore(score)
			}
			f, err = finding.NewManual(s.ids.NewID(), engagementID, in, s.clock.Now())
			if err != nil {
				return err
			}
			f.DedupKey = key
			if err := s.repo.Upsert(writeCtx, []finding.Finding{f}); err != nil {
				return fmt.Errorf("persist finding: %w", err)
			}
			if stored, err := s.findByDedupKey(writeCtx, engagementID, key); err != nil {
				return creationFollowupError(project, f.ID, err)
			} else if !stored.ID.IsZero() {
				f = stored
			}
			if err := s.record(writeCtx, actor, "finding.created", engagementID, f.ID, map[string]string{"severity": string(f.Severity), "kind": string(f.Kind)}); err != nil {
				return creationFollowupError(project, f.ID, err)
			}
			if err := s.appendFindingCreated(writeCtx, tenantID, f, "", actor); err != nil {
				return creationFollowupError(project, f.ID, err)
			}
		}
		if err := s.attributor.Record(writeCtx, engagementID, assetID, "manual:"+f.ID, "manual:"+f.ID, asset.EdgeObserved, []shared.ID{f.ID}); err != nil {
			err = fmt.Errorf("record finding attribution: %w", err)
			if created {
				return creationFollowupError(project, f.ID, err)
			}
			return err
		}
		if created && project {
			return s.shadow.ProjectCreatedFinding(writeCtx, tenantID, f, actor)
		}
		return nil
	})
	return f, err
}

func creationFollowupError(transactional bool, findingID shared.ID, err error) error {
	if err == nil || transactional {
		return err
	}
	return &ports.PartialWriteError{Operation: "manual finding", IDs: []shared.ID{findingID}, Err: err}
}

func attributedManualKey(actor string, engagementID, assetID shared.ID, in finding.ManualInput) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{actor, engagementID.String(), assetID.String(), strings.TrimSpace(in.Title), strings.TrimSpace(in.Description), string(in.Severity), strings.TrimSpace(in.CVSSVector), strings.TrimSpace(in.CWE)}, "\x00")))
	return "manual:attributed:" + hex.EncodeToString(sum[:16])
}

func (s *Service) findByDedupKey(ctx context.Context, engagementID shared.ID, key string) (finding.Finding, error) {
	if reader, ok := s.repo.(ports.FindingDedupReader); ok {
		stored, err := reader.GetByEngagementAndDedupKey(ctx, engagementID, key)
		if errors.Is(err, shared.ErrNotFound) {
			return finding.Finding{}, nil
		}
		if err != nil {
			return finding.Finding{}, fmt.Errorf("read finding dedup identity: %w", err)
		}
		return stored, nil
	}
	all, err := s.repo.ListByEngagement(ctx, engagementID)
	if err != nil {
		return finding.Finding{}, fmt.Errorf("list findings: %w", err)
	}
	for _, f := range all {
		if f.DedupKey == key {
			return f, nil
		}
	}
	return finding.Finding{}, nil
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
	if !j.Publishable() {
		return fmt.Errorf("%w: threat judgment %s is not publishable", shared.ErrValidation, j.ID)
	}
	tc, ok := j.Claim.(judgment.ThreatClaim)
	if !ok {
		return fmt.Errorf("%w: threat judgment %s carries no ThreatClaim", shared.ErrValidation, j.ID)
	}
	assetID, err := s.projectionAssetID(ctx, j, tc.AssetID)
	if err != nil {
		return err
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
	return s.withFindingBoundary(ctx, j.EngagementID, func(writeCtx context.Context, tenantID shared.ID) error {
		created := s.notifications != nil
		if created {
			stored, err := s.findByDedupKey(writeCtx, j.EngagementID, f.DedupKey)
			if err != nil {
				return err
			}
			created = stored.ID.IsZero()
		}
		if err := s.repo.Upsert(writeCtx, []finding.Finding{f}); err != nil {
			return fmt.Errorf("persist threat finding: %w", err)
		}
		candidateID := f.ID
		f, err = s.canonicalProjection(writeCtx, j.EngagementID, f.DedupKey)
		if err != nil {
			return &ports.PartialWriteError{Operation: "threat finding", IDs: []shared.ID{candidateID}, Err: err}
		}
		if err := s.recordAttribution(writeCtx, j.EngagementID, assetID, shared.ID("threat:"+j.ID.String()), f.ID); err != nil {
			return &ports.PartialWriteError{Operation: "threat finding", IDs: []shared.ID{f.ID}, Err: err}
		}
		// Attribute the promotion to the human VERIFIER who ratified the threat (the trigger), not the agent
		// that originally proposed the judgment – the judgment's own verdict audit already records the proposer.
		if err := s.record(writeCtx, verifier, "finding.threat_promoted", j.EngagementID, f.ID,
			map[string]string{"judgment": j.ID.String(), "category": string(tc.Category), "element": j.SubjectID.String()}); err != nil {
			return &ports.PartialWriteError{Operation: "threat finding", IDs: []shared.ID{f.ID}, Err: err}
		}
		if created {
			return s.appendFindingCreated(writeCtx, tenantID, f, "", verifier)
		}
		return nil
	})
}

// RecordConfirmedSAST promotes a verifier-confirmed CapSAST (taint) judgment to a persisted Kind=sast
// finding (auto-emit on confirm). Idempotent via the sast:ai:<judgmentID> dedup key – a re-confirm
// updates in place. The finding is built DETERMINISTICALLY from the typed SASTClaim (no LLM);
// severity starts Unknown so a human triages it through the normal finding workflow. Audited.
func (s *Service) RecordConfirmedSAST(ctx context.Context, verifier string, j judgment.Judgment) error {
	if j.Capability != judgment.CapSAST {
		return fmt.Errorf("%w: not a sast judgment (%s)", shared.ErrValidation, j.Capability)
	}
	if !j.Publishable() {
		return fmt.Errorf("%w: sast judgment %s is not publishable", shared.ErrValidation, j.ID)
	}
	sc, ok := j.Claim.(judgment.SASTClaim)
	if !ok {
		return fmt.Errorf("%w: sast judgment %s carries no SASTClaim", shared.ErrValidation, j.ID)
	}
	assetID, err := s.projectionAssetID(ctx, j, sc.AssetID)
	if err != nil {
		return err
	}
	f, err := finding.NewSAST(s.ids.NewID(), j.EngagementID, finding.SASTInput{
		JudgmentID: j.ID.String(),
		CWE:        sc.CWE,
		Location:   sc.Location,
		Rule:       sc.Rule,
		DataFlow:   findingDataFlowFromClaim(sc.DataFlow),
	}, s.clock.Now())
	if err != nil {
		return err
	}
	return s.withFindingBoundary(ctx, j.EngagementID, func(writeCtx context.Context, tenantID shared.ID) error {
		if err := s.claimProjection(writeCtx, j.EngagementID, j.ID, ports.FindingProjectionSAST); err != nil {
			return fmt.Errorf("claim sast finding projection: %w", err)
		}
		created := s.notifications != nil
		if created {
			stored, err := s.findByDedupKey(writeCtx, j.EngagementID, f.DedupKey)
			if err != nil {
				return err
			}
			created = stored.ID.IsZero()
		}
		if err := s.repo.Upsert(writeCtx, []finding.Finding{f}); err != nil {
			return fmt.Errorf("persist sast finding: %w", err)
		}
		candidateID := f.ID
		f, err = s.canonicalProjection(writeCtx, j.EngagementID, f.DedupKey)
		if err != nil {
			return &ports.PartialWriteError{Operation: "sast finding", IDs: []shared.ID{candidateID}, Err: err}
		}
		if err := s.recordAttribution(writeCtx, j.EngagementID, assetID, shared.ID("sast:"+j.ID.String()), f.ID); err != nil {
			return &ports.PartialWriteError{Operation: "sast finding", IDs: []shared.ID{f.ID}, Err: err}
		}
		// Attribute the promotion to the VERIFIER who confirmed the taint judgment (the trigger), not the
		// system proposer – the judgment's own verdict audit already records the proposer.
		if err := s.record(writeCtx, verifier, "finding.sast_promoted", j.EngagementID, f.ID,
			map[string]string{"judgment": j.ID.String(), "cwe": sc.CWE, "rule": sc.Rule, "location": sc.Location}); err != nil {
			return &ports.PartialWriteError{Operation: "sast finding", IDs: []shared.ID{f.ID}, Err: err}
		}
		if created {
			return s.appendFindingCreated(writeCtx, tenantID, f, "", verifier)
		}
		return nil
	})
}

func findingDataFlowFromClaim(claim *judgment.SASTDataFlow) *finding.DataFlowTrace {
	if claim == nil {
		return nil
	}
	location := func(in judgment.SASTFlowLocation) finding.SourceLocation {
		start, end := in.Column, in.Column
		return finding.SourceLocation{
			File: in.File, StartLine: in.Line, EndLine: in.Line, StartColumn: &start, EndColumn: &end,
		}
	}
	steps := make([]finding.SourceLocation, len(claim.Steps))
	for i := range claim.Steps {
		steps[i] = location(claim.Steps[i])
	}
	return &finding.DataFlowTrace{
		Language: claim.Language, Source: location(claim.Source), Sink: location(claim.Sink), Steps: steps,
		CoverageComplete: claim.CoverageComplete, GraphTruncated: claim.GraphTruncated,
	}
}

// RecordConfirmedDAST promotes a RUNTIME-verifier-confirmed CapSAST judgment to a persisted Kind=dast
// finding (auto-emit on runtime confirm). It is the runtime twin of RecordConfirmedSAST — the same
// verifier-confirmed CapSAST judgment, but the confirming verdict came from a safe runtime probe rather
// than a static/LLM verifier, so it projects to a distinct, dynamically-proven Kind=dast finding.
// Idempotent via the dast:ai:<judgmentID> dedup key – a re-confirm updates in place. The finding is built
// DETERMINISTICALLY from the typed SASTClaim (no LLM); severity starts Unknown so a human triages it
// through the normal finding workflow. Audited.
func (s *Service) RecordConfirmedDAST(ctx context.Context, verifier string, j judgment.Judgment) error {
	in := finding.DASTInput{JudgmentID: j.ID.String()}
	var assetID shared.ID
	claimProjection := false
	switch claim := j.Claim.(type) {
	case judgment.DASTClaim:
		if j.Capability != judgment.CapDAST {
			return fmt.Errorf("%w: DAST claim has capability %s", shared.ErrValidation, j.Capability)
		}
		in.CWE, in.Location, in.Rule = claim.CWE, claim.Location, claim.Rule
		in.Source, in.Fingerprint = claim.Source, claim.Fingerprint
	case judgment.SASTClaim:
		if !j.Publishable() {
			return fmt.Errorf("%w: sast judgment %s is not publishable", shared.ErrValidation, j.ID)
		}
		if j.Capability != judgment.CapSAST {
			return fmt.Errorf("%w: SAST claim has capability %s", shared.ErrValidation, j.Capability)
		}
		in.CWE, in.Location, in.Rule = claim.CWE, claim.Location, claim.Rule
		var err error
		assetID, err = s.projectionAssetID(ctx, j, claim.AssetID)
		if err != nil {
			return err
		}
		claimProjection = true
	default:
		return fmt.Errorf("%w: DAST judgment %s carries no supported DAST claim", shared.ErrValidation, j.ID)
	}

	f, err := finding.NewDAST(s.ids.NewID(), j.EngagementID, in, s.clock.Now())
	if err != nil {
		return err
	}
	return s.withFindingBoundary(ctx, j.EngagementID, func(writeCtx context.Context, tenantID shared.ID) error {
		if claimProjection {
			if err := s.claimProjection(writeCtx, j.EngagementID, j.ID, ports.FindingProjectionDAST); err != nil {
				return fmt.Errorf("claim dast finding projection: %w", err)
			}
		}
		created := s.notifications != nil
		if created {
			stored, err := s.findByDedupKey(writeCtx, j.EngagementID, f.DedupKey)
			if err != nil {
				return err
			}
			created = stored.ID.IsZero()
		}
		if err := s.repo.Upsert(writeCtx, []finding.Finding{f}); err != nil {
			return fmt.Errorf("persist dast finding: %w", err)
		}
		candidateID := f.ID
		f, err = s.canonicalProjection(writeCtx, j.EngagementID, f.DedupKey)
		if err != nil {
			return &ports.PartialWriteError{Operation: "dast finding", IDs: []shared.ID{candidateID}, Err: err}
		}
		if err := s.recordAttribution(writeCtx, j.EngagementID, assetID, shared.ID("dast:"+j.ID.String()), f.ID); err != nil {
			return &ports.PartialWriteError{Operation: "dast finding", IDs: []shared.ID{f.ID}, Err: err}
		}
		if err := s.record(writeCtx, verifier, "finding.dast_promoted", j.EngagementID, f.ID,
			map[string]string{"judgment": j.ID.String(), "cwe": in.CWE, "rule": in.Rule, "location": in.Location}); err != nil {
			return &ports.PartialWriteError{Operation: "dast finding", IDs: []shared.ID{f.ID}, Err: err}
		}
		if created {
			return s.appendFindingCreated(writeCtx, tenantID, f, "", verifier)
		}
		return nil
	})
}

func (s *Service) claimProjection(ctx context.Context, engagementID, judgmentID shared.ID, mode ports.FindingProjectionMode) error {
	if s.claimer == nil {
		return fmt.Errorf("%w: finding projection claim is not configured", shared.ErrValidation)
	}
	tenantID := shared.ID("default")
	if s.engagements != nil {
		eng, err := s.engagements.GetByID(ctx, engagementID)
		if err != nil {
			return fmt.Errorf("load projection engagement: %w", err)
		}
		tenantID = shared.TenantOrDefault(eng.TenantID)
	}
	return s.claimer.ClaimFindingProjection(ctx, tenantID, engagementID, judgmentID, mode)
}

func (s *Service) canonicalProjection(ctx context.Context, engagementID shared.ID, dedupKey string) (finding.Finding, error) {
	stored, err := s.findByDedupKey(ctx, engagementID, dedupKey)
	if err != nil {
		return finding.Finding{}, err
	}
	if stored.ID.IsZero() {
		return finding.Finding{}, fmt.Errorf("%w: persisted projection %q was not found", shared.ErrNotFound, dedupKey)
	}
	return stored, nil
}

func (s *Service) projectionAssetID(ctx context.Context, j judgment.Judgment, explicit shared.ID) (shared.ID, error) {
	if s.attributor == nil {
		return "", nil
	}
	if j.SubjectKind == judgment.SubjectFinding && !j.SubjectID.IsZero() {
		return s.attributor.InheritedAssetID(ctx, j.EngagementID, []shared.ID{j.SubjectID})
	}
	if explicit.IsZero() {
		return "", fmt.Errorf("%w: standalone %s finding projection requires asset id", shared.ErrValidation, j.Capability)
	}
	if err := s.attributor.ValidateAsset(ctx, j.EngagementID, explicit); err != nil {
		return "", err
	}
	return explicit, nil
}

func (s *Service) recordAttribution(ctx context.Context, engagementID, assetID, provenance, findingID shared.ID) error {
	if assetID.IsZero() {
		return nil
	}
	if err := s.attributor.Record(ctx, engagementID, assetID, provenance, provenance, asset.EdgeObserved, []shared.ID{findingID}); err != nil {
		return fmt.Errorf("record finding attribution: %w", err)
	}
	return nil
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
	var f finding.Finding
	err := s.withCreationBoundary(ctx, engagementID, func(writeCtx context.Context, tenantID shared.ID, project bool) error {
		var err error
		f, err = finding.NewManual(s.ids.NewID(), engagementID, in, s.clock.Now())
		if err != nil {
			return err
		}
		if err := s.repo.Upsert(writeCtx, []finding.Finding{f}); err != nil {
			return fmt.Errorf("persist finding: %w", err)
		}
		if err := s.record(writeCtx, actor, "finding.created", engagementID, f.ID,
			map[string]string{"severity": string(f.Severity), "kind": string(f.Kind)}); err != nil {
			return err
		}
		if err := s.appendFindingCreated(writeCtx, tenantID, f, "", actor); err != nil {
			return err
		}
		if project {
			return s.shadow.ProjectCreatedFinding(writeCtx, tenantID, f, actor)
		}
		return nil
	})
	return f, err
}

func (s *Service) withCreationBoundary(ctx context.Context, engagementID shared.ID, write func(context.Context, shared.ID, bool) error) error {
	needsShadow := s.shadowTx != nil && s.shadow != nil && s.shadowOn != nil
	if !needsShadow && s.notificationTx == nil {
		return write(ctx, "", false)
	}
	tenantID, err := s.findingTenant(ctx, engagementID)
	if err != nil {
		return err
	}
	project := needsShadow && s.shadowOn(tenantID.String())
	if !project && s.notificationTx == nil {
		return write(ctx, tenantID, false)
	}
	runner := s.notificationTx
	if runner == nil {
		runner = s.shadowTx
	}
	return runner.Run(ctx, tenantID, func(txCtx context.Context) error {
		return write(txCtx, tenantID, project)
	})
}

// withFindingBoundary wraps mutations that can emit a finding source record. It
// deliberately keeps legacy callers unmodified until notification capture is
// wired, while capture-enabled writes always share one tenant transaction.
func (s *Service) withFindingBoundary(ctx context.Context, engagementID shared.ID, write func(context.Context, shared.ID) error) error {
	if s.notificationTx == nil || s.notifications == nil {
		return write(ctx, "")
	}
	tenantID, err := s.findingTenant(ctx, engagementID)
	if err != nil {
		return err
	}
	return s.notificationTx.Run(ctx, tenantID, func(txCtx context.Context) error {
		return write(txCtx, tenantID)
	})
}

func (s *Service) findingTenant(ctx context.Context, engagementID shared.ID) (shared.ID, error) {
	if s.engagements == nil {
		return "", fmt.Errorf("%w: engagement tenant resolver is required", shared.ErrValidation)
	}
	engagement, err := s.engagements.GetByID(ctx, engagementID)
	if err != nil {
		return "", err
	}
	tenantID := shared.TenantOrDefault(engagement.TenantID)
	if current, ok := shared.TenantFrom(ctx); ok && shared.TenantOrDefault(current) != tenantID {
		return "", fmt.Errorf("%w: finding engagement belongs to another tenant", shared.ErrValidation)
	}
	return tenantID, nil
}

func (s *Service) appendFindingCreated(ctx context.Context, tenantID shared.ID, f finding.Finding, engagementName, actor string) error {
	return s.appendFindingEvent(ctx, tenantID, notification.EventFindingCreated, "finding_created", f.ID.String(), f, engagementName, actor, map[string]any{
		"title": "Finding created", "summary": "A finding was created.",
		"finding_id": f.ID, "engagement_id": f.EngagementID, "finding_kind": f.Kind,
		"status": f.Status, "finding_version": f.Version,
	})
}

func (s *Service) appendFindingStatusChanged(ctx context.Context, tenantID shared.ID, f finding.Finding, from finding.Status, engagementName, actor string) error {
	return s.appendFindingEvent(ctx, tenantID, notification.EventFindingStatusChanged, "finding_status", f.ID.String()+":"+fmt.Sprint(f.Version), f, engagementName, actor, map[string]any{
		"title": "Finding status changed", "summary": "A finding status changed.",
		"finding_id": f.ID, "engagement_id": f.EngagementID, "finding_kind": f.Kind,
		"from_status": from, "to_status": f.Status, "status": f.Status, "finding_version": f.Version,
	})
}

func (s *Service) appendFindingRetestCompleted(ctx context.Context, tenantID shared.ID, rt finding.Retest, f finding.Finding, from finding.Status, engagementName, actor string) error {
	return s.appendFindingEvent(ctx, tenantID, notification.EventFindingRetestCompleted, "finding_retest", rt.ID.String(), f, engagementName, actor, map[string]any{
		"title": "Finding retest completed", "summary": "A finding retest was completed.",
		"finding_id": f.ID, "engagement_id": f.EngagementID, "finding_kind": f.Kind,
		"from_status": from, "to_status": f.Status, "status": f.Status, "retest_id": rt.ID,
		"result": rt.Outcome, "finding_version": f.Version,
	})
}

func (s *Service) appendFindingCommented(ctx context.Context, tenantID shared.ID, c finding.Comment, f finding.Finding, actor string) error {
	excerpt := privacy.ScrubURLCredentials(notification.ScrubPersonalText(c.Body, 500))
	return s.appendFindingEvent(ctx, tenantID, notification.EventFindingCommented, "finding_comment", c.ID.String(), f, "", actor, map[string]any{
		"title": "Finding comment added", "summary": "A comment was added to a finding.",
		"finding_id": f.ID, "engagement_id": f.EngagementID, "status": f.Status,
		"comment_id": c.ID, "comment_excerpt": excerpt,
	})
}

func (s *Service) appendFindingMentioned(ctx context.Context, tenantID shared.ID, c finding.Comment, f finding.Finding, mentioned shared.ID) error {
	return s.appendFindingEvent(ctx, tenantID, notification.EventFindingMentioned, "finding_mention", c.ID.String()+":"+mentioned.String(), f, "", c.Author, map[string]any{
		"title": "You were mentioned on a finding", "summary": "You were mentioned in a finding comment.",
		"finding_id": f.ID, "engagement_id": f.EngagementID, "status": f.Status,
		"comment_id": c.ID, "mentioned_user_id": mentioned,
	})
}

func (s *Service) appendFindingEvent(ctx context.Context, tenantID shared.ID, eventType notification.EventType, sourceKind, sourceID string, f finding.Finding, engagementName, actor string, data map[string]any) error {
	if s.notifications == nil {
		return nil
	}
	if engagementName == "" {
		engagement, err := s.engagements.GetByID(ctx, f.EngagementID)
		if err != nil {
			return fmt.Errorf("load finding notification engagement: %w", err)
		}
		if shared.TenantOrDefault(engagement.TenantID) != tenantID {
			return fmt.Errorf("%w: finding notification engagement belongs to another tenant", shared.ErrValidation)
		}
		engagementName = engagement.Name
	}
	facts, err := s.notificationFacts.SnapshotFindingNotificationFacts(ctx, tenantID, f.EngagementID, f.ID, f.AssigneeUserID, actor)
	if err != nil {
		return fmt.Errorf("snapshot finding notification identities: %w", err)
	}
	if eventType == notification.EventFindingCommented {
		data["lead_user_id"] = facts.LeadUserID.String()
	}
	if !facts.ActorUserID.IsZero() {
		data["actor_user_id"] = facts.ActorUserID
	}
	if !facts.AssigneeUserID.IsZero() {
		data["assignee_user_id"] = facts.AssigneeUserID
	}
	if !facts.TeamID.IsZero() {
		data["team_id"] = facts.TeamID
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode finding notification data: %w", err)
	}
	vars := map[string]string{
		"finding_title": f.Title, "engagement_name": engagementName, "severity": string(f.Severity),
		"finding_kind": string(f.Kind), "status": string(f.Status),
	}
	if facts.ActorName != "" {
		vars["actor"] = facts.ActorName
	}
	for _, name := range []string{"from_status", "to_status", "result"} {
		if value, ok := data[name]; ok {
			vars[name] = fmt.Sprint(value)
		}
	}
	if excerpt, ok := data["comment_excerpt"]; ok {
		vars["comment_excerpt"] = privacy.ScrubURLCredentials(notification.ScrubPersonalText(fmt.Sprint(excerpt), 500))
	}
	record, err := notification.SnapshotSourceRecord(notification.SourceRecord{
		TenantID: tenantID, SourceKind: sourceKind, SourceID: sourceID, EventType: eventType,
		EngagementID: f.EngagementID, Severity: f.Severity, OccurredAt: s.clock.Now(), Data: raw,
		SubjectKind: "finding", SubjectID: f.ID.String(),
	}, vars)
	if err != nil {
		return fmt.Errorf("snapshot finding notification: %w", err)
	}
	if err := s.notifications.Append(ctx, record); err != nil {
		return fmt.Errorf("append finding notification: %w", err)
	}
	return nil
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
	var updated finding.Finding
	err := s.withFindingBoundary(ctx, engagementID, func(writeCtx context.Context, tenantID shared.ID) error {
		// Evidence gate: an exploitation/AI finding may not be promoted to
		// CONFIRMED until its claim clears the evidence bar (>= 75). SCA/recon/manual
		// findings are not gated (CanPromote returns true for them).
		current, loadErr := s.loadFinding(writeCtx, engagementID, findingID)
		if loadErr != nil && s.notifications != nil {
			return fmt.Errorf("read finding status notification facts: %w", loadErr)
		}
		if loadErr == nil && status == finding.StatusConfirmed && !current.CanPromote() {
			return fmt.Errorf("%w: %s finding cannot be confirmed below the evidence bar (score %d < %d)",
				shared.ErrValidation, current.Kind, current.EvidenceScore, finding.EvidenceThreshold)
		}
		var err error
		updated, err = s.repo.UpdateStatus(writeCtx, engagementID, findingID, status, expectedVersion)
		if err != nil {
			return err
		}
		meta := map[string]string{"status": string(status)}
		if note != "" {
			meta["note"] = note
		}
		if err := s.record(writeCtx, actor, "finding.status", engagementID, findingID, meta); err != nil {
			return err
		}
		if loadErr == nil && current.Status != updated.Status {
			if err := s.appendFindingStatusChanged(writeCtx, tenantID, updated, current.Status, "", actor); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return finding.Finding{}, err
	}
	return updated, nil
}

// ApplyAITriageReview applies the human's decision to the authoritative finding.
// Accept means the reviewer accepts the AI false-positive recommendation; Reject
// explicitly reopens the finding so it is counted by subsequent gates.
func (s *Service) ApplyAITriageReview(ctx context.Context, actor string, engagementID, findingID shared.ID, accepted bool, rationale string) error {
	current, err := s.loadFinding(ctx, engagementID, findingID)
	if err != nil {
		return err
	}
	target := finding.StatusOpen
	if accepted {
		target = finding.StatusFalsePos
	}
	if current.Status == target {
		return nil
	}
	if _, err := s.UpdateStatus(ctx, engagementID, findingID, target, rationale, actor, current.Version); err != nil {
		return err
	}
	return nil
}

// SetAssignee assigns/unassigns a finding with the same optimistic-concurrency
// guard, then audits it.
func (s *Service) SetAssignee(ctx context.Context, engagementID, findingID shared.ID, assignee, actor string, expectedVersion int) (finding.Finding, error) {
	if s.assigneeWriter != nil {
		return s.assigneeWriter.SetLegacyAssignee(ctx, engagementID, findingID, assignee, actor, expectedVersion)
	}
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
	return s.AddCommentWithMentions(ctx, engagementID, findingID, body, actor, nil)
}

// AddCommentWithMentions stores a native comment plus an immutable canonical
// mention relation. Mention syntax is a transport concern: only explicit user
// IDs supplied by the caller reach this method.
func (s *Service) AddCommentWithMentions(ctx context.Context, engagementID, findingID shared.ID, body, actor string, mentioned []shared.ID) (finding.Comment, error) {
	if len(mentioned) != 0 {
		if s.notificationTx == nil || s.notifications == nil || s.notificationFacts == nil {
			return finding.Comment{}, fmt.Errorf("%w: mention capture dependencies are required", shared.ErrValidation)
		}
		if _, ok := s.comments.(ports.CommentMentionRepository); !ok {
			return finding.Comment{}, fmt.Errorf("%w: comment mention persistence is required", shared.ErrValidation)
		}
	}
	var c finding.Comment
	err := s.withFindingBoundary(ctx, engagementID, func(writeCtx context.Context, tenantID shared.ID) error {
		canonicalMentions, err := s.validateMentionUsers(writeCtx, engagementID, mentioned)
		if err != nil {
			return err
		}
		f, err := s.loadFinding(writeCtx, engagementID, findingID)
		if err != nil {
			return err
		}
		c, err = finding.NewComment(s.ids.NewID(), engagementID, findingID, actor, body, s.clock.Now())
		if err != nil {
			return err
		}
		c.MentionUserIDs = append([]shared.ID(nil), canonicalMentions...)
		if repository, ok := s.comments.(ports.CommentMentionRepository); ok {
			err = repository.AddWithMentions(writeCtx, c, canonicalMentions)
		} else {
			err = s.comments.Add(writeCtx, c)
		}
		if err != nil {
			return fmt.Errorf("persist comment: %w", err)
		}
		if s.notifications == nil {
			return s.record(writeCtx, actor, "finding.comment", engagementID, findingID, nil)
		}
		if err := s.appendFindingCommented(writeCtx, tenantID, c, f, actor); err != nil {
			return err
		}
		for _, userID := range canonicalMentions {
			if err := s.appendFindingMentioned(writeCtx, tenantID, c, f, userID); err != nil {
				return err
			}
		}
		return s.record(writeCtx, actor, "finding.comment", engagementID, findingID, nil)
	})
	if err != nil {
		return finding.Comment{}, err
	}
	return c, nil
}

func (s *Service) validateMentionUsers(ctx context.Context, engagementID shared.ID, mentioned []shared.ID) ([]shared.ID, error) {
	if len(mentioned) == 0 {
		return nil, nil
	}
	if s.mentionUsers == nil {
		return nil, fmt.Errorf("%w: mention users must contain at most 10 canonical active users", shared.ErrValidation)
	}
	tenantID, err := s.findingTenant(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	unique := make(map[shared.ID]bool, len(mentioned))
	result := make([]shared.ID, 0, len(mentioned))
	for _, userID := range mentioned {
		if userID.IsZero() {
			return nil, fmt.Errorf("%w: mentioned user is not an active viewer", shared.ErrValidation)
		}
		if unique[userID] {
			continue
		}
		if len(result) == 10 {
			return nil, fmt.Errorf("%w: mention users must contain at most 10 canonical active users", shared.ErrValidation)
		}
		candidate, err := s.mentionUsers.GetByID(ctx, tenantID, userID)
		if err != nil {
			return nil, fmt.Errorf("%w: mentioned user is not an active viewer", shared.ErrValidation)
		}
		if candidate.Disabled || !candidate.Role.Valid() || !candidate.Role.Can(user.PermView) {
			return nil, fmt.Errorf("%w: mentioned user is not an active viewer", shared.ErrValidation)
		}
		unique[userID] = true
		result = append(result, userID)
	}
	return result, nil
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
	var updated finding.Finding
	err = s.withFindingBoundary(ctx, engagementID, func(writeCtx context.Context, tenantID shared.ID) error {
		var current finding.Finding
		if s.notifications != nil {
			var err error
			current, err = s.loadFinding(writeCtx, engagementID, findingID)
			if err != nil {
				return err
			}
		}
		var err error
		updated, err = s.repo.UpdateStatus(writeCtx, engagementID, findingID, outcome.ResultingStatus(), expectedVersion)
		if err != nil {
			return err
		}
		if err := s.retests.Add(writeCtx, rt); err != nil {
			return fmt.Errorf("persist retest: %w", err)
		}
		if err := s.record(writeCtx, actor, "finding.retest", engagementID, findingID,
			map[string]string{"outcome": string(outcome), "status": string(outcome.ResultingStatus())}); err != nil {
			return err
		}
		if s.notifications != nil && current.Status != updated.Status {
			if err := s.appendFindingStatusChanged(writeCtx, tenantID, updated, current.Status, "", actor); err != nil {
				return err
			}
		}
		if s.notifications != nil {
			return s.appendFindingRetestCompleted(writeCtx, tenantID, rt, updated, current.Status, "", actor)
		}
		return nil
	})
	if err != nil {
		return finding.Retest{}, finding.Finding{}, err
	}
	return rt, updated, nil
}

// Retests returns a finding's retest history (oldest first), scoped to the engagement.
func (s *Service) Retests(ctx context.Context, engagementID, findingID shared.ID) ([]finding.Retest, error) {
	return s.retests.ListByEngagementFinding(ctx, engagementID, findingID)
}

// loadFinding reads the indexed, engagement-scoped canonical finding.
func (s *Service) loadFinding(ctx context.Context, engagementID, findingID shared.ID) (finding.Finding, error) {
	return s.repo.GetByEngagementAndID(ctx, engagementID, findingID)
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
