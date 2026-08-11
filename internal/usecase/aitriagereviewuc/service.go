// Package aitriagereviewuc implements the durable human-review workflow for
// AI false-positive recommendations held back by the deterministic policy.
package aitriagereviewuc

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aitriagereview"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Service struct {
	decisionMu  sync.Mutex // API is single-instance; serialize queue refresh and review+finding mutation
	store       ports.AITriageReviewStore
	engagements ports.EngagementRepository
	findings    ports.AITriageFindingDecision
	audit       ports.AuditLogger
	clock       ports.Clock
	ids         ports.IDGenerator
}

func NewService(store ports.AITriageReviewStore, engagements ports.EngagementRepository, findings ports.AITriageFindingDecision, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if store == nil || engagements == nil || findings == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: AI-triage review service requires store, engagements, findings, audit, clock, and ids", shared.ErrValidation)
	}
	return &Service{store: store, engagements: engagements, findings: findings, audit: audit, clock: clock, ids: ids}, nil
}

// RecordScan materializes every ReviewRequired critique after the scan evidence is sealed.
// UpsertPending is idempotent by finding plus policy/prompt/model identity.
func (s *Service) RecordScan(ctx context.Context, engagementID, evidenceRef shared.ID, items []finding.Finding, critiques []ports.AICritique) error {
	s.decisionMu.Lock()
	defer s.decisionMu.Unlock()
	if evidenceRef.IsZero() {
		for _, c := range critiques {
			if c.ReviewRequired {
				return fmt.Errorf("%w: review-required AI triage has no sealed evidence reference", shared.ErrValidation)
			}
		}
		return nil
	}
	e, err := s.engagements.GetByID(ctx, engagementID)
	if err != nil {
		return fmt.Errorf("load review engagement: %w", err)
	}
	byKey := make(map[string]finding.Finding, len(items))
	for _, item := range items {
		byKey[strings.TrimSpace(item.DedupKey)] = item
	}
	for _, c := range critiques {
		if !c.ReviewRequired {
			continue
		}
		item, ok := byKey[strings.TrimSpace(c.DedupKey)]
		if !ok {
			return fmt.Errorf("%w: review-required critique references an unknown finding", shared.ErrValidation)
		}
		review, err := aitriagereview.NewPending(aitriagereview.Input{
			ID: s.ids.NewID(), TenantID: shared.TenantOrDefault(e.TenantID), EngagementID: engagementID,
			ProjectID: e.ProjectID, FindingID: item.ID, EvidenceRef: evidenceRef,
			DedupKey: item.DedupKey, Title: item.Title, Severity: item.Severity, CWE: item.CWE,
			Verdict: c.Verdict, Driver: c.Driver, Confidence: c.Confidence, SuspectedFP: c.SuspectedFP,
			ProposerModel: c.ProposerModel, ProposerProvider: c.ProposerProvider, ProposerModelFamily: c.ProposerModelFamily,
			VerifierModel: c.VerifierModel, VerifierProvider: c.VerifierProvider, VerifierModelFamily: c.VerifierModelFamily,
			IndependencePolicy: string(c.IndependencePolicy), PromptVersion: c.PromptVersion, Verified: c.Verified,
			VerifierVerdict: c.VerifierVerdict, VerifierDriver: c.VerifierDriver, VerifierConfidence: c.VerifierConfidence,
			PolicyVersion: c.PolicyVersion, PolicyReason: c.PolicyReason, Shadow: c.Shadow, WouldGateExempt: c.WouldGateExempt,
			GateExempt: c.GateExempt, ReviewRequired: c.ReviewRequired,
		}, s.clock.Now())
		if err != nil {
			return err
		}
		if err := s.store.UpsertPending(ctx, review); err != nil {
			return fmt.Errorf("persist AI-triage review: %w", err)
		}
	}
	return nil
}

func (s *Service) List(ctx context.Context, tenantID shared.ID, filter ports.AITriageReviewFilter) ([]aitriagereview.Review, error) {
	if filter.Severity != "" && !filter.Severity.Valid() {
		return nil, fmt.Errorf("%w: invalid severity filter", shared.ErrValidation)
	}
	if filter.State != "" && !filter.State.Valid() {
		return nil, fmt.Errorf("%w: invalid state filter", shared.ErrValidation)
	}
	filter.CWE = strings.TrimSpace(filter.CWE)
	return s.store.List(ctx, shared.TenantOrDefault(tenantID), filter)
}

func (s *Service) Decide(ctx context.Context, tenantID, id shared.ID, actor string, decision aitriagereview.Decision, rationale string, expectedVersion int) (aitriagereview.Review, error) {
	s.decisionMu.Lock()
	defer s.decisionMu.Unlock()
	tenantID = shared.TenantOrDefault(tenantID)
	current, err := s.store.Get(ctx, tenantID, id)
	if err != nil {
		return aitriagereview.Review{}, err
	}
	updated, err := current.Decide(decision, actor, rationale, expectedVersion, s.clock.Now())
	if err != nil {
		return aitriagereview.Review{}, err
	}
	accepted := updated.State == aitriagereview.StateAccepted
	auditEntry := ports.AuditEntry{
		Actor: actor, Action: "ai_triage_review." + string(updated.State), Target: id.String(), At: updated.UpdatedAt,
		Metadata: map[string]string{
			"tenant": tenantID.String(), "engagement": updated.EngagementID.String(), "project": updated.ProjectID.String(),
			"finding": updated.FindingID.String(), "decision": string(decision), "policy_version": updated.PolicyVersion,
			"prompt_version": updated.PromptVersion, "proposer_model": updated.ProposerModel,
			"proposer_provider": updated.ProposerProvider, "proposer_model_family": updated.ProposerModelFamily,
			"verifier_model": updated.VerifierModel, "verifier_provider": updated.VerifierProvider,
			"verifier_model_family": updated.VerifierModelFamily, "independence_policy": updated.IndependencePolicy,
			"confidence":          fmt.Sprintf("%d", updated.Confidence),
			"verifier_confidence": fmt.Sprintf("%d", updated.VerifierConfidence), "evidence_ref": updated.EvidenceRef.String(),
			"rationale": updated.DecisionRationale,
		},
	}
	// Accept can remove the finding from subsequent gate counts, so its durable
	// decision and evidence-linked audit must succeed before that mutation. Reject
	// moves in the fail-safe direction (back to gating), so apply it first.
	if accepted {
		if err := s.store.SaveDecision(ctx, updated, expectedVersion); err != nil {
			return aitriagereview.Review{}, fmt.Errorf("persist AI-triage decision: %w", err)
		}
		if err := s.audit.Record(ctx, auditEntry); err != nil {
			return aitriagereview.Review{}, fmt.Errorf("audit AI-triage decision: %w", err)
		}
		if err := s.findings.ApplyAITriageReview(ctx, actor, updated.EngagementID, updated.FindingID, true, updated.DecisionRationale); err != nil {
			return aitriagereview.Review{}, fmt.Errorf("apply AI-triage review to finding: %w", err)
		}
		return updated, nil
	}
	if err := s.findings.ApplyAITriageReview(ctx, actor, updated.EngagementID, updated.FindingID, false, updated.DecisionRationale); err != nil {
		return aitriagereview.Review{}, fmt.Errorf("apply AI-triage review to finding: %w", err)
	}
	if err := s.store.SaveDecision(ctx, updated, expectedVersion); err != nil {
		return aitriagereview.Review{}, fmt.Errorf("persist AI-triage decision: %w", err)
	}
	if err := s.audit.Record(ctx, auditEntry); err != nil {
		return aitriagereview.Review{}, fmt.Errorf("audit AI-triage decision: %w", err)
	}
	return updated, nil
}

func (s *Service) Claim(ctx context.Context, tenantID, id shared.ID, actor string, expectedVersion int) (aitriagereview.Review, error) {
	s.decisionMu.Lock()
	defer s.decisionMu.Unlock()
	tenantID = shared.TenantOrDefault(tenantID)
	current, err := s.store.Get(ctx, tenantID, id)
	if err != nil {
		return aitriagereview.Review{}, err
	}
	updated, err := current.Claim(actor, expectedVersion, s.clock.Now())
	if err != nil {
		return aitriagereview.Review{}, err
	}
	if err := s.store.SaveOwner(ctx, updated, expectedVersion); err != nil {
		return aitriagereview.Review{}, err
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: "ai_triage_review.claimed", Target: id.String(), At: updated.UpdatedAt,
		Metadata: map[string]string{"tenant": tenantID.String(), "engagement": updated.EngagementID.String(), "finding": updated.FindingID.String(), "owner": updated.Owner, "evidence_ref": updated.EvidenceRef.String()}}); err != nil {
		return aitriagereview.Review{}, fmt.Errorf("audit AI-triage review claim: %w", err)
	}
	return updated, nil
}

var _ ports.AITriageReviewRecorder = (*Service)(nil)
