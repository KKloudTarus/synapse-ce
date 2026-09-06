// Package dastworkflow coordinates the governed DAST verification lifecycle.
//
// It deliberately reuses Synapse's existing approval and safety gate primitives instead of
// inventing a second approval path: propose creates an intrusive, approval-required action; decide
// records a human decision; run re-admits the decided action through safety.Gate and then calls the
// safe dastrunner.
package dastworkflow

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastrunner"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

type Service struct {
	gate          *safety.Gate
	approvals     *approval.Service
	store         ports.ApprovalStore
	runner        *dastrunner.Service
	clock         ports.Clock
	ids           ports.IDGenerator
	session       scanSession
	helperBin     string
	evidence      *evidence.Service
	ceilings      ScanCeilings
	evaluator     ports.DASTCheckEvaluator
	proofVerifier ports.DASTProofVerifier
	judgments     scanJudgmentProposer
	verifier      scanProofVerifier
}

func NewService(gate *safety.Gate, approvals *approval.Service, store ports.ApprovalStore, runner *dastrunner.Service, ev *evidence.Service, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if gate == nil || approvals == nil || store == nil || runner == nil || ev == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: dast workflow requires gate, approvals, store, runner, evidence, clock, and ids", shared.ErrValidation)
	}
	return &Service{gate: gate, approvals: approvals, store: store, runner: runner, evidence: ev, clock: clock, ids: ids}, nil
}

type Proposal struct {
	Action   agent.ProposedAction   `json:"action"`
	Decision agent.ApprovalDecision `json:"decision"`
}

func (s *Service) Propose(ctx context.Context, actor string, engagementID shared.ID, probe dastrunner.Probe) (Proposal, error) {
	if actor == "" {
		return Proposal{}, fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	if engagementID == "" || probe.JudgmentID == "" {
		return Proposal{}, fmt.Errorf("%w: engagement id and judgment id are required", shared.ErrValidation)
	}
	method := strings.ToUpper(strings.TrimSpace(probe.Method))
	if method == "" {
		method = "GET"
	}
	probe.URL = strings.TrimSpace(probe.URL)
	if err := validateDASTURL(probe.URL); err != nil {
		return Proposal{}, err
	}
	p := agent.ProposedAction{
		ID:           s.ids.NewID(),
		SessionID:    shared.ID("dast:" + probe.JudgmentID.String()),
		EngagementID: engagementID,
		Tool:         dastrunner.ToolRunDASTVerifier,
		Action:       dastrunner.ActionSafeHTTPProbe,
		Target:       engagement.Target{Kind: engagement.TargetURL, Value: probe.URL},
		Argv:         []string{"synapse-dast-probe", "--config-sha256=" + probeDigest(probe, method)},
		Risk:         agent.RiskIntrusive,
		Rationale:    strings.TrimSpace(probe.Rationale),
		ProposedAt:   s.clock.Now(),
	}
	if p.Rationale == "" {
		p.Rationale = "runtime verifier proof requested for " + probe.JudgmentID.String()
	}
	_, err := s.gate.Admit(ctx, p, actor)
	if err != nil && !errors.Is(err, safety.ErrPendingApproval) {
		return Proposal{}, err
	}
	_, dec, gerr := s.store.Get(ctx, p.ID)
	if gerr != nil {
		return Proposal{}, gerr
	}
	return Proposal{Action: p, Decision: dec}, nil
}
func (s *Service) Decide(ctx context.Context, human string, engagementID, actionID shared.ID, approve bool, reason string) (agent.ApprovalDecision, error) {
	p, _, err := s.store.Get(ctx, actionID)
	if err != nil {
		return agent.ApprovalDecision{}, err
	}
	if p.EngagementID != engagementID || !isDASTAction(p) {
		return agent.ApprovalDecision{}, fmt.Errorf("%w: DAST approval not found for this engagement", shared.ErrNotFound)
	}
	return s.approvals.Decide(ctx, human, actionID, approve, reason)
}

func (s *Service) Run(ctx context.Context, actor string, engagementID, actionID shared.ID, probe dastrunner.Probe) (dastrunner.Result, error) {
	p, _, err := s.store.Get(ctx, actionID)
	if err != nil {
		return dastrunner.Result{}, err
	}
	if p.EngagementID != engagementID || p.Tool != dastrunner.ToolRunDASTVerifier || p.Action != dastrunner.ActionSafeHTTPProbe {
		return dastrunner.Result{}, fmt.Errorf("%w: DAST approval not found for this engagement", shared.ErrNotFound)
	}
	method := strings.ToUpper(strings.TrimSpace(probe.Method))
	if method == "" {
		method = "GET"
	}
	if err := validateDASTURL(probe.URL); err != nil {
		return dastrunner.Result{}, err
	}
	if len(p.Argv) != 2 || p.Argv[0] != "synapse-dast-probe" || subtle.ConstantTimeCompare([]byte(p.Argv[1]), []byte("--config-sha256="+probeDigest(probe, method))) != 1 {
		return dastrunner.Result{}, fmt.Errorf("%w: DAST approval does not bind this probe configuration", shared.ErrValidation)
	}
	adm, err := s.gate.Admit(ctx, p, actor)
	if err != nil {
		return dastrunner.Result{}, err
	}
	if err := s.consume(ctx, engagementID, actionID, actor); err != nil {
		return dastrunner.Result{}, err
	}
	return s.runner.Execute(ctx, adm, probe)
}

func (s *Service) consume(ctx context.Context, engagementID, actionID shared.ID, actor string) error {
	if err := s.store.Consume(ctx, actionID); err != nil {
		if errors.Is(err, shared.ErrConflict) {
			return fmt.Errorf("%w: DAST approval was already consumed", shared.ErrForbidden)
		}
		return err
	}
	payload := fmt.Appendf(nil, `{"action_id":%q,"actor":%q}`, actionID.String(), actor)
	if _, err := s.evidence.Seal(ctx, engagementID, "agent_approval_consumed", payload, actor); err != nil {
		return fmt.Errorf("seal DAST approval consumption: %w", err)
	}
	return nil
}

func isDASTAction(p agent.ProposedAction) bool {
	return (p.Tool == dastrunner.ToolRunDASTVerifier && p.Action == dastrunner.ActionSafeHTTPProbe) || (p.Tool == ToolAuthenticatedScan && p.Action == ActionAuthenticatedScan)
}

func probeDigest(probe dastrunner.Probe, method string) string {
	payload := strings.Join([]string{probe.JudgmentID.String(), probe.URL, method, fmt.Sprint(probe.ExpectedStatus), probe.ExpectedBodyContains, fmt.Sprint(probe.ScoreIfConfirmed), fmt.Sprint(probe.ScoreIfRefuted), fmt.Sprint(probe.ExpectedVersion), probe.Rationale}, "\n")
	digest := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(digest[:])
}

// validateDASTURL delegates to dastrunner.ValidateURL, the single source of truth for probe-target
// validation, so the durable submit edge and the execution edge reject exactly the same URLs.
func validateDASTURL(raw string) error {
	return dastrunner.ValidateURL(raw)
}
