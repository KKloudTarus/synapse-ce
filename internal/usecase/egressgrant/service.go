// Package egressgrant authorizes short-lived, process-bound egress grants from
// authoritative execution and engagement state. Workers may request a grant but
// cannot choose the policy that the control plane signs.
package egressgrant

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	ExecutionKindRecon = "recon"
	GrantLifetime      = time.Minute
)

type CanonicalRule = ports.CanonicalEgressRule

type Request = ports.EgressGrantRequest

type Signer = ports.EgressGrantSigner

type PolicyCanonicalizer = ports.EgressPolicyCanonicalizer

type ReconRunReader interface {
	Get(context.Context, shared.ID) (recon.Run, error)
}

type Service struct {
	runs          ReconRunReader
	engagements   ports.EngagementRepository
	guard         ports.ExecutionAuthorizer
	clock         ports.Clock
	tools         map[string]ports.ReconTool
	compiler      ports.EgressPolicyCompiler
	canonicalizer PolicyCanonicalizer
	signer        Signer
}

func NewService(runs ReconRunReader, engagements ports.EngagementRepository, guard ports.ExecutionAuthorizer, clock ports.Clock, tools map[string]ports.ReconTool, compiler ports.EgressPolicyCompiler, canonicalizer ports.EgressPolicyCanonicalizer, signer ports.EgressGrantSigner) (*Service, error) {
	if runs == nil || engagements == nil || guard == nil || clock == nil || compiler == nil || canonicalizer == nil || signer == nil || len(tools) == 0 {
		return nil, errors.New("egress grant service requires runs, engagements, guard, clock, tools, compiler, canonicalizer, and signer")
	}
	return &Service{runs: runs, engagements: engagements, guard: guard, clock: clock, tools: tools, compiler: compiler, canonicalizer: canonicalizer, signer: signer}, nil
}

func (s *Service) Authorize(ctx context.Context, req Request) (string, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || strings.TrimSpace(req.TenantID) == "" || req.TenantID != tenantID.String() {
		return "", fmt.Errorf("%w: egress grant tenant context is missing or mismatched", shared.ErrValidation)
	}
	if req.ExecutionKind != ExecutionKindRecon {
		return "", fmt.Errorf("%w: unsupported egress execution kind %q", shared.ErrValidation, req.ExecutionKind)
	}
	if strings.TrimSpace(req.ExecutionID) == "" || req.ExecutionID != strings.TrimSpace(req.ExecutionID) {
		return "", fmt.Errorf("%w: invalid egress execution id", shared.ErrValidation)
	}

	run, err := s.runs.Get(ctx, shared.ID(req.ExecutionID))
	if err != nil {
		return "", fmt.Errorf("load authoritative recon run: %w", err)
	}
	if run.ID.String() != req.ExecutionID || run.Status != recon.StatusRunning {
		return "", fmt.Errorf("%w: recon execution is not running", shared.ErrForbidden)
	}
	eng, err := s.engagements.GetByIDInTenant(ctx, tenantID, run.EngagementID)
	if err != nil {
		return "", fmt.Errorf("load authoritative engagement: %w", err)
	}
	if eng.TenantID != tenantID || !eng.LiveReconEnabled {
		return "", fmt.Errorf("%w: recon execution tenant or live-recon posture is invalid", shared.ErrForbidden)
	}
	tool, ok := s.tools[run.Tool]
	if !ok {
		return "", fmt.Errorf("%w: authoritative recon tool %q is unavailable", shared.ErrValidation, run.Tool)
	}
	target := engagement.Target{Kind: engagement.InferTargetKind(run.Target), Value: run.Target}
	target, err = engagement.NormalizeTarget(target, false)
	if err != nil || !tool.Accepts(target.Kind) {
		return "", fmt.Errorf("%w: authoritative recon target is invalid for tool %q", shared.ErrValidation, run.Tool)
	}
	if _, err := s.guard.Authorize(ctx, ports.ExecutionRequest{
		Actor:        "synapse-egress-authority",
		EngagementID: run.EngagementID,
		Action:       tool.Action(),
		Target:       target,
		Metadata: map[string]string{
			"execution_kind": req.ExecutionKind,
			"execution_id":   req.ExecutionID,
			"grant_run":      req.RunID,
		},
	}); err != nil {
		return "", fmt.Errorf("authorize current execution state: %w", err)
	}

	rules, err := s.canonicalizer.Canonicalize(ctx, s.compiler.Compile(eng.Scope))
	if err != nil {
		return "", fmt.Errorf("derive authoritative egress rules: %w", err)
	}
	if !CanonicalRulesEqual(rules, req.Rules) {
		return "", fmt.Errorf("%w: requested egress rules differ from authoritative scope", shared.ErrForbidden)
	}
	grant, err := s.signer.Sign(req, s.clock.Now(), GrantLifetime)
	if err != nil {
		return "", fmt.Errorf("sign egress grant: %w", err)
	}
	return grant, nil
}

func CanonicalRulesEqual(left, right []CanonicalRule) bool {
	return ports.CanonicalEgressRulesEqual(left, right)
}
