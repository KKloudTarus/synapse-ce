// Package slauc coordinates tenant policy versions, immutable SLA assessments, and human-owned
// remediation transitions. The scoring algorithm stays in domain/sla; this package owns clocks,
// identifiers, persistence, and cross-domain input mapping.
package slauc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityrisk"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const builtInPolicyActor = "system:sla-default"

// Service is safe to share between scan, continuous-intelligence, HTTP, and CLI entry points. The
// store owns transaction/concurrency semantics; all time and IDs enter through ports for replayable
// tests.
type Service struct {
	store ports.SLAStore
	clock ports.Clock
	ids   ports.IDGenerator
}

func NewService(store ports.SLAStore, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if store == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: sla service dependencies are required", shared.ErrValidation)
	}
	return &Service{store: store, clock: clock, ids: ids}, nil
}

var _ ports.SLAAssessor = (*Service)(nil)
var _ ports.FindingSLAAssessor = (*Service)(nil)

// AssessFinding derives the reproducible subset of SLA inputs available on a finding row.
func (s *Service) AssessFinding(ctx context.Context, tenantID shared.ID, item finding.Finding) (sla.View, error) {
	return s.Assess(ctx, sla.AssessmentInput{
		TenantID: tenantID, EngagementID: item.EngagementID, FindingID: item.ID,
		SourceRiskAssessmentID: item.RiskAssessmentID, Risk: InputsFromFinding(item),
	})
}

// Assess evaluates and promotes a current SLA assessment. An idempotent replay returns the existing
// immutable artifact and does not move its deadlines. A materially changed input advances the current
// pointer while the store preserves every human lifecycle field.
func (s *Service) Assess(ctx context.Context, input sla.AssessmentInput) (sla.View, error) {
	tenantID, err := tenantFor(ctx, input.TenantID)
	if err != nil {
		return sla.View{}, err
	}
	input.TenantID = tenantID
	policy, err := s.ensureActivePolicy(ctx, tenantID)
	if err != nil {
		return sla.View{}, err
	}
	candidate, err := sla.Evaluate(input, policy.Config, s.clock.Now().UTC())
	if err != nil {
		return sla.View{}, err
	}
	if _, err := s.store.UpsertAssessment(ctx, candidate); err != nil {
		return sla.View{}, fmt.Errorf("persist sla assessment: %w", err)
	}
	current, err := s.store.Current(ctx, tenantID, input.EngagementID, input.FindingID)
	if err != nil {
		return sla.View{}, fmt.Errorf("load current sla assessment: %w", err)
	}
	return current.View(s.clock.Now().UTC())
}

// Get returns the live overdue/acceptance-expiry projection for one finding.
func (s *Service) Get(ctx context.Context, tenantID, engagementID, findingID shared.ID) (sla.View, error) {
	tenantID, err := tenantFor(ctx, tenantID)
	if err != nil {
		return sla.View{}, err
	}
	current, err := s.store.Current(ctx, tenantID, engagementID, findingID)
	if err != nil {
		return sla.View{}, err
	}
	return current.View(s.clock.Now().UTC())
}

// List returns current SLA views in the deterministic order supplied by the store.
func (s *Service) List(ctx context.Context, tenantID, engagementID shared.ID) ([]sla.View, error) {
	tenantID, err := tenantFor(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	items, err := s.store.ListCurrent(ctx, tenantID, engagementID)
	if err != nil {
		return nil, err
	}
	views := make([]sla.View, 0, len(items))
	now := s.clock.Now().UTC()
	for _, item := range items {
		view, err := item.View(now)
		if err != nil {
			return nil, fmt.Errorf("project stored sla current: %w", err)
		}
		views = append(views, view)
	}
	return views, nil
}

func (s *Service) AssessmentHistory(ctx context.Context, tenantID, engagementID, findingID shared.ID) ([]sla.Assessment, error) {
	tenantID, err := tenantFor(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return s.store.AssessmentHistory(ctx, tenantID, engagementID, findingID)
}

func (s *Service) LifecycleEvents(ctx context.Context, tenantID, engagementID, findingID shared.ID) ([]sla.LifecycleEvent, error) {
	tenantID, err := tenantFor(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return s.store.LifecycleEvents(ctx, tenantID, engagementID, findingID)
}

// Transition applies a human decision under optimistic concurrency and persists its audit event in
// the same store transaction. AI/machine identities are rejected by the domain even if a caller
// bypasses an HTTP permission check.
func (s *Service) Transition(ctx context.Context, tenantID, engagementID, findingID shared.ID, cmd sla.TransitionCommand) (sla.View, error) {
	tenantID, err := tenantFor(ctx, tenantID)
	if err != nil {
		return sla.View{}, err
	}
	current, err := s.store.Current(ctx, tenantID, engagementID, findingID)
	if err != nil {
		return sla.View{}, err
	}
	now := s.clock.Now().UTC()
	next, event, err := sla.ApplyTransition(current.Lifecycle, s.ids.NewID(), cmd, now)
	if err != nil {
		return sla.View{}, err
	}
	if err := s.store.SaveTransition(ctx, next, event); err != nil {
		return sla.View{}, fmt.Errorf("persist sla lifecycle transition: %w", err)
	}
	return sla.NewView(current.Assessment, next, now)
}

// ActivatePolicy appends a validated tenant policy and atomically selects it for future assessments.
// Existing assessments are not rewritten; callers can explicitly reassess findings to adopt it.
func (s *Service) ActivatePolicy(ctx context.Context, tenantID shared.ID, cfg sla.Config, actor string) (sla.Policy, bool, error) {
	tenantID, err := tenantFor(ctx, tenantID)
	if err != nil {
		return sla.Policy{}, false, err
	}
	if shared.IsMachineActor(actor) {
		return sla.Policy{}, false, fmt.Errorf("%w: activating an sla policy requires a human principal", shared.ErrValidation)
	}
	policy, err := sla.NewPolicy(tenantID, cfg, actor, s.clock.Now().UTC())
	if err != nil {
		return sla.Policy{}, false, err
	}
	created, err := s.store.PutPolicy(ctx, policy, true)
	if err != nil {
		return sla.Policy{}, false, err
	}
	active, err := s.store.ActivePolicy(ctx, tenantID)
	return active, created, err
}

func (s *Service) Policies(ctx context.Context, tenantID shared.ID) ([]sla.Policy, error) {
	tenantID, err := tenantFor(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return s.store.PolicyHistory(ctx, tenantID)
}

// ActivePolicy returns the selected tenant policy, installing the built-in version on first use.
func (s *Service) ActivePolicy(ctx context.Context, tenantID shared.ID) (sla.Policy, error) {
	tenantID, err := tenantFor(ctx, tenantID)
	if err != nil {
		return sla.Policy{}, err
	}
	return s.ensureActivePolicy(ctx, tenantID)
}

func (s *Service) ensureActivePolicy(ctx context.Context, tenantID shared.ID) (sla.Policy, error) {
	policy, err := s.store.ActivePolicy(ctx, tenantID)
	if err == nil {
		return policy, nil
	}
	if !errors.Is(err, shared.ErrNotFound) {
		return sla.Policy{}, fmt.Errorf("load active sla policy: %w", err)
	}
	policy, err = sla.NewPolicy(tenantID, sla.DefaultConfig(), builtInPolicyActor, s.clock.Now().UTC())
	if err != nil {
		return sla.Policy{}, err
	}
	if _, err := s.store.PutPolicy(ctx, policy, true); err != nil {
		return sla.Policy{}, fmt.Errorf("install default sla policy: %w", err)
	}
	return s.store.ActivePolicy(ctx, tenantID)
}

func tenantFor(ctx context.Context, requested shared.ID) (shared.ID, error) {
	bound, ok := shared.TenantFrom(ctx)
	if !ok {
		return "", fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	bound, requested = shared.TenantOrDefault(bound), shared.TenantOrDefault(requested)
	if bound != requested {
		return "", fmt.Errorf("%w: sla tenant does not match context", shared.ErrValidation)
	}
	return bound, nil
}

// InputsFromFinding maps durable finding facts into SLA risk signals without inventing asset
// criticality or network exposure. RiskScore is EPSS*CVSS in the finding model, so EPSS can be
// recovered when a valid CVSS vector is present. Unknown context remains neutral by domain design.
func InputsFromFinding(item finding.Finding) sla.Inputs {
	inputs := sla.Inputs{Severity: item.Severity, KEV: item.KEV}
	if score, ok := shared.CVSSv3BaseScore(item.CVSSVector); ok {
		inputs.CVSSScore = score
		if score > 0 && item.RiskScore >= 0 {
			inputs.EPSS = item.RiskScore / score
			if inputs.EPSS > 1 {
				inputs.EPSS = 1
			}
		}
	}
	if strings.TrimSpace(item.FixedVersion) != "" {
		inputs.Feasibility = sla.FeasibilityPatchAvailable
	} else if item.Kind == finding.KindSCA && strings.HasPrefix(strings.TrimSpace(item.DedupKey), "vuln:") {
		inputs.Feasibility = sla.FeasibilityNoPatch
	}
	return inputs
}

// InputsFromRiskAssessment preserves continuous-intelligence signals that are not projected onto
// the finding row (public PoC and active exploitation). Asset context is intentionally left unknown.
func InputsFromRiskAssessment(item vulnerabilityrisk.Assessment) sla.Inputs {
	inputs := sla.Inputs{
		Severity: item.Severity, CVSSScore: item.CVSSScore, KEV: item.KEV, EPSS: item.EPSS,
	}
	for _, reason := range item.ReasonCodes {
		switch strings.TrimSpace(reason) {
		case "public_exploit":
			inputs.PublicPoC = true
		case "active_exploitation":
			inputs.ActiveExploitation = true
		}
	}
	if strings.TrimSpace(item.FixedVersion) != "" {
		inputs.Feasibility = sla.FeasibilityPatchAvailable
	} else {
		inputs.Feasibility = sla.FeasibilityNoPatch
	}
	return inputs
}
