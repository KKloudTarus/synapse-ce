package offensivepolicy

import (
	"context"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
)

// PlanStep is one enumerated action: what would run, against what, and under what authority.
//
// Permitted is the whole point. A dry run that only listed the steps would tell an operator what the
// platform intends but not what it is allowed to do, and the interesting rows are exactly the ones that
// would be refused.
type PlanStep struct {
	Technique   string
	Target      string
	RiskClass   offensivepolicy.RiskClass
	Approval    offensivepolicy.ApprovalMode
	BlastRadius offensivepolicy.Radius
	Cleanup     offensivepolicy.CleanupSpec
	Permitted   bool
	Refusal     string
}

// Plan is the result of a dry run: every step, and nothing executed.
type Plan struct {
	EngagementID string
	Steps        []PlanStep
	// PermittedCount and RefusedCount are stated rather than left to the caller to compute, so a UI or
	// CLI cannot render a plan as "8 steps" while 5 of them would be refused.
	PermittedCount int
	RefusedCount   int
}

// PlanRequest is one intended step, before any authorization has been sought.
type PlanRequest struct {
	Technique string
	Target    string
}

// DryRun enumerates exactly what would execute against what, and executes nothing.
//
// It is part of the policy, not a debug flag (document 9). The Service holds no executor at all, so
// there is no code path from here to a target — the guarantee is structural rather than a matter of
// remembering not to call something. TestPlanExecutesNothing asserts it with an executor that fails the
// test if it is invoked.
//
// A dry run deliberately does NOT seal evidence or count as an authorization: nothing happened, so
// recording an authorization would put a permission in the chain that no action ever used.
func (s *Service) DryRun(ctx context.Context, req Request, steps []PlanRequest) Plan {
	plan := Plan{EngagementID: req.EngagementID.String()}
	if s == nil {
		return plan
	}
	missing := req.RoE.missingFields()
	for _, step := range steps {
		technique := strings.TrimSpace(step.Technique)
		target := strings.TrimSpace(step.Target)
		row := PlanStep{Technique: technique, Target: target}

		policy, ok := s.register.Lookup(technique)
		switch {
		case !ok:
			row.Refusal = "no register entry: the register is an allowlist and this technique is not in it"
		case policy.RiskClass == offensivepolicy.RiskProhibited:
			row.RiskClass, row.BlastRadius = policy.RiskClass, policy.BlastRadius
			row.Refusal = "prohibited category: no scope, window or approval permits this"
		case target == "":
			row.RiskClass, row.Approval, row.BlastRadius = policy.RiskClass, policy.Approval, policy.BlastRadius
			row.Refusal = "no target"
		case len(missing) > 0:
			row.RiskClass, row.Approval, row.BlastRadius = policy.RiskClass, policy.Approval, policy.BlastRadius
			row.Refusal = "engagement is missing required rules of engagement: " + strings.Join(missing, ", ")
		case !offensivepolicy.RiskCeilingPermits(req.RoE.RiskCeiling, policy.RiskClass):
			row.RiskClass, row.Approval, row.BlastRadius = policy.RiskClass, policy.Approval, policy.BlastRadius
			row.Refusal = "above the engagement risk ceiling " + string(req.RoE.RiskCeiling)
		default:
			row.RiskClass, row.Approval, row.BlastRadius, row.Cleanup =
				policy.RiskClass, policy.Approval, policy.BlastRadius, policy.Cleanup
			// The approvals a dry run reports on are the ones recorded SO FAR. A step that still needs a
			// signature is shown as refused with the count outstanding, because that is the operator's
			// next action.
			if _, err := s.validApprovers(policy, technique, target, req); err != nil {
				row.Refusal = err.Error()
			} else {
				row.Permitted = true
			}
		}
		if row.Permitted {
			plan.PermittedCount++
		} else {
			plan.RefusedCount++
		}
		plan.Steps = append(plan.Steps, row)
	}
	// Deterministic order so two dry runs of the same plan read identically and a diff means a change.
	sort.SliceStable(plan.Steps, func(i, j int) bool {
		if plan.Steps[i].Technique != plan.Steps[j].Technique {
			return plan.Steps[i].Technique < plan.Steps[j].Technique
		}
		return plan.Steps[i].Target < plan.Steps[j].Target
	})
	return plan
}
