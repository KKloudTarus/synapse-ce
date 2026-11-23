package httpapi

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/slauc"
)

// seedSLAGovernance wires the real SLA service over the in-memory SLA store and gives finding f1 of
// engagement engA one assessment and one lifecycle transition under tenantA. The four engagement SLA
// routes (list, get, assessment history, lifecycle events) then answer tenantA's rows.
//
// The service never loads the finding: an assessment carries its own risk inputs, so no finding
// repository is needed and this seed stays independent of whatever the findings seed plants. The
// store keys every row by tenant, engagement and finding, so the rows are reachable only with the
// tenantA context the use case demands.
func seedSLAGovernance(w *harnessWorld) {
	service, err := slauc.NewService(memory.NewSLAStore(), slaSeedClock{}, &slaSeedIDs{})
	if err != nil {
		w.t.Fatalf("sla service: %v", err)
	}
	ctx := slaSeedTenantCtx()
	// The source risk assessment id is provenance only, so it carries the marker into the list, the
	// single view and the assessment history without touching the scoring inputs.
	if _, err := service.Assess(ctx, sla.AssessmentInput{
		TenantID: "tenantA", EngagementID: slaSeedEngagement, FindingID: slaSeedFinding,
		SourceRiskAssessmentID: shared.ID(slaSeedMarker),
		Risk:                   sla.Inputs{Severity: shared.SeverityHigh, CVSSScore: 8.1, EPSS: 0.4, Feasibility: sla.FeasibilityPatchAvailable},
	}); err != nil {
		w.t.Fatalf("assess finding %s: %v", slaSeedFinding, err)
	}
	// A human decision is what writes a lifecycle event, and its reason is free text.
	if _, err := service.Transition(ctx, "tenantA", slaSeedEngagement, slaSeedFinding, sla.TransitionCommand{
		To: sla.RemediationMitigating, Actor: "sla-seed-reviewer", Reason: "patch scheduled " + slaSeedMarker, ExpectedVersion: 1,
	}); err != nil {
		w.t.Fatalf("transition finding %s: %v", slaSeedFinding, err)
	}
	w.rt.SetSLA(service)
}
