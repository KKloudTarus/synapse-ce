package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	responseuc "github.com/KKloudTarus/synapse-ce/internal/usecase/response"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

// responseService is the narrow slice of the governed-response use case the HTTP layer drives (#425):
// plan (dry run, executes nothing), apply (through the admission gate + human approval), revert, and
// list by state. *responseuc.Service satisfies it. The service is wired with the SAME admission gate a
// DAST probe and an exploitation step use, so a response action is not a privileged side path.
type responseService interface {
	DryRun(action rdom.Action) ([]responseuc.PlanStep, error)
	Apply(ctx context.Context, engagementID shared.ID, action rdom.Action, target engagement.Target, approver string) (responseuc.Record, error)
	Revert(ctx context.Context, actionID shared.ID, target engagement.Target, approver string) (responseuc.Record, error)
	ListByState(ctx context.Context, state rdom.State) ([]responseuc.Record, error)
}

// SetResponse wires the governed defensive-response routes (#425). Left unset, the routes are not
// registered — the feature is optional, exactly like every other subsystem the router gates on a nil
// dependency. ids mints the action id server-side so a client can never choose it.
func (rt *Router) SetResponse(svc responseService, ids ports.IDGenerator) {
	if svc != nil && ids != nil {
		rt.responses = svc
		rt.responseIDs = ids
	}
}

type responseActionRequest struct {
	Kind   string `json:"kind"`   // isolate_host | quarantine_file | stop_process
	Target string `json:"target"` // the asset id the action affects; must be in the engagement scope
	// TargetKind names the scope entry kind the target is authorized as (default: ip). The admission
	// gate matches it against the engagement's scope, so a target outside scope is refused.
	TargetKind string `json:"target_kind"`
}

type responseRevertRequest struct {
	Target     string `json:"target"`
	TargetKind string `json:"target_kind"`
}

type responsePlanStepDTO struct {
	Label       string   `json:"label"`
	Argv        []string `json:"argv"`
	BlastRadius string   `json:"blast_radius"`
}

type responsePlanDTO struct {
	Kind   string                `json:"kind"`
	Target string                `json:"target"`
	Steps  []responsePlanStepDTO `json:"steps"`
}

type responseRecordDTO struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	Target       string `json:"target"`
	State        string `json:"state"`
	Approver     string `json:"approver,omitempty"`
	Verification string `json:"verification,omitempty"`
	EvidenceID   string `json:"evidence_id,omitempty"`
}

func targetKindOrDefault(raw string) engagement.TargetKind {
	if raw == "" {
		return engagement.TargetIP
	}
	return engagement.TargetKind(raw)
}

func toResponseRecordDTO(rec responseuc.Record) responseRecordDTO {
	return responseRecordDTO{
		ID:           rec.Action.ID.String(),
		Kind:         string(rec.Action.Kind),
		Target:       rec.Action.Target.String(),
		State:        string(rec.State),
		Approver:     rec.ApprovedBy,
		Verification: string(rec.Verification),
		EvidenceID:   rec.ApprovalEvidenceID.String(),
	}
}

// planResponse dry-runs a response action for an engagement: it enumerates the apply and the mandatory
// reversal and executes NOTHING. It validates the action's SHAPE (an unknown kind is a 400 here) and
// resolves the engagement in the caller's tenant (404 on cross-tenant/unknown). It does NOT authorize
// the target against the engagement scope — that check runs at apply, through the admission gate.
func (rt *Router) planResponse(w http.ResponseWriter, r *http.Request) {
	if _, err := rt.eng.Get(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id"))); err != nil {
		writeError(w, rt.log, err)
		return
	}
	var req responseActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	action, err := rdom.NewAction(rt.responseIDs.NewID(), rdom.Kind(req.Kind), shared.ID(req.Target))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	steps, err := rt.responses.DryRun(action)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := responsePlanDTO{Kind: string(action.Kind), Target: action.Target.String()}
	for _, s := range steps {
		out.Steps = append(out.Steps, responsePlanStepDTO{Label: s.Label, Argv: s.Argv, BlastRadius: string(s.BlastRadius)})
	}
	writeJSON(w, http.StatusOK, out)
}

// applyResponse applies a governed response action to an engagement's in-scope target. The apply is
// authorized server-side (scope guard + the human approver recorded as evidence) and the executed
// effect is checked against the declared blast radius. The approver is the authenticated principal; a
// machine identity is refused by the use case.
func (rt *Router) applyResponse(w http.ResponseWriter, r *http.Request) {
	engID := shared.ID(r.PathValue("id"))
	// Resolve the engagement in the caller's tenant first: a cross-tenant or unknown engagement is a
	// 404 before any action is built, and the resolved engagement binds the tenant the store writes under.
	eng, err := rt.eng.Get(r.Context(), shared.ID(TenantFrom(r.Context())), engID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	var req responseActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	action, aerr := rdom.NewAction(rt.responseIDs.NewID(), rdom.Kind(req.Kind), shared.ID(req.Target))
	if aerr != nil {
		writeError(w, rt.log, aerr)
		return
	}
	target := engagement.Target{Kind: targetKindOrDefault(req.TargetKind), Value: req.Target}
	ctx := shared.WithTenant(r.Context(), shared.TenantOrDefault(eng.TenantID))
	rec, err := rt.responses.Apply(ctx, engID, action, target, PrincipalFrom(r.Context()))
	if errors.Is(err, safety.ErrPendingApproval) {
		// The action is recorded pending a second human; hand back its server-minted id so the operator
		// can find it in the list and the kill switch can cancel it.
		writeJSON(w, http.StatusAccepted, toResponseRecordDTO(rec))
		return
	}
	if err != nil {
		writeResponseError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, toResponseRecordDTO(rec))
}

// revertResponse reverses an applied action. The reversal is itself an admitted, audited, human-approved
// action; only an applied action can be reverted, and the target must match the action's target.
func (rt *Router) revertResponse(w http.ResponseWriter, r *http.Request) {
	actionID := shared.ID(r.PathValue("id"))
	var req responseRevertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	target := engagement.Target{Kind: targetKindOrDefault(req.TargetKind), Value: req.Target}
	ctx := shared.WithTenant(r.Context(), requestTenant(r))
	rec, err := rt.responses.Revert(ctx, actionID, target, PrincipalFrom(r.Context()))
	if err != nil {
		writeResponseError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, toResponseRecordDTO(rec))
}

// listResponses returns the tenant's response actions in a state (default pending), so an operator can
// see what is admitted-but-not-applied — the same set the kill switch cancels.
func (rt *Router) listResponses(w http.ResponseWriter, r *http.Request) {
	state := rdom.State(r.URL.Query().Get("state"))
	if state == "" {
		state = rdom.StatePending
	}
	if !state.Valid() {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "unknown response state: " + string(state)})
		return
	}
	ctx := shared.WithTenant(r.Context(), requestTenant(r))
	recs, err := rt.responses.ListByState(ctx, state)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]responseRecordDTO, 0, len(recs))
	for _, rec := range recs {
		out = append(out, toResponseRecordDTO(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{"responses": out})
}

// writeResponseError maps governed-response failures to status codes. The pending-approval case is
// handled directly by applyResponse (it returns the pending record), so this maps a blast-radius or
// scope refusal to 403 and validation to 400 through writeError, and 202 for any pending signal that
// still reaches it (revert).
func writeResponseError(w http.ResponseWriter, log *slog.Logger, err error) {
	if errors.Is(err, safety.ErrPendingApproval) {
		writeJSON(w, http.StatusAccepted, errorBody{Error: "response action recorded; awaiting a second human approval"})
		return
	}
	writeError(w, log, err)
}
