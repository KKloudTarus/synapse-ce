package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/compliance"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// findingView is a finding annotated for the UI read path with two purely-additive, DETERMINISTIC
// augmentations (no LLM): the suspected-FP flag (a CONFIRMED, publishable "refuted" critique –
// advisory only, never suppresses the finding) and the curated compliance controls the finding's CWE
// maps to (the same table the report uses – a lookup, not a model output). The embedded
// finding's JSON shape is unchanged; both new fields are omitempty (non-breaking).
type findingView struct {
	finding.Finding
	SuspectedFP bool                 `json:"suspected_fp,omitempty"`
	Compliance  []compliance.Control `json:"compliance_controls,omitempty"`
}

// listFindings returns the findings for an engagement (highest risk first), each annotated with the
// suspected-FP flag and its curated compliance controls.
func (rt *Router) listFindings(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id is required"})
		return
	}
	list, err := rt.findings.List(r.Context(), shared.ID(id))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	fp := rt.suspectedFP(r.Context(), shared.ID(id))
	writeJSON(w, http.StatusOK, findingViews(list, fp))
}

// findingViews annotates each finding with its UI read-path augmentations: the suspected-FP flag
// (from fp) and the curated compliance controls its CWE maps to. Both are deterministic
// and additive; an unmapped/empty CWE simply yields no controls (compliance.ControlsFor fail-open).
func findingViews(list []finding.Finding, fp map[shared.ID]bool) []findingView {
	views := make([]findingView, len(list))
	for i, f := range list {
		views[i] = findingView{Finding: f, SuspectedFP: fp[f.ID], Compliance: compliance.ControlsFor(f.CWE)}
	}
	return views
}

// suspectedFP returns the set of finding ids that have a CONFIRMED (publishable) "refuted" critique
// judgment. Best-effort: judgments disabled or a read error ⇒ no flags (never breaks the list).
func (rt *Router) suspectedFP(ctx context.Context, engagementID shared.ID) map[shared.ID]bool {
	if rt.judgments == nil {
		return nil
	}
	js, err := rt.judgments.List(ctx, engagementID)
	if err != nil {
		return nil
	}
	out := map[shared.ID]bool{}
	for _, j := range js {
		if !j.Publishable() || j.Capability != judgment.CapCritique {
			continue
		}
		if cc, ok := j.Claim.(judgment.CritiqueClaim); ok && cc.Verdict == judgment.CritiqueRefuted {
			out[j.SubjectID] = true
		}
	}
	return out
}

type createFindingRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	CVSSVector  string `json:"cvss_vector"`
	CWE         string `json:"cwe"`
}

// createFinding authors a manual finding. If a CVSS vector is supplied,
// severity is derived from it server-side. Attributed to the principal + audited.
func (rt *Router) createFinding(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id") // engagement existence + tenant isolation enforced by withEngTenant
	var req createFindingRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	f, err := rt.findings.Create(r.Context(), PrincipalFrom(r.Context()), shared.ID(id), finding.ManualInput{
		Title:       req.Title,
		Description: req.Description,
		Severity:    shared.Severity(req.Severity),
		CVSSVector:  req.CVSSVector,
		CWE:         req.CWE,
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, f)
}

// verifyFinding applies a DISTINCT verifier's adversarial verdict to an exploitation finding
// it seals the verdict into the evidence chain and, if the score clears the bar, makes
// the finding promotable. Separation of duties is enforced two independent ways: the route requires
// PermReview (machine roles – mcp/agent – are granted nothing in the RBAC matrix, so they cannot
// verify) and the domain rejects verifier == proposed_by. A passing verdict still does not
// auto-confirm – a human PATCHes status=confirmed afterward (which the findings service blocks
// below the evidence bar).
func (rt *Router) verifyFinding(w http.ResponseWriter, r *http.Request) {
	engID, findID := r.PathValue("id"), r.PathValue("fid")
	if engID == "" || findID == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id and finding id are required"})
		return
	}
	var body struct {
		Score     int    `json:"score"`
		Rationale string `json:"rationale"`
		Version   int    `json:"version"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	updated, err := rt.exploitation.Confirm(r.Context(), PrincipalFrom(r.Context()), shared.ID(engID), shared.ID(findID), body.Score, body.Rationale, body.Version)
	if err != nil {
		writeError(w, rt.log, err) // verifier==proposer / bad score → ErrValidation → 400
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// updateFindingStatus applies a triage status change with optimistic concurrency
// the client sends the version it last saw; a mismatch is 409. Audited.
func (rt *Router) updateFindingStatus(w http.ResponseWriter, r *http.Request) {
	engID, findID := r.PathValue("id"), r.PathValue("fid")
	if engID == "" || findID == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id and finding id are required"})
		return
	}
	var body struct {
		Status  string `json:"status"`
		Note    string `json:"note"`
		Version int    `json:"version"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	updated, err := rt.findings.UpdateStatus(
		r.Context(), shared.ID(engID), shared.ID(findID),
		finding.Status(body.Status), body.Note, PrincipalFrom(r.Context()), body.Version)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

type assigneeRequest struct {
	Assignee string `json:"assignee"`
	Version  int    `json:"version"`
}

// setFindingAssignee assigns/unassigns a finding, same optimistic guard.
func (rt *Router) setFindingAssignee(w http.ResponseWriter, r *http.Request) {
	var body assigneeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	updated, err := rt.findings.SetAssignee(
		r.Context(), shared.ID(r.PathValue("id")), shared.ID(r.PathValue("fid")),
		body.Assignee, PrincipalFrom(r.Context()), body.Version)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// listFindingComments returns a finding's comment thread (oldest first).
func (rt *Router) listFindingComments(w http.ResponseWriter, r *http.Request) {
	list, err := rt.findings.Comments(r.Context(), shared.ID(r.PathValue("id")), shared.ID(r.PathValue("fid")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// addFindingComment appends a persisted, attributed comment to a finding.
func (rt *Router) addFindingComment(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	c, err := rt.findings.AddComment(
		r.Context(), shared.ID(r.PathValue("id")), shared.ID(r.PathValue("fid")),
		body.Body, PrincipalFrom(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

// listRetests returns a finding's retest history, engagement-scoped.
func (rt *Router) listRetests(w http.ResponseWriter, r *http.Request) {
	rs, err := rt.findings.Retests(r.Context(), shared.ID(r.PathValue("id")), shared.ID(r.PathValue("fid")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, rs)
}

// recordRetest appends a retest and moves the finding to the implied status (under
// the optimistic-concurrency version). Returns the retest + the updated finding.
func (rt *Router) recordRetest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Outcome string `json:"outcome"`
		Note    string `json:"note"`
		Version int    `json:"version"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	rt2, f, err := rt.findings.RecordRetest(
		r.Context(), shared.ID(r.PathValue("id")), shared.ID(r.PathValue("fid")),
		finding.RetestOutcome(body.Outcome), body.Note, PrincipalFrom(r.Context()), body.Version)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"retest": rt2, "finding": f})
}

// cvssScore computes a CVSS v3.1 base score + severity from a vector, for the UI
// vector builder (one authoritative formula, server-side).
func (rt *Router) cvssScore(w http.ResponseWriter, r *http.Request) {
	vector := r.URL.Query().Get("vector")
	score, ok := shared.CVSSv3BaseScore(vector)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid CVSS v3.1 vector"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"vector":   vector,
		"score":    score,
		"severity": shared.SeverityFromScore(score),
	})
}
