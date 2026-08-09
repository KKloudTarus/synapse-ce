package httpapi

import (
	"context"
	"io"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/sarifingest"
)

// sarifBodyCap bounds the request body before the usecase sees it, so an oversized upload is rejected
// at the edge rather than buffered whole.
const sarifBodyCap = sarifingest.DefaultMaxDocumentBytes

// sarifIngester is the narrow view of the ingest usecase the HTTP layer needs.
type sarifIngester interface {
	Ingest(ctx context.Context, req sarifingest.IngestRequest) (sarifingest.IngestResult, error)
}

// SetSARIFIngest wires the ingest usecase and enables the import route. Optional: when nil the route is
// not registered.
func (rt *Router) SetSARIFIngest(s sarifIngester) { rt.sarif = s }

// sarifIngestResponse mirrors the usecase result. Refusals are a LIST, never a count, because a silent
// refusal is indistinguishable from a clean ingest.
type sarifIngestResponse struct {
	Accepted      int                        `json:"accepted"`
	Deduplicated  int                        `json:"deduplicated"`
	Matched       int                        `json:"matched_first_party"`
	Disagreements []sarifDisagreementPayload `json:"disagreements"`
	Refused       []sarifRefusalPayload      `json:"refused"`
	// Coverage states what the ingest could not fully represent (an unmappable severity, a truncated
	// field). Without it a lossy ingest is indistinguishable from a complete one.
	Coverage []string `json:"coverage"`
}

type sarifRefusalPayload struct {
	RunIndex    int    `json:"run_index"`
	ResultIndex int    `json:"result_index"`
	Code        string `json:"code"`
	Detail      string `json:"detail"`
}

type sarifDisagreementPayload struct {
	FindingID       string `json:"finding_id"`
	Rule            string `json:"rule"`
	Tool            string `json:"tool"`
	FirstPartyLevel string `json:"first_party_severity"`
	ExternalLevel   string `json:"external_severity"`
}

// importSARIF ingests a third-party SARIF report into an engagement.
func (rt *Router) importSARIF(w http.ResponseWriter, r *http.Request) {
	document, err := io.ReadAll(http.MaxBytesReader(w, r.Body, sarifBodyCap))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "sarif document could not be read or exceeds the size bound"})
		return
	}
	result, err := rt.sarif.Ingest(r.Context(), sarifingest.IngestRequest{
		// TenantFrom is empty in single-tenant mode (and for the bootstrap admin). Normalizing here is
		// what keeps the route usable in the default deployment instead of rejecting every ingest.
		TenantID:     shared.TenantOrDefault(shared.ID(TenantFrom(r.Context()))),
		EngagementID: shared.ID(r.PathValue("id")),
		Document:     document,
		Actor:        shared.ID(PrincipalFrom(r.Context())),
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}

	payload := sarifIngestResponse{
		Accepted:      result.Accepted,
		Deduplicated:  result.Deduped,
		Matched:       result.Matched,
		Disagreements: make([]sarifDisagreementPayload, 0, len(result.Disagreements)),
		Refused:       make([]sarifRefusalPayload, 0, len(result.Refused)),
		Coverage:      make([]string, 0, len(result.Coverage)),
	}
	for _, issue := range result.Coverage {
		payload.Coverage = append(payload.Coverage, issue.Detail)
	}
	for _, d := range result.Disagreements {
		payload.Disagreements = append(payload.Disagreements, sarifDisagreementPayload{
			FindingID:       d.FindingID.String(),
			Rule:            d.Rule,
			Tool:            d.Tool,
			FirstPartyLevel: string(d.FirstPartyLevel),
			ExternalLevel:   string(d.ExternalLevel),
		})
	}
	for _, refusal := range result.Refused {
		payload.Refused = append(payload.Refused, sarifRefusalPayload{
			RunIndex: refusal.RunIndex, ResultIndex: refusal.ResultIndex,
			Code: string(refusal.Code), Detail: refusal.Detail,
		})
	}
	writeJSON(w, http.StatusOK, payload)
}
