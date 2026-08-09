package httpapi

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"

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
		// The RAW tenant is passed on. The use case resolves the engagement inside it and then takes the
		// row tenant from the ENGAGEMENT, so the value that authorizes the write and the value that
		// stamps it are always the same one. Normalizing here instead would let an empty-tenant
		// principal pass the gate for another tenant's engagement and land the rows in `default`.
		TenantID:     shared.ID(TenantFrom(r.Context())),
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

// sarifReader is the narrow read the imported-finding listing needs.
type sarifReader interface {
	ListByEngagement(ctx context.Context, tenantID, engagementID shared.ID) ([]importedfinding.ImportedFinding, error)
}

// SetImportedFindings wires the imported-finding read. Optional: when nil the route is not registered.
func (rt *Router) SetImportedFindings(r sarifReader) { rt.importedFindings = r }

// importedFindingPayload renders one third-party finding.
//
// `external` and `can_self_promote` are on the wire deliberately. They are the type's own answers, not
// this handler's opinion, so every consumer — the UI, an export, another service — sees the governance
// position rather than having to infer it from the presence of a provenance block.
type importedFindingPayload struct {
	ID             string `json:"id"`
	FindingID      string `json:"finding_id,omitempty"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Message        string `json:"message"`
	Path           string `json:"path,omitempty"`
	StartLine      int    `json:"start_line,omitempty"`
	StartColumn    int    `json:"start_column,omitempty"`
	LogicalName    string `json:"logical_name,omitempty"`
	Suppressed     bool   `json:"suppressed_by_tool"`
	Fingerprint    string `json:"fingerprint,omitempty"`
	External       bool   `json:"external"`
	CanSelfPromote bool   `json:"can_self_promote"`
	Tool           string `json:"tool"`
	ToolVersion    string `json:"tool_version"`
	Rule           string `json:"rule"`
	SourceDigest   string `json:"source_digest"`
	IngestedBy     string `json:"ingested_by"`
	IngestedAt     string `json:"ingested_at"`
}

// listImportedFindings returns an engagement's third-party findings.
func (rt *Router) listImportedFindings(w http.ResponseWriter, r *http.Request) {
	if rt.importedFindings == nil {
		writeJSON(w, http.StatusOK, []importedFindingPayload{})
		return
	}
	// The tenant is normalized HERE, at the store boundary, because the RLS partition uses a non-empty
	// id — the engagement gate has already proven this caller may see this engagement.
	findings, err := rt.importedFindings.ListByEngagement(r.Context(),
		shared.TenantOrDefault(shared.ID(TenantFrom(r.Context()))), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]importedFindingPayload, 0, len(findings))
	for _, f := range findings {
		out = append(out, importedFindingPayload{
			ID:             f.ID.String(),
			FindingID:      f.FindingID.String(),
			Severity:       string(f.Severity),
			Title:          f.Title,
			Message:        f.Message,
			Path:           f.Location.Path,
			StartLine:      f.Location.StartLine,
			StartColumn:    f.Location.StartColumn,
			LogicalName:    f.Location.LogicalName,
			Suppressed:     f.Suppressed,
			Fingerprint:    f.Fingerprint,
			External:       f.External(),
			CanSelfPromote: f.CanSelfPromote(),
			Tool:           f.Provenance.ToolName,
			ToolVersion:    f.Provenance.ToolVersion,
			Rule:           f.Provenance.RuleID,
			SourceDigest:   f.Provenance.SourceDigest,
			IngestedBy:     f.Provenance.IngestedBy.String(),
			IngestedAt:     f.Provenance.IngestedAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, out)
}
