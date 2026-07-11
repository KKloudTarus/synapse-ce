package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	transferuc "github.com/KKloudTarus/synapse-ce/internal/usecase/transfer"
)

// maxBundleBytes caps an uploaded import bundle (defensive – bundles are JSON).
const maxBundleBytes = 64 << 20 // 64 MiB

// exportBundle streams a portable engagement bundle: scope + findings +
// comments + the full tamper-evident evidence chain, as a JSON download.
func (rt *Router) exportBundle(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id is required"})
		return
	}
	bundle, err := rt.transfer.Export(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), shared.ID(id))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="synapse-`+safeID(id)+`-bundle.json"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// importBundle ingests a portable bundle and materializes a NEW engagement from it,
// after re-verifying the evidence chain (a tampered chain is rejected).
func (rt *Router) importBundle(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBundleBytes)
	var bundle transferuc.Bundle
	if err := json.NewDecoder(r.Body).Decode(&bundle); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid bundle: " + err.Error()})
		return
	}
	eng, err := rt.transfer.Import(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), bundle)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, eng)
}

// listAudit returns the most recent append-only audit entries (audit trail).
func (rt *Router) listAudit(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil {
			limit = n
		}
	}
	entries, err := rt.audit.List(r.Context(), limit)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// verifyAudit re-derives the audit hash chain and reports whether it is intact
// – the audit-log analogue of the evidence-chain verify. A broken
// chain means the append-only log was tampered with after the fact.
func (rt *Router) verifyAudit(w http.ResponseWriter, r *http.Request) {
	report, err := rt.audit.Verify(r.Context())
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}
