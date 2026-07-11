package httpapi

import (
	"encoding/json"
	"net/http"
)

// aupText is the acceptable-use policy shown on first run.
const aupText = `Synapse – Acceptable Use Policy (summary)

Synapse is for AUTHORIZED security testing ONLY. You must have explicit written
permission to test any target. Synapse validates scope DATA but cannot verify
legal authorization – you, the operator, are solely responsible. Provided WITHOUT
WARRANTY of any kind. By accepting, you agree to these terms. See docs/adr/0008.`

func (rt *Router) getAUP(w http.ResponseWriter, r *http.Request) {
	st, err := rt.aup.Status(r.Context())
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  st.Version,
		"accepted": st.Accepted,
		"text":     aupText,
	})
}

type acceptAUPRequest struct {
	Version string `json:"version"`
}

func (rt *Router) acceptAUP(w http.ResponseWriter, r *http.Request) {
	var req acceptAUPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	// Attribute to the authenticated principal (single-user → operator today).
	if err := rt.aup.Accept(r.Context(), PrincipalFrom(r.Context()), req.Version); err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted", "version": rt.aup.CurrentVersion()})
}

// requireAUP blocks protected routes until the current AUP is accepted. The AUP
// read/accept endpoints (and other exempt paths) pass through.
func (rt *Router) requireAUP(exempt map[string]bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exempt[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		ok, err := rt.aup.IsAccepted(r.Context())
		if err != nil {
			writeError(w, rt.log, err)
			return
		}
		if !ok {
			writeJSON(w, http.StatusForbidden, errorBody{
				Error: "acceptable-use policy not accepted; GET then POST /api/v1/aup/accept",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}
