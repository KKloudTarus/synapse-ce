package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/qualityprofile"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// qualityProfileService is the HTTP slice for named, per-language quality profiles: read the built-in
// and custom profiles, copy a profile, toggle rules + severities on a custom copy, delete a custom
// profile, and assign a profile to a project language. Mutations are PermOperate; reads are PermView.
type qualityProfileService interface {
	List(ctx context.Context, tenantID shared.ID, language string) ([]qualityprofile.Profile, error)
	Get(ctx context.Context, tenantID shared.ID, key string) (qualityprofile.Profile, error)
	Copy(ctx context.Context, actor string, tenantID shared.ID, sourceKey, newKey, newName string) (qualityprofile.Profile, error)
	ActivateRule(ctx context.Context, actor string, tenantID shared.ID, key, ruleKey string, severity shared.Severity) (qualityprofile.Profile, error)
	DeactivateRule(ctx context.Context, actor string, tenantID shared.ID, key, ruleKey string) (qualityprofile.Profile, error)
	SetSeverity(ctx context.Context, actor string, tenantID shared.ID, key, ruleKey string, severity shared.Severity) (qualityprofile.Profile, error)
	Delete(ctx context.Context, actor string, tenantID shared.ID, key string) error
	Assign(ctx context.Context, actor string, tenantID shared.ID, projectKey, language, profileKey string) error
}

// SetQualityProfiles wires the quality-profile management endpoints. nil ⇒ routes are not registered.
func (rt *Router) SetQualityProfiles(s qualityProfileService) { rt.qualityProfiles = s }

func (rt *Router) listQualityProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := rt.qualityProfiles.List(r.Context(), shared.ID(TenantFrom(r.Context())), r.URL.Query().Get("language"))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, profiles)
}

func (rt *Router) getQualityProfile(w http.ResponseWriter, r *http.Request) {
	profile, err := rt.qualityProfiles.Get(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

type copyProfileRequest struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

func (rt *Router) copyQualityProfile(w http.ResponseWriter, r *http.Request) {
	var req copyProfileRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	profile, err := rt.qualityProfiles.Copy(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), req.Key, req.Name)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, profile)
}

type ruleActivationRequest struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
}

func (rt *Router) activateProfileRule(w http.ResponseWriter, r *http.Request) {
	var req ruleActivationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	profile, err := rt.qualityProfiles.ActivateRule(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), req.Rule, shared.Severity(req.Severity))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

func (rt *Router) deactivateProfileRule(w http.ResponseWriter, r *http.Request) {
	var req ruleActivationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	profile, err := rt.qualityProfiles.DeactivateRule(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), req.Rule)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

func (rt *Router) setProfileRuleSeverity(w http.ResponseWriter, r *http.Request) {
	var req ruleActivationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	profile, err := rt.qualityProfiles.SetSeverity(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), req.Rule, shared.Severity(req.Severity))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

func (rt *Router) deleteQualityProfile(w http.ResponseWriter, r *http.Request) {
	if err := rt.qualityProfiles.Delete(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), r.PathValue("key")); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type assignProfileRequest struct {
	Profile string `json:"profile"`
}

func (rt *Router) assignProjectProfile(w http.ResponseWriter, r *http.Request) {
	var req assignProfileRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	if err := rt.qualityProfiles.Assign(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), r.PathValue("language"), req.Profile); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
