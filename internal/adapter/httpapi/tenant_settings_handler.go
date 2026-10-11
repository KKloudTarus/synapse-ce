package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	tenancyuc "github.com/KKloudTarus/synapse-ce/internal/usecase/tenancy"
)

// SetTenantSettings wires the tenant settings service (#1359). nil means the routes are not registered.
func (rt *Router) SetTenantSettings(s *tenancyuc.Service) { rt.tenantSettings = s }

const tenantSettingsBodyCap = 4 << 10

// tenantSettingsView is the wire shape of GET and PUT /api/v1/tenant/settings. `locales` lists the
// languages this build can render, so the console never offers one a template lookup would miss.
type tenantSettingsView struct {
	DefaultLocale tenancy.Locale   `json:"default_locale"`
	TimeZone      string           `json:"time_zone"`
	Revision      int              `json:"revision"`
	UpdatedAt     *time.Time       `json:"updated_at,omitempty"`
	Locales       []tenancy.Locale `json:"locales"`
}

func newTenantSettingsView(s tenancy.Settings) tenantSettingsView {
	view := tenantSettingsView{DefaultLocale: s.DefaultLocale, TimeZone: s.TimeZone, Revision: s.Revision, Locales: tenancy.Locales()}
	if s.Revision > 0 {
		at := s.UpdatedAt.UTC()
		view.UpdatedAt = &at
	}
	return view
}

// getTenantSettings returns the caller's tenant settings, or the defaults at revision 0. Any role
// may read them: they are presentation choices, not configuration secrets.
func (rt *Router) getTenantSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := rt.tenantSettings.Settings(r.Context(), shared.ID(TenantFrom(r.Context())))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, newTenantSettingsView(settings))
}

// putTenantSettings saves the caller's tenant settings. The tenant comes from the session, never
// from the body, and the revision guards a concurrent edit.
func (rt *Router) putTenantSettings(w http.ResponseWriter, r *http.Request) {
	var in tenancyuc.Update
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, tenantSettingsBodyCap))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, rt.log, fmt.Errorf("%w: invalid tenant settings request", shared.ErrValidation))
		return
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, rt.log, fmt.Errorf("%w: tenant settings request must contain one JSON object", shared.ErrValidation))
		return
	}
	saved, err := rt.tenantSettings.Save(r.Context(), shared.ID(TenantFrom(r.Context())), PrincipalFrom(r.Context()), in)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, newTenantSettingsView(saved))
}
