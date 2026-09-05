package httpapi

import (
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/capabilities"
)

// capabilityCatalog is the narrow read slice of the capabilities use case: the optional subsystems
// this deployment resolved at startup. *capabilities.Service satisfies it.
type capabilityCatalog interface {
	List() []capabilities.Capability
}

// SetCapabilities wires the deployment capability catalog. nil means the route is not registered.
func (rt *Router) SetCapabilities(c capabilityCatalog) { rt.capabilities = c }

// capabilityView is the serialized shape of one optional subsystem. It carries configuration
// booleans and the name of the environment variable that controls them, never a value: a switch
// NAME is not a secret, and no secret-bearing setting appears in the catalog.
type capabilityView struct {
	Key      string   `json:"key"`
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Switch   string   `json:"switch"`
	Requires []string `json:"requires,omitempty"`
}

type capabilitiesResponse struct {
	Capabilities []capabilityView `json:"capabilities"`
}

// listCapabilities reports which optional subsystems are on, so a client can render a disabled
// subsystem as disabled (and name the switch that turns it on) instead of showing a link that
// answers 404. Gated at the view floor: it exposes only configuration booleans.
func (rt *Router) listCapabilities(w http.ResponseWriter, _ *http.Request) {
	list := rt.capabilities.List()
	out := make([]capabilityView, 0, len(list))
	for _, capability := range list {
		out = append(out, capabilityView{
			Key:      capability.Key,
			Name:     capability.Name,
			Enabled:  capability.Enabled,
			Switch:   capability.Switch,
			Requires: capability.Requires,
		})
	}
	writeJSON(w, http.StatusOK, capabilitiesResponse{Capabilities: out})
}
