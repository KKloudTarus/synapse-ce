// Package capabilities answers one product question: which optional subsystems are switched on in
// this deployment, and which SYNAPSE_* variable switches each one.
//
// Without it the dashboard cannot tell "this subsystem is off" from "this subsystem is broken":
// every optional route is registered conditionally in the composition root, so a disabled subsystem
// and a crashed one both answer 404. The catalog is static product knowledge, so it lives in the use
// case layer; the composition root only hands it the resolved flag values.
package capabilities

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Flags carries the resolved value of every SYNAPSE_* switch that gates an optional subsystem.
// The composition root assigns each field straight from config; no derivation happens there. A
// subsystem whose enablement depends on more than one switch is derived here, once.
type Flags struct {
	Fleet                bool // SYNAPSE_FLEET_ENABLED
	FleetAssets          bool // SYNAPSE_FLEET_ASSETS_ENABLED
	FleetHostIngest      bool // SYNAPSE_FLEET_HOST_INGEST_ENABLED
	FleetClusterIngest   bool // SYNAPSE_FLEET_CLUSTER_INGEST_ENABLED
	FleetTelemetryIngest bool // SYNAPSE_FLEET_TELEMETRY_INGEST_ENABLED
	FleetDetectionIngest bool // SYNAPSE_FLEET_DETECTION_INGEST_ENABLED
	CSPM                 bool // SYNAPSE_CSPM_ENABLED
	Agent                bool // SYNAPSE_AGENT_ENABLED
	FPTriage             bool // SYNAPSE_FP_TRIAGE_ENABLED
	SLA                  bool // SYNAPSE_SLA_ENABLED
	Judgments            bool // SYNAPSE_JUDGMENTS_ENABLED
	Sandbox              bool // SYNAPSE_SANDBOX_ENABLED
	WriteupDrafts        bool // SYNAPSE_WRITEUP_DRAFTS_ENABLED
	Taint                bool // SYNAPSE_TAINT_ENABLED
	JSReachability       bool // SYNAPSE_JSREACH_ENABLED
	SingleTenant         bool // SYNAPSE_SINGLE_TENANT
	OIDC                 bool // SYNAPSE_OIDC_ENABLED
}

// Capability describes one optional subsystem to a client. Key is stable API: a dashboard keys its
// navigation off it. Switch names the SYNAPSE_* variable an operator sets to change Enabled, so the
// product can say "Fleet is off because SYNAPSE_FLEET_ENABLED is false" instead of showing a dead
// link. Requires lists the keys of other capabilities this one needs, so a client can explain an
// enabled switch that still yields a disabled subsystem.
type Capability struct {
	Key      string
	Name     string
	Enabled  bool
	Switch   string
	Requires []string
}

// Service serves the immutable capability catalog resolved at startup.
type Service struct{ catalog []Capability }

// NewService resolves the catalog from the deployment's flags. It rejects a catalog with a
// duplicate or incomplete entry, so a future edit cannot ship an ambiguous key or a capability that
// names no switch.
func NewService(flags Flags) (*Service, error) {
	catalog := build(flags)
	if err := validate(catalog); err != nil {
		return nil, err
	}
	return &Service{catalog: catalog}, nil
}

// validate rejects a catalog with a blank field, a duplicate key, or a dependency on a capability
// that does not exist. It runs at startup so a bad edit fails the process, never a request.
func validate(catalog []Capability) error {
	seen := make(map[string]bool, len(catalog))
	for _, capability := range catalog {
		if capability.Key == "" || capability.Name == "" || capability.Switch == "" {
			return fmt.Errorf("%w: capability %q is missing a key, name, or switch", shared.ErrValidation, capability.Key)
		}
		if seen[capability.Key] {
			return fmt.Errorf("%w: duplicate capability key %q", shared.ErrValidation, capability.Key)
		}
		seen[capability.Key] = true
	}
	for _, capability := range catalog {
		for _, required := range capability.Requires {
			if !seen[required] {
				return fmt.Errorf("%w: capability %q requires unknown capability %q", shared.ErrValidation, capability.Key, required)
			}
		}
	}
	return nil
}

// List returns the catalog in a stable order. The slice is copied so a caller cannot mutate the
// startup-resolved answer. It reads no I/O, so it takes no context.
func (s *Service) List() []Capability {
	out := make([]Capability, len(s.catalog))
	copy(out, s.catalog)
	for i := range out {
		if len(out[i].Requires) > 0 {
			requires := make([]string, len(out[i].Requires))
			copy(requires, out[i].Requires)
			out[i].Requires = requires
		}
	}
	return out
}

// build resolves each subsystem's effective enablement. A subsystem is enabled only when its own
// switch is on AND every subsystem it depends on is enabled, which is exactly the condition the
// composition root uses when it decides to register the routes.
func build(f Flags) []Capability {
	return []Capability{
		{Key: "fleet", Name: "Agent fleet transport", Enabled: f.Fleet, Switch: "SYNAPSE_FLEET_ENABLED"},
		{Key: "fleet_assets", Name: "Fleet asset model", Enabled: f.FleetAssets, Switch: "SYNAPSE_FLEET_ASSETS_ENABLED"},
		{
			Key: "fleet_host_ingest", Name: "Fleet host inventory ingest",
			Enabled: f.FleetHostIngest && f.Fleet && f.FleetAssets,
			Switch:  "SYNAPSE_FLEET_HOST_INGEST_ENABLED", Requires: []string{"fleet", "fleet_assets"},
		},
		{
			Key: "fleet_cluster_ingest", Name: "Fleet cluster inventory ingest",
			Enabled: f.FleetClusterIngest && f.Fleet && f.FleetAssets,
			Switch:  "SYNAPSE_FLEET_CLUSTER_INGEST_ENABLED", Requires: []string{"fleet", "fleet_assets"},
		},
		{
			Key: "fleet_telemetry_ingest", Name: "Fleet telemetry ingest",
			Enabled: f.FleetTelemetryIngest && f.Fleet,
			Switch:  "SYNAPSE_FLEET_TELEMETRY_INGEST_ENABLED", Requires: []string{"fleet"},
		},
		{
			Key: "fleet_detection_ingest", Name: "Fleet detection ingest",
			Enabled: f.FleetDetectionIngest && f.Fleet,
			Switch:  "SYNAPSE_FLEET_DETECTION_INGEST_ENABLED", Requires: []string{"fleet"},
		},
		{
			Key: "cspm", Name: "Cloud security posture management",
			Enabled: f.CSPM && f.FleetAssets, Switch: "SYNAPSE_CSPM_ENABLED", Requires: []string{"fleet_assets"},
		},
		{Key: "agent", Name: "AI agent orchestration", Enabled: f.Agent, Switch: "SYNAPSE_AGENT_ENABLED"},
		{Key: "ai_triage", Name: "AI false-positive triage", Enabled: f.FPTriage, Switch: "SYNAPSE_FP_TRIAGE_ENABLED"},
		{Key: "sla", Name: "SLA governance", Enabled: f.SLA, Switch: "SYNAPSE_SLA_ENABLED"},
		{Key: "judgments", Name: "Judgment lifecycle", Enabled: f.Judgments, Switch: "SYNAPSE_JUDGMENTS_ENABLED"},
		{Key: "sandbox", Name: "Sandboxed tool execution", Enabled: f.Sandbox, Switch: "SYNAPSE_SANDBOX_ENABLED"},
		{
			// DAST actively probes a target, so its workflow routes are served only when the sandbox
			// can kernel-enforce egress confinement and the judgment lifecycle can seal the verdict.
			Key: "dast", Name: "Governed DAST", Enabled: f.Sandbox && f.Judgments,
			Switch: "SYNAPSE_SANDBOX_ENABLED", Requires: []string{"sandbox", "judgments"},
		},
		{Key: "writeup_drafts", Name: "AI write-up drafts", Enabled: f.WriteupDrafts, Switch: "SYNAPSE_WRITEUP_DRAFTS_ENABLED"},
		{Key: "taint", Name: "Taint analysis", Enabled: f.Taint, Switch: "SYNAPSE_TAINT_ENABLED"},
		{Key: "js_reachability", Name: "JavaScript reachability", Enabled: f.JSReachability, Switch: "SYNAPSE_JSREACH_ENABLED"},
		{Key: "single_tenant", Name: "Single-tenant mode", Enabled: f.SingleTenant, Switch: "SYNAPSE_SINGLE_TENANT"},
		{Key: "oidc", Name: "OIDC browser login", Enabled: f.OIDC, Switch: "SYNAPSE_OIDC_ENABLED"},
	}
}
