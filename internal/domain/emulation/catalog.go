package emulation

import (
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// catalogue is the built-in set of emulation techniques. Each maps to a public ATT&CK technique id and
// declares the detection it should produce. Entries are added as techniques are classified, not in
// advance — an emulation with no expected detection cannot contribute to a coverage number.
//
// The benign/production-safe techniques here generate their telemetry without a real effect (a discovery
// command that only reads, a DNS lookup to a benign sink). The one lab-only entry has no benign variant
// and is ProductionSafe=false, so it is gated behind an explicit opt-in and never runs against a
// customer estate by default.
var catalogue = []Technique{
	{
		ID: "emu.process_discovery", TaxonomyRef: "T1057", BenignVariant: true, ProductionSafe: true,
		Expected: ExpectedObservable{Telemetry: []TelemetryClass{TelemetryProcess}, DetectionID: "det.process_enumeration", Version: "v1"},
	},
	{
		ID: "emu.system_network_config_discovery", TaxonomyRef: "T1016", BenignVariant: true, ProductionSafe: true,
		Expected: ExpectedObservable{Telemetry: []TelemetryClass{TelemetryProcess, TelemetryNetwork}, DetectionID: "det.network_config_discovery", Version: "v1"},
	},
	{
		ID: "emu.dns_beacon_benign", TaxonomyRef: "T1071.004", BenignVariant: true, ProductionSafe: true,
		Expected: ExpectedObservable{Telemetry: []TelemetryClass{TelemetryDNS, TelemetryNetwork}, DetectionID: "det.suspicious_dns_beacon", Version: "v2"},
	},
	{
		ID: "emu.credential_file_read", TaxonomyRef: "T1552.001", BenignVariant: true, ProductionSafe: true,
		Expected: ExpectedObservable{Telemetry: []TelemetryClass{TelemetryFile}, DetectionID: "det.credential_file_access", Version: "v1"},
	},
	{
		// Lab-only: a service-restart probe has no benign proof of its observable — you cannot generate
		// the restart telemetry without actually restarting the service — so it is not production-safe
		// and runs only under an explicit lab opt-in. It is reversible (restart back), so unlike log
		// tampering it is not a prohibited category; its register entry is high-risk with dual approval.
		ID: "emu.service_restart_probe", TaxonomyRef: "T1569.002", BenignVariant: false, ProductionSafe: false,
		Expected: ExpectedObservable{Telemetry: []TelemetryClass{TelemetryProcess, TelemetryAuth}, DetectionID: "det.unexpected_service_restart", Version: "v1"},
	},
}

// Catalogue returns a validated copy of the built-in technique set, deterministically ordered by id so
// a coverage run and its trend are comparable over time.
//
// It validates on every call rather than trusting the literal above, so a malformed entry fails the
// build via the catalogue test rather than shipping a technique that cannot be measured.
func Catalogue() ([]Technique, error) {
	seen := make(map[string]struct{}, len(catalogue))
	out := make([]Technique, 0, len(catalogue))
	for _, t := range catalogue {
		if err := t.Validate(); err != nil {
			return nil, err
		}
		if _, dup := seen[t.ID]; dup {
			return nil, fmt.Errorf("%w: duplicate technique id %q", shared.ErrValidation, t.ID)
		}
		if _, dupTax := taxonomyIndex(out, t.TaxonomyRef); dupTax {
			// Two techniques may legitimately share nothing else, but a duplicate taxonomy ref would
			// double-count a technique in the coverage number, so refuse it.
			return nil, fmt.Errorf("%w: duplicate taxonomy reference %q", shared.ErrValidation, t.TaxonomyRef)
		}
		seen[t.ID] = struct{}{}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Lookup returns a catalogued technique by id. The second result is false for an unknown id, which the
// caller MUST treat as "not an emulation technique" rather than fabricating one.
func Lookup(id string) (Technique, bool) {
	for _, t := range catalogue {
		if t.ID == id {
			if t.Validate() != nil {
				return Technique{}, false
			}
			return t, true
		}
	}
	return Technique{}, false
}

func taxonomyIndex(ts []Technique, ref string) (int, bool) {
	for i, t := range ts {
		if t.TaxonomyRef == ref {
			return i, true
		}
	}
	return 0, false
}
