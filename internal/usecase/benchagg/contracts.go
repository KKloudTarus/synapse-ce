package benchagg

import "fmt"

// The truth-contract manifest is the #1040 acceptance artifact "each dimension has a versioned truth contract,
// provenance, positive/negative cases, Unknown/NotAssessed semantics, and a committed ratchet". It records, per
// benchmark dimension and in one machine-readable place, what a positive is, how the corpus is built (provenance),
// how the dimension treats an unknown/unassessable input (the no-false-suppression posture: an unknown must never
// be reported as a clean/compliant result), and the committed recall/precision floors the dimension gates on.
// The types and Validate here are pure (no I/O); a test loads the committed JSON and validates it, so the
// contract is checked on every run without the usecase layer reaching the filesystem.

// ContractSchemaVersion tags the serialized truth-contract manifest.
const ContractSchemaVersion = "synapse-dimension-contracts-v1"

// Contract is one dimension's versioned truth contract.
type Contract struct {
	// Positive states what a positive case is for this dimension (its own truth semantics, never another's).
	Positive string `json:"positive"`
	// Unit is the counted entity (finding, resource, observation).
	Unit string `json:"unit"`
	// UnknownSemantics states how the dimension treats an input it cannot assess. Every dimension must document
	// this, because the EPIC's no-false-suppression guardrail forbids converting an unknown into a clean result.
	// A dimension whose corpus is closed states that explicitly (there is no unknown state), rather than leaving
	// it blank.
	UnknownSemantics string `json:"unknown_semantics"`
	// Provenance records how the labeled corpus is produced, so a reader can reproduce the numbers.
	Provenance string `json:"provenance"`
	// RecallFloor / PrecisionFloor are the committed ratchets the dimension's gate enforces (documented here so
	// the truth contract and the gate are read together). A floor of 0 means that metric is not gated.
	RecallFloor    float64 `json:"recall_floor"`
	PrecisionFloor float64 `json:"precision_floor"`
}

// ContractManifest is the committed set of per-dimension truth contracts, keyed by dimension id.
type ContractManifest struct {
	Schema     string              `json:"schema"`
	Dimensions map[string]Contract `json:"dimensions"`
}

// Validate reports whether the manifest is internally well-formed: the current schema, at least one dimension,
// and every contract complete (a positive, a unit, documented Unknown semantics, provenance, and floors within
// [0,1]). It does not measure anything; it guards the committed artifact against an incomplete or malformed
// contract, so a dimension can never ship a truth contract that omits its Unknown/NotAssessed posture.
func (m ContractManifest) Validate() error {
	if m.Schema != ContractSchemaVersion {
		return fmt.Errorf("benchagg: contract manifest schema %q, want %q", m.Schema, ContractSchemaVersion)
	}
	if len(m.Dimensions) == 0 {
		return fmt.Errorf("benchagg: contract manifest has no dimensions")
	}
	for id, c := range m.Dimensions {
		if id == "" {
			return fmt.Errorf("benchagg: contract manifest has an empty dimension id")
		}
		if c.Positive == "" || c.Unit == "" {
			return fmt.Errorf("benchagg: dimension %q must state its positive and unit", id)
		}
		if c.UnknownSemantics == "" {
			return fmt.Errorf("benchagg: dimension %q must document its Unknown/NotAssessed semantics (no-false-suppression)", id)
		}
		if c.Provenance == "" {
			return fmt.Errorf("benchagg: dimension %q must record its corpus provenance", id)
		}
		if !inUnitRange(c.RecallFloor) || !inUnitRange(c.PrecisionFloor) {
			return fmt.Errorf("benchagg: dimension %q floors must be within [0,1] (recall %v, precision %v)", id, c.RecallFloor, c.PrecisionFloor)
		}
	}
	return nil
}

func inUnitRange(x float64) bool { return x >= 0 && x <= 1 }
