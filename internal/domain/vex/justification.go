// Package vex holds the OpenVEX domain vocabulary (the closed justification enum, shared by the VEX export
// and the AI vex-justification judgment) AND the consume-side parser + product-to-finding matcher
// (document.go: Parse, Statement.Suppresses, Statement.MatchesFinding) shared by the post-scan VEX apply
// and the in-scan .vex consumer. Pure: parsing + matching only, no I/O beyond the passed-in bytes.
package vex

// OpenVexJustification is the CLOSED set of OpenVEX justifications for a not_affected status (per the OpenVEX
// spec). A justification is a STRUCTURED choice, never free prose – so it can ride in a judgment claim (R8).
type OpenVexJustification string

const (
	// ComponentNotPresent: the vulnerable component is not in the product at all.
	ComponentNotPresent OpenVexJustification = "component_not_present"
	// VulnerableCodeNotPresent: the component is present but the vulnerable code is not included.
	VulnerableCodeNotPresent OpenVexJustification = "vulnerable_code_not_present"
	// VulnerableCodeNotInExecutePath: the vulnerable code is present but never on an executed path.
	VulnerableCodeNotInExecutePath OpenVexJustification = "vulnerable_code_not_in_execute_path"
	// VulnerableCodeCannotBeControlled: the vulnerable code executes but an adversary cannot control the inputs.
	VulnerableCodeCannotBeControlled OpenVexJustification = "vulnerable_code_cannot_be_controlled_by_adversary"
	// InlineMitigationsAlreadyExist: a compensating control already neutralizes the vulnerability.
	InlineMitigationsAlreadyExist OpenVexJustification = "inline_mitigations_already_exist"
)

// Valid reports whether j is one of the five OpenVEX not_affected justifications (fail-closed).
func (j OpenVexJustification) Valid() bool {
	switch j {
	case ComponentNotPresent, VulnerableCodeNotPresent, VulnerableCodeNotInExecutePath,
		VulnerableCodeCannotBeControlled, InlineMitigationsAlreadyExist:
		return true
	}
	return false
}
