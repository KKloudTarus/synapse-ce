package riskassessment

import "github.com/KKloudTarus/synapse-ce/internal/domain/shared"

// ThreatFromSeverity maps a runtime-detection severity (the label an incident carries, derived from the
// max severity of its correlated detections) to the RiskContext.Threat factor (0..100). It is the
// severity→factor projection the tri-score assembler uses for the Threat axis — a deterministic policy
// mapping, mirroring the shape of the exposure factor's priority bands. Unknown severity yields 0 (which
// lowers Coverage/Confidence, never Risk — the honest "we don't know" value).
func ThreatFromSeverity(sev shared.Severity) Score {
	switch sev {
	case shared.SeverityCritical:
		return 100
	case shared.SeverityHigh:
		return 80
	case shared.SeverityMedium:
		return 55
	case shared.SeverityLow:
		return 30
	case shared.SeverityInfo:
		return 10
	default: // SeverityUnknown or any unrecognized value
		return 0
	}
}
