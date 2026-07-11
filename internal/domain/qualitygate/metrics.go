package qualitygate

// Metric name constants for a gate condition. "new_*" metrics count only findings on new/changed code
// (Clean as You Code); the others are whole-codebase. Ratings are numeric: A=1, B=2, C=3, D=4, E=5, so
// `security_rating <= 1` means "must be A".
const (
	MetricNewCritical      = "new_critical"      // new findings with critical severity
	MetricNewHigh          = "new_high"          // new findings with high severity
	MetricNewMedium        = "new_medium"        // new findings with medium severity
	MetricNewSecret        = "new_secret"        // new secret findings
	MetricNewVulnerability = "new_vulnerability" // new security findings (sca/sast/secret/misconfig)
	MetricNewIssues        = "new_issues"        // all new findings
	MetricTotalCritical    = "total_critical"    // whole-codebase critical findings
	MetricDuplicationPct   = "duplication_density"
	MetricCoveragePct      = "coverage"
	MetricSecurityRating   = "security_rating"
	MetricReliability      = "reliability_rating"
	MetricMaintainability  = "maintainability_rating"
)

// Default returns the built-in "clean new code" gate: no new critical/high findings, no new secrets, and
// A ratings on the whole codebase. It mirrors the widely used default of gating strictly on new code
// while holding overall ratings at their best. Override with a .synapse-gate.yaml.
func Default() Gate {
	return Gate{Conditions: []Condition{
		{Metric: MetricNewCritical, Op: OpLE, Threshold: 0},
		{Metric: MetricNewHigh, Op: OpLE, Threshold: 0},
		{Metric: MetricNewSecret, Op: OpLE, Threshold: 0},
		{Metric: MetricSecurityRating, Op: OpLE, Threshold: 1},
		{Metric: MetricReliability, Op: OpLE, Threshold: 1},
	}}
}
