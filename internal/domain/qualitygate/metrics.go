package qualitygate

// Metric name constants for a gate condition. "new_*" metrics count only findings on new/changed code
// (Clean as You Code); the others are whole-codebase. Ratings are numeric: A=1, B=2, C=3, D=4, E=5, so
// `security_rating <= 1` means "must be A".
const (
	MetricNewCritical                 = "new_critical"      // new findings with critical severity
	MetricNewHigh                     = "new_high"          // new findings with high severity
	MetricNewMedium                   = "new_medium"        // new findings with medium severity
	MetricNewSecret                   = "new_secret"        // new secret findings
	MetricNewVulnerability            = "new_vulnerability" // new security findings (sca/sast/secret/misconfig/exploitation/dast)
	MetricNewIssues                   = "new_issues"        // all new findings
	MetricTotalCritical               = "total_critical"    // whole-codebase critical findings
	MetricDuplicationPct              = "duplication_density"
	MetricCoveragePct                 = "coverage"
	MetricSecurityRating              = "security_rating"
	MetricReliability                 = "reliability_rating"
	MetricMaintainability             = "maintainability_rating"
	MetricSecurityHotspotsReviewed    = "security_hotspots_reviewed"
	MetricNewSecurityHotspotsReviewed = "new_security_hotspots_reviewed"
	MetricNewCoverage                 = "new_coverage"    // line coverage on new/changed code
	MetricNewDuplication              = "new_duplication" // duplication density on new/changed code
)

// knownMetrics is the set a gate condition may reference, so a typo'd metric name is rejected at load
// time (a metric absent from the snapshot reads as 0, which could otherwise silently pass a gate).
// NOTE: `coverage`, `new_coverage`, and `new_duplication` are accepted as valid condition metrics but are
// not yet measured (coverage lands with the coverage-import phase; the new-code variants need retained
// changed-line data). Until then each reads 0 from the snapshot: a `>=` coverage condition fails closed,
// and a `<=` new_duplication condition passes at 0. They are offered so a custom gate can encode the
// Clean-as-You-Code policy now and start enforcing the moment the measurement lands.
var knownMetrics = map[string]bool{
	MetricNewCritical: true, MetricNewHigh: true, MetricNewMedium: true, MetricNewSecret: true,
	MetricNewVulnerability: true, MetricNewIssues: true, MetricTotalCritical: true,
	MetricDuplicationPct: true, MetricCoveragePct: true,
	MetricSecurityRating: true, MetricReliability: true, MetricMaintainability: true,
	MetricSecurityHotspotsReviewed: true, MetricNewSecurityHotspotsReviewed: true,
	MetricNewCoverage: true, MetricNewDuplication: true,
}

// ValidMetric reports whether name is a recognized gate metric.
func ValidMetric(name string) bool { return knownMetrics[name] }

// Default returns the built-in "clean new code" gate: no new critical/high findings, no new secrets, and
// A ratings on the whole codebase. It mirrors the widely used default of gating strictly on new code
// while holding overall ratings at their best. Override with a .synapse-gate.yaml.
func Default() Gate {
	return Gate{Key: "synapse-way", Name: "Synapse way", BuiltIn: true, Conditions: []Condition{
		{Metric: MetricNewCritical, Op: OpLE, Threshold: 0},
		{Metric: MetricNewHigh, Op: OpLE, Threshold: 0},
		{Metric: MetricNewSecret, Op: OpLE, Threshold: 0},
		{Metric: MetricSecurityRating, Op: OpLE, Threshold: 1},
		{Metric: MetricReliability, Op: OpLE, Threshold: 1},
	}}
}
