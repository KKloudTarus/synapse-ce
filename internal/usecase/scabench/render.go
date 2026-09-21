package scabench

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

// RenderResult writes a deterministic, quoted plain-text representation of a validated result.
// Quoting all externally supplied text makes line and delimiter injection unambiguous.
func RenderResult(writer io.Writer, result Result) error {
	if err := result.Validate(); err != nil {
		return fmt.Errorf("validate result: %w", err)
	}
	result = canonicalResult(result)
	var out strings.Builder
	line := func(format string, args ...any) {
		fmt.Fprintf(&out, format, args...)
		out.WriteByte('\n')
	}
	quote := strconv.Quote
	metric := func(value *float64) string {
		if value == nil {
			return "null"
		}
		return strconv.FormatFloat(*value, 'g', -1, 64)
	}
	writeMetrics := func(prefix string, summary EngineResult) {
		line("%sengine: %s", prefix, quote(string(summary.Engine)))
		line("%scovered: %d", prefix, summary.Covered)
		line("%sunknown: %d", prefix, summary.Unknown)
		line("%sunsupported: %d", prefix, summary.Unsupported)
		line("%sincomplete: %d", prefix, summary.Incomplete)
		line("%saffected_relations: %d", prefix, summary.AffectedRelations)
		line("%snegative_relations: %d", prefix, summary.NegativeRelations)
		line("%strue_positives: %d", prefix, summary.TruePositives)
		line("%sfalse_positives: %d", prefix, summary.FalsePositives)
		line("%sfalse_negatives: %d", prefix, summary.FalseNegatives)
		line("%smetrics_complete: %t", prefix, summary.MetricsComplete)
		line("%sprecision: %s", prefix, metric(summary.Precision))
		line("%srecall: %s", prefix, metric(summary.Recall))
	}
	writeRun := func(prefix string, run RunIdentity) {
		line("%scatalog_revision: %s", prefix, quote(run.CatalogRevision))
		line("%scatalog_digest: %s", prefix, quote(run.CatalogDigest))
		line("%sengine: %s", prefix, quote(string(run.Engine)))
		line("%sengine_version: %s", prefix, quote(run.EngineVersion))
		line("%sengine_binary_digest: %s", prefix, quote(run.EngineBinaryDigest))
		line("%sdatabase_build: %s", prefix, quote(run.DatabaseBuild))
		line("%sdatabase_digest: %s", prefix, quote(run.DatabaseDigest))
		line("%senvironment_id: %s", prefix, quote(run.EnvironmentID))
		line("%senvironment_digest: %s", prefix, quote(run.EnvironmentDigest))
		line("%starget_id: %s", prefix, quote(run.TargetID))
		line("%starget_digest: %s", prefix, quote(run.TargetDigest))
		line("%ssbom_digest: %s", prefix, quote(run.SBOMDigest))
		line("%sstate: %s", prefix, quote(string(run.State)))
		line("%sconfig_digest: %s", prefix, quote(run.ConfigDigest))
		if run.CapabilityKind != "" {
			line("%scapability_kind: %s", prefix, quote(string(run.CapabilityKind)))
			line("%scapability_digest: %s", prefix, quote(run.CapabilityDigest))
		}
	}
	writeExpected := func(prefix string, expected ExpectedRunIdentity) {
		line("%starget_id: %s", prefix, quote(expected.TargetID))
		line("%starget_digest: %s", prefix, quote(expected.TargetDigest))
		line("%ssbom_digest: %s", prefix, quote(expected.SBOMDigest))
		line("%sengine: %s", prefix, quote(string(expected.Engine)))
		line("%sengine_version: %s", prefix, quote(expected.EngineVersion))
		line("%sengine_binary_digest: %s", prefix, quote(expected.EngineBinaryDigest))
		line("%sdatabase_build: %s", prefix, quote(expected.DatabaseBuild))
		line("%sdatabase_digest: %s", prefix, quote(expected.DatabaseDigest))
		line("%senvironment_id: %s", prefix, quote(expected.EnvironmentID))
		line("%senvironment_digest: %s", prefix, quote(expected.EnvironmentDigest))
		line("%sconfig_digest: %s", prefix, quote(expected.ConfigDigest))
		if expected.CapabilityKind != "" {
			line("%scapability_kind: %s", prefix, quote(string(expected.CapabilityKind)))
			line("%scapability_digest: %s", prefix, quote(expected.CapabilityDigest))
		}
	}

	line("SCA Benchmark Result")
	line("schema_version: %s", quote(result.SchemaVersion))
	line("id: %s", quote(result.ID))
	line("catalog_revision: %s", quote(result.CatalogRevision))
	line("catalog_digest: %s", quote(result.CatalogDigest))
	line("oracle_digest: %s", quote(result.OracleDigest))
	line("scoring_observation_digest: %s", quote(result.ScoringObservationDigest))
	line("interpretation:")
	line("  oracle_provenance: %s", quote("scanner-independent truth derived from frozen Debian, SLES, and Red Hat vendor evidence"))
	line("  owned_database_coupling: %s", quote("owned consumes the corresponding pinned vendor OVAL and CSAF; comparator engines consume their own pinned database snapshots"))
	line("  engine_database_scope: %s", quote("see each run_metrics database_build and database_digest"))
	line("  comparative_limit: %s", quote("scores measure agreement with the frozen vendor oracle; differences can reflect database provenance or snapshot timing and do not establish abstract market-wide accuracy"))
	line("targets:")
	for _, target := range result.Targets {
		line("  - id: %s", quote(target.ID))
		line("    target_digest: %s", quote(target.Digest))
		line("    sbom_digest: %s", quote(target.SBOMDigest))
	}
	if result.Gate == nil {
		line("gate: absent")
	} else {
		line("gate:")
		line("  ratchet_digest: %s", quote(result.Gate.RatchetDigest))
		line("  gate_outcome: %s", quote(renderGateOutcome(*result.Gate)))
		line("  accuracy_status: %s", quote(renderGateAccuracyStatus(result, *result.Gate)))
		line("  passed: %t", result.Gate.Passed)
		line("  checks:")
		for i, check := range result.Gate.Checks {
			line("    - gate_outcome: %s", quote(renderCheckOutcome(check)))
			line("      accuracy_status: %s", quote(renderCheckAccuracyStatus(result, check)))
			line("      passed: %t", check.Passed)
			line("      mode: %s", quote(string(check.Mode.effective())))
			line("      allow_undefined_precision: %t", result.Gate.Ratchet.Floors[i].AllowUndefinedPrecision)
			writeExpected("      expected_", check.Expected)
			if check.Actual == nil {
				line("      actual: absent")
			} else {
				writeRun("      actual_", *check.Actual)
			}
			line("      reason_codes: [%s]", renderReasons(check.ReasonCodes))
		}
	}
	line("engine_summaries:")
	for _, summary := range result.Engines {
		line("  -")
		writeMetrics("    ", summary)
	}
	line("run_metrics:")
	for _, runMetric := range result.RunMetrics {
		line("  - run:")
		writeRun("      ", runMetric.Run)
		line("    metrics:")
		writeMetrics("      ", runMetric.Metrics)
	}
	line("diagnostics:")
	for _, diagnostic := range result.Diagnostics {
		line("  - engine: %s", quote(string(diagnostic.Engine)))
		line("    target_id: %s", quote(diagnostic.TargetID))
		line("    code: %s", quote(string(diagnostic.Code)))
		line("    detail: %s", quote(diagnostic.Detail))
	}
	if _, err := io.WriteString(writer, out.String()); err != nil {
		return fmt.Errorf("write rendered result: %w", err)
	}
	return nil
}

func renderReasons(reasons []GateReasonCode) string {
	values := make([]string, len(reasons))
	for i, reason := range reasons {
		values[i] = strconv.Quote(string(reason))
	}
	return strings.Join(values, ", ")
}

func renderGateOutcome(gate Gate) string {
	if !gate.Passed {
		return "failed"
	}
	accuracy, unsupportedOnly := false, false
	for _, check := range gate.Checks {
		if check.Mode.effective() == FloorGateModeUnsupportedOnly {
			unsupportedOnly = true
		} else {
			accuracy = true
		}
	}
	switch {
	case accuracy && unsupportedOnly:
		return "mixed_passed"
	case unsupportedOnly:
		return "unsupported_only_passed"
	default:
		return "accuracy_passed"
	}
}

func renderGateAccuracyStatus(result Result, gate Gate) string {
	measured, unavailable, unmeasured := 0, 0, 0
	for _, check := range gate.Checks {
		switch renderCheckAccuracyStatus(result, check) {
		case "measured":
			measured++
		case "unavailable":
			unavailable++
		default:
			unmeasured++
		}
	}
	switch {
	case measured == len(gate.Checks):
		return "measured"
	case measured > 0:
		return "partially_measured"
	case unavailable > 0:
		return "unavailable"
	case unmeasured > 0:
		return "unmeasured"
	default:
		return "unmeasured"
	}
}

func renderCheckOutcome(check GateCheck) string {
	if check.Mode.effective() == FloorGateModeUnsupportedOnly {
		if check.Passed {
			return "unsupported_only_passed"
		}
		return "unsupported_only_failed"
	}
	if check.Passed {
		return "accuracy_passed"
	}
	return "accuracy_failed"
}

func renderCheckAccuracyStatus(result Result, check GateCheck) string {
	if check.Mode.effective() == FloorGateModeUnsupportedOnly || check.Actual == nil {
		return "unmeasured"
	}
	for _, runMetric := range result.RunMetrics {
		if sameRunIdentity(runMetric.Run, *check.Actual) {
			if !runMetric.Metrics.MetricsComplete || runMetric.Metrics.Precision == nil || runMetric.Metrics.Recall == nil {
				return "unavailable"
			}
			return "measured"
		}
	}
	return "unmeasured"
}
