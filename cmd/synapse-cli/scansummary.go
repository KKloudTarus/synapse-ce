package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

// pushStatusWriter is where push status lines go. They sit beside the human report on stdout, but a
// machine-readable document owns stdout outright, so while one is written they go to stderr with the
// other progress lines. SARIF written to a file leaves stdout to the human report.
func pushStatusWriter(jsonOut, sbomOut, sarifOut bool, sarifPath string) io.Writer {
	if jsonOut || sbomOut || (sarifOut && sarifPath == "") {
		return os.Stderr
	}
	return os.Stdout
}

// writeScanCompletionSummary closes a --json scan on stderr with what a reader would otherwise have to
// dig out of the document: whether every required engine completed, which did not and why, and the
// source warnings. It reads the structured engine outcomes and coverage, never the warning text, so an
// engine left out on purpose is reported as excluded rather than as a failure. Warnings are printed in
// full, because a truncated one is where the reason gets cut.
func writeScanCompletionSummary(w io.Writer, res *scauc.ScanResult) {
	coverage := res.EngineCoverage
	if coverage.Required == 0 {
		_, _ = fmt.Fprintf(w, "synapse-cli: engine coverage %s: no required engine outcome was recorded\n", coverage.Status)
	} else {
		_, _ = fmt.Fprintf(w, "synapse-cli: engine coverage %s: %d of %d required engine(s) completed\n", coverage.Status, coverage.Completed, coverage.Required)
	}
	var excluded []string
	for _, o := range res.EngineOutcomes {
		if !o.Required {
			excluded = append(excluded, fmt.Sprintf("%s (%s)", o.Engine, reasonText(o.Reason, "not required")))
			continue
		}
		if o.Execution == scanrun.EngineCompleted && o.Coverage == scanrun.CoverageComplete {
			continue
		}
		_, _ = fmt.Fprintf(w, "synapse-cli:   incomplete: %s %s (%s), coverage %s\n", o.Engine, o.Execution, reasonText(o.Reason, "no reason recorded"), o.Coverage)
	}
	if len(excluded) > 0 {
		_, _ = fmt.Fprintf(w, "synapse-cli:   excluded from this scan: %s\n", strings.Join(excluded, ", "))
	}
	for _, warning := range res.SourceWarnings {
		_, _ = fmt.Fprintf(w, "synapse-cli: warning: %s\n", warning)
	}
}

func reasonText(reason scanrun.EngineReason, fallback string) string {
	if reason == scanrun.ReasonNone {
		return fallback
	}
	return string(reason)
}
