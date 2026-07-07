package sca

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// suppressedByFloor reports whether a vulnerability is NOT promoted to a finding because it
// falls below the severity floor. Only ACTIONABLE third-party vulns are gated: an unversioned
// (first-party-historic) advisory and an unknown-severity advisory are ALWAYS promoted. This is
// the single source of truth shared by buildFindings (what it skips) and countBelowThreshold
// (what it reports as hidden), so the "no silent gap" count can never drift from what was
// actually suppressed.
func suppressedByFloor(v vulnerability.Vulnerability, min int) bool {
	return !v.Unversioned && v.Severity != shared.SeverityUnknown && shared.SeverityRank(v.Severity) < min
}

// countBelowThreshold counts detected vulnerabilities that buildFindings will NOT promote
// because they fall below the severity floor. Surfaced on ScanResult so a raised floor can
// never silently hide detected vulns.
func countBelowThreshold(vulns []vulnerability.Vulnerability, minSeverity shared.Severity) int {
	min := shared.SeverityRank(minSeverity)
	n := 0
	for _, v := range vulns {
		if suppressedByFloor(v, min) {
			n++
		}
	}
	return n
}

// countUnfixedSuppressed counts vulnerabilities that buildFindings will NOT promote ONLY because
// --ignore-unfixed is on and they have no available fix (and they were not already below the
// severity floor). Surfaced so the suppression is visible, never silent.
func countUnfixedSuppressed(vulns []vulnerability.Vulnerability, minSeverity shared.Severity, ignoreUnfixed bool) int {
	if !ignoreUnfixed {
		return 0
	}
	min := shared.SeverityRank(minSeverity)
	n := 0
	for _, v := range vulns {
		if !suppressedByFloor(v, min) && v.FixedVersion == "" {
			n++
		}
	}
	return n
}

// layerNote renders the container-image layer attribution for a vuln (Epic D): which layer
// introduced it and whether that layer belongs to the base image (OS/distro rootfs) vs an
// application layer added on top — so a report tells an operator where to remediate (the base
// image vs. their own Dockerfile/app deps). Empty for non-image scans (no layer attributed).
func layerNote(v vulnerability.Vulnerability) string {
	if v.LayerID == "" || v.LayerIndex == nil {
		return ""
	}
	origin := "application layer"
	if v.InBaseImage {
		origin = "base image"
	}
	s := fmt.Sprintf("Image layer: %d (%s)", *v.LayerIndex, origin)
	if cmd := strings.TrimSpace(v.LayerCreatedBy); cmd != "" {
		const max = 120
		if r := []rune(cmd); len(r) > max {
			cmd = string(r[:max]) + "…"
		}
		s += ": " + cmd
	}
	return s
}

// noFixNote renders a human remediation note for a vuln with no fixed version, from its
// FixState, so the report reflects WHY there is no fix (vendor won't fix vs. not yet).
func noFixNote(state string) string {
	switch state {
	case "wont-fix":
		return "No fix available: the vendor will not fix this."
	case "deferred":
		return "No fix available: the vendor has deferred the fix."
	case "not-fixed":
		return "No fix available yet."
	default:
		return "No fix available."
	}
}

// buildFindings derives findings from a scan result: vulnerabilities at/above
// minSeverity (and, when ignoreUnfixed, only those with an available fix) and
// policy-denied licenses. Each finding has a deterministic id + dedup key so
// re-scans update in place (1:1), never duplicate.
func buildFindings(engagementID shared.ID, res *ScanResult, now time.Time, minSeverity shared.Severity, ignoreUnfixed bool, sastRaws []ports.SASTRawFinding) []finding.Finding {
	out := make([]finding.Finding, 0)
	min := shared.SeverityRank(minSeverity)

	for _, v := range res.Vulnerabilities {
		// An advisory matched to a component with no resolvable version (the project's
		// own first-party modules scanned from source) CANNOT be confirmed — there is
		// no version to compare to the affected range. These are recorded as
		// first-party historical advisories (informational), never as actionable
		// third-party findings, so they never pollute remediation queues or
		// critical/high counts (trust fix).
		class := finding.ClassThirdParty
		if v.Unversioned {
			class = finding.ClassFirstPartyHistoric
		}
		// Severity threshold applies to ACTIONABLE third-party findings only (an unversioned /
		// first-party-historic advisory and an unknown-severity advisory are always promoted) —
		// the same predicate countBelowThreshold reports on, so the two can never disagree.
		if suppressedByFloor(v, min) {
			continue
		}
		// --ignore-unfixed: a vulnerability with no available fix is not promoted to a finding
		// (it stays in the vuln inventory + is counted in UnfixedSuppressed, never silently lost).
		if ignoreUnfixed && v.FixedVersion == "" {
			continue
		}
		dedup := vulnDedupKey(v)
		desc := v.Description
		if v.FixedVersion != "" {
			desc = strings.TrimSpace(desc + "\nFixed in: " + v.FixedVersion)
		} else if note := noFixNote(v.FixState); note != "" {
			desc = strings.TrimSpace(desc + "\n" + note)
		}
		if note := layerNote(v); note != "" {
			desc = strings.TrimSpace(desc + "\n" + note)
		}
		out = append(out, finding.Finding{
			ID:                findingID(engagementID, dedup),
			EngagementID:      engagementID,
			Title:             fmt.Sprintf("%s in %s@%s", v.ID, v.Component, v.Version),
			Description:       desc,
			Severity:          v.Severity,
			CVSSVector:        v.CVSSVector,
			KEV:               v.KEV,
			RiskScore:         v.RiskScore(),
			Sources:           v.Sources,
			Confidence:        v.Confidence,
			Class:             class,
			Scope:             v.Scope,
			Reachability:      v.Reachability,
			ClassReachability: v.ClassReachability,
			Impact:            v.Impact,
			Priority:          v.Priority,
			Status:            finding.StatusOpen,
			Kind:              finding.KindSCA,
			DedupKey:          dedup,
			Audit:             shared.Audit{CreatedAt: now, UpdatedAt: now},
		})
	}

	for _, l := range res.Licenses {
		if l.Verdict != ports.LicenseDeny {
			continue
		}
		dedup := "license:" + l.License
		out = append(out, finding.Finding{
			ID:           findingID(engagementID, dedup),
			EngagementID: engagementID,
			Title:        "Denied license: " + l.License,
			Description:  "Policy-denied license used by: " + strings.Join(l.Components, ", "),
			Severity:     shared.SeverityMedium,
			Class:        finding.ClassThirdParty,
			Scope:        sbom.ScopeProduction,
			Reachability: vulnerability.ReachMedium,
			Impact:       vulnerability.ImpactMediumAction,
			Priority:     3,
			Status:       finding.StatusOpen,
			Kind:         finding.KindSCA,
			DedupKey:     dedup,
			Audit:        shared.Audit{CreatedAt: now, UpdatedAt: now},
		})
	}
	for _, sr := range sastRaws {
		// Deterministic pattern-SAST hit: first-party, actionable, ungated (ProposedBy == ""),
		// publishable like SCA. Respect the engagement severity threshold (Unknown always promoted).
		if sr.Severity != shared.SeverityUnknown && shared.SeverityRank(sr.Severity) < min {
			continue
		}
		// Dedup on rule+file+line so a re-scan updates in place (1:1).
		dedup := "sast:" + sr.RuleID + ":" + sr.File + ":" + strconv.Itoa(sr.Line)
		scope := sbom.ClassifyScope(sr.File, "")
		confidence := sr.Confidence
		if confidence == "" {
			confidence = vulnerability.ConfidenceForSources(1)
		}
		out = append(out, finding.Finding{
			ID:           findingID(engagementID, dedup),
			EngagementID: engagementID,
			Title:        fmt.Sprintf("%s (%s:%d)", sr.Title, sr.File, sr.Line),
			Description:  sastDescription(sr),
			Severity:     sr.Severity,
			CWE:          sr.CWE,
			Sources:      []string{"synapse-pattern-sast"},
			Confidence:   confidence,
			Class:        finding.ClassFirstParty,
			Scope:        scope,
			Reachability: vulnerability.Reachability(scope, true),
			Impact:       vulnerability.Impact(sr.Severity, scope),
			Priority:     sastPriority(sr.Severity),
			Status:       finding.StatusOpen,
			Kind:         finding.KindSAST,
			DedupKey:     dedup,
			Audit:        shared.Audit{CreatedAt: now, UpdatedAt: now},
		})
	}
	return out
}

// buildSecretFindings turns redacted secret hits into ungated Kind=secret findings (deterministic,
// publishable like SCA). The Match is already redacted by the scanner, so the raw credential is never
// stored in the finding, the evidence seal, or the report.
func buildSecretFindings(engagementID shared.ID, raws []ports.SecretRawFinding, now time.Time, minSeverity shared.Severity) []finding.Finding {
	min := shared.SeverityRank(minSeverity)
	out := make([]finding.Finding, 0, len(raws))
	for _, sr := range raws {
		if sr.Severity != shared.SeverityUnknown && shared.SeverityRank(sr.Severity) < min {
			continue
		}
		// Dedup on rule+file+line so a re-scan updates in place (1:1).
		dedup := "secret:" + sr.RuleID + ":" + sr.File + ":" + strconv.Itoa(sr.Line)
		scope := sbom.ClassifyScope(sr.File, "")
		out = append(out, finding.Finding{
			ID:           findingID(engagementID, dedup),
			EngagementID: engagementID,
			Title:        fmt.Sprintf("%s (%s:%d)", sr.Title, sr.File, sr.Line),
			Description:  secretDescription(sr),
			Severity:     sr.Severity,
			Sources:      []string{"synapse-secret-scan"},
			Confidence:   vulnerability.ConfidenceForSources(1),
			Class:        finding.ClassFirstParty,
			Scope:        scope,
			// Reachability/Impact are left empty on purpose: a hardcoded secret is a PRESENCE fact, not a
			// reachable-code weakness, so the scope+severity impact model the SAST loop uses does not apply.
			Priority: sastPriority(sr.Severity),
			Status:   finding.StatusOpen,
			Kind:     finding.KindSecret,
			DedupKey: dedup,
			Audit:    shared.Audit{CreatedAt: now, UpdatedAt: now},
		})
	}
	return out
}

func secretDescription(sr ports.SecretRawFinding) string {
	return fmt.Sprintf("A %s secret was detected (rule %s). Rotate the credential and remove it from source; prefer a secret manager or environment injection. Match (redacted): %s",
		sr.Category, sr.RuleID, sr.Match)
}

func sastDescription(sr ports.SASTRawFinding) string {
	desc := strings.TrimSpace(sr.Description)
	proof := []string{}
	if sr.OWASP2025 != "" {
		proof = append(proof, "OWASP/CWE mapping: "+sr.OWASP2025+" / "+sr.CWE)
	}
	if sr.EntryPoint != "" && sr.EntryPoint != sr.Route {
		proof = append(proof, "Entrypoint/control: "+sr.EntryPoint)
	}
	if sr.Source != "" {
		proof = append(proof, "Source: "+sr.Source)
	}
	if sr.SourceEvidence != "" {
		proof = append(proof, "Source evidence: "+sr.SourceEvidence)
	}
	if sr.Sink != "" {
		proof = append(proof, "Sink/control: "+sr.Sink)
	}
	if sr.SinkEvidence != "" {
		proof = append(proof, "Sink evidence: "+sr.SinkEvidence)
	}
	if sr.ControlEvidence != "" {
		proof = append(proof, "Control evidence: "+sr.ControlEvidence)
	}
	if sr.RouteMiddleware != "" {
		proof = append(proof, "Route middleware: "+sr.RouteMiddleware)
	}
	if sr.AuthEvidence != "" {
		proof = append(proof, "Auth evidence: "+sr.AuthEvidence)
	}
	if sr.Exposure != "" {
		proof = append(proof, "Exposure: "+sr.Exposure)
	}
	if sr.TrustBoundary != "" {
		proof = append(proof, "Trust boundary: "+sr.TrustBoundary)
	}
	if sr.Impact != "" {
		proof = append(proof, "Impact hypothesis: "+sr.Impact)
	}
	if sr.Route != "" {
		proof = append(proof, "Route reachability: "+sr.Route)
	}
	if sr.AuthScope != "" {
		auth := sr.AuthScope
		if sr.RoleCheck != "" {
			auth += " (" + sr.RoleCheck + ")"
		}
		proof = append(proof, "Auth/role context: "+auth)
	}
	if sr.DataFlow != "" {
		proof = append(proof, "Dataflow: "+sr.DataFlow)
	}
	if sr.DataFlowEvidence != "" {
		proof = append(proof, "Dataflow evidence: "+sr.DataFlowEvidence)
	}
	if sr.DataFlowConfidence != "" {
		proof = append(proof, "Dataflow confidence: "+sr.DataFlowConfidence)
	}
	if sr.ValidationMethod != "" || sr.ValidationDisposition != "" {
		validation := strings.TrimSpace(sr.ValidationMethod + " / " + sr.ValidationDisposition)
		validation = strings.Trim(validation, " /")
		proof = append(proof, "Validation receipt: "+validation)
	}
	if sr.Preconditions != "" {
		proof = append(proof, "Preconditions/proof gaps: "+sr.Preconditions)
	}
	if sr.CounterEvidence != "" {
		proof = append(proof, "Counterevidence: "+sr.CounterEvidence)
	}
	if sr.ValidationRubric != "" {
		proof = append(proof, "Validation rubric: "+sr.ValidationRubric)
	}
	if sr.Exploitability != "" {
		proof = append(proof, "Exploitability validation: "+sr.Exploitability)
	}
	if sr.AttackPath != "" {
		proof = append(proof, "Attack-path calibration: "+sr.AttackPath)
	}
	if sr.SeverityRationale != "" {
		proof = append(proof, "Severity rationale: "+sr.SeverityRationale)
	}
	if len(proof) == 0 {
		return desc
	}
	if desc != "" {
		desc += "\n\n"
	}
	return desc + "AppSec validation envelope:\n- " + strings.Join(proof, "\n- ")
}

// sastPriority maps a SAST severity to the unified risk priority (1 highest.. 5). SAST hits have no
// KEV/EPSS, so priority comes straight from severity; 1 stays reserved for KEV-driven SCA findings.
func sastPriority(sev shared.Severity) int {
	switch sev {
	case shared.SeverityCritical, shared.SeverityHigh:
		return 2
	case shared.SeverityMedium:
		return 3
	default:
		return 4
	}
}

// findingID is a stable id derived from the engagement + dedup key, so the same
// issue always maps to the same finding across re-scans.
func findingID(engagementID shared.ID, dedupKey string) shared.ID {
	sum := sha256.Sum256([]byte(engagementID.String() + "|" + dedupKey))
	return shared.ID(hex.EncodeToString(sum[:16]))
}

// vulnDedupKey is the idempotency key for a vuln-derived finding (advisory+component+version). It is the
// single source of truth shared by buildFindings (which sets it as the finding's DedupKey) and
// reachabilitySubjects (which joins back to it) — so the reachability subject's FindingID provably matches
// a persisted finding and the two can never drift.
func vulnDedupKey(v vulnerability.Vulnerability) string {
	return "vuln:" + v.ID + ":" + v.Component + ":" + v.Version
}

// reachabilitySubjects builds the per-finding reachability inputs: each PROMOTED finding that maps
// to an advisory carrying affected symbols becomes a subject keyed by the real finding id. Joining via the
// finding's DedupKey (the "vuln:id:component:version" key buildFindings derives) guarantees the subject's
// FindingID matches a persisted finding, and only advisories with symbols (the Go vuln DB form) are worth
// a symbol-level reachability query — non-symbol findings are skipped.
func reachabilitySubjects(findings []finding.Finding, vulns []vulnerability.Vulnerability) []ports.ReachabilitySubject {
	byDedup := make(map[string]vulnerability.Vulnerability, len(vulns))
	for _, v := range vulns {
		byDedup[vulnDedupKey(v)] = v
	}
	var subs []ports.ReachabilitySubject
	for _, f := range findings {
		if v, ok := byDedup[f.DedupKey]; ok && len(v.AffectedSymbols) > 0 {
			subs = append(subs, ports.ReachabilitySubject{FindingID: f.ID, Symbols: v.AffectedSymbols})
		}
	}
	return subs
}

// detectionSourceNames returns the names of the run detection sources — the cross-check "run set",
// so a source that ran but reported nothing for a vuln is correctly flagged as a disagreement.
func detectionSourceNames(sources []ports.DetectionSource) []string {
	out := make([]string, 0, len(sources))
	for _, src := range sources {
		out = append(out, src.Name())
	}
	return out
}
