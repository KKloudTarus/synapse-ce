// Package sca orchestrates the Software Composition Analysis pipeline. Scope and
// the engagement authorization window are enforced HERE (the execution layer),
// before any tool runs — never as a skippable check.
package sca

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/distro"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedsbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service orchestrates the SCA pipeline over swappable ports.
type Service struct {
	engagements    ports.EngagementRepository
	findings       ports.FindingRepository
	scans          ports.ScanRepository
	results        ports.ScanResultStore
	importedSBOM   ports.ImportedSBOMStore
	jobs           ports.ScanJobStore
	runs           ports.ScanRunStore
	evidence       *evidenceuc.Service
	ids            ports.IDGenerator
	jobQueue       ports.JobQueue  // optional; when set, StartScan defers to the durable queue
	runLock        ports.RunLocker // optional; guards single active execution per scan job
	prov           ports.Provenance
	clock          ports.Clock
	audit          ports.AuditLogger
	minSeverity    shared.Severity
	timeout        time.Duration
	acquirer       ports.Acquirer
	detector       ports.LanguageDetector
	sbomGen        ports.SBOMGenerator
	sources        []ports.DetectionSource
	riskEnricher   ports.RiskEnricher
	licScan        ports.LicenseScanner
	licEnricher    ports.LicenseEnricher
	sbomEnricher   ports.SBOMEnricher            // optional manifest enrichment (gem edges, maven/gradle deps, pnpm scope)
	licCoord       ports.MavenCoordResolver      // optional: recover real Maven coords from JAR pom.properties before license lookup
	jarHash        ports.JarHashResolver         // optional: recover coords of shaded/metadata-less JARs via SHA-1
	licFile        ports.LicenseFileResolver     // optional offline license-text fallback from JAR LICENSE files
	sastAnalyzer   ports.SASTAnalyzer            // optional deterministic pattern-SAST over the live workspace
	secretScanner  ports.SecretScanner           // optional deterministic secret scan over the live workspace
	reachability   ports.ReachabilityRecorder    // optional deterministic Tier-2 reachability proof
	correlation    ports.CorrelationRecorder     // optional cross-check disagreement → judgment minter
	sbomGen2       ports.SBOMGenerator           // optional 2nd SBOM producer for the cross-check
	sbomCrossCheck ports.SBOMCrossCheckRecorder  // optional SBOM-producer disagreement → judgment minter
	taint          ports.TaintScanner            // optional deterministic taint-analysis → gated CapSAST proposals
	graphResolver  ports.DependencyGraphResolver // optional transitive-edge resolver (Go via `go mod graph`)
	mavenResolver  ports.MavenResolver           // optional Maven transitive-tree resolver (`mvn dependency:list`)
	gradleResolver ports.GradleResolver          // optional Gradle transitive-tree resolver (`gradle dependencies`)
	jvmReach       ports.JVMReachabilityAnalyzer // optional coarse JVM class-reachability tagger
	sevEnricher    ports.SeverityEnricher        // optional NVD CVSS backfill for unknown-severity vulns
	ignoreUnfixed  bool                          // when set, don't promote no-fix vulns to findings (Trivy --ignore-unfixed)
	guard          *execution.Guard              // shared scope + window + audit gate; built in NewService
}

// SetSeverityEnricher configures optional severity backfill (NVD CVSS) for vulnerabilities the
// detection sources left unknown. Best-effort + bounded; nil skips it. Runs before risk
// enrichment so risk priority can use the backfilled CVSS.
func (s *Service) SetSeverityEnricher(e ports.SeverityEnricher) { s.sevEnricher = e }

// SetImportedSBOMStore configures the engagement-scoped client SBOM artifact store.
func (s *Service) SetImportedSBOMStore(store ports.ImportedSBOMStore) { s.importedSBOM = store }

// SetIgnoreUnfixed controls whether vulnerabilities with no available fix are promoted to
// findings. true = suppress them (Trivy's --ignore-unfixed); they stay in the vuln inventory.
func (s *Service) SetIgnoreUnfixed(v bool) { s.ignoreUnfixed = v }

// SetSBOMEnricher configures optional manifest-based SBOM enrichment.
// Best-effort: nil leaves the generator's SBOM untouched. A setter (not a
// constructor param) keeps the many existing NewService call sites unchanged.
func (s *Service) SetSBOMEnricher(e ports.SBOMEnricher) { s.sbomEnricher = e }

// SetMavenCoordResolver configures optional Maven coordinate recovery (deterministic,
// offline) that runs before registry license enrichment, so a mis-derived JAR groupId
// doesn't make the deps.dev lookup 404 → "unknown". Best-effort; nil disables it.
func (s *Service) SetMavenCoordResolver(r ports.MavenCoordResolver) { s.licCoord = r }

// SetJarHashResolver configures optional SHA-1 coordinate recovery for shaded/metadata-less JARs
// an egress call to Maven Central, so it's opt-in + best-effort. nil disables it.
func (s *Service) SetJarHashResolver(r ports.JarHashResolver) { s.jarHash = r }

// SetLicenseFileResolver configures an optional deterministic, offline fallback that
// recovers a component's license from the license text embedded in its JAR when the
// registry left it unknown. Best-effort; nil disables it.
func (s *Service) SetLicenseFileResolver(r ports.LicenseFileResolver) { s.licFile = r }

// SetSASTAnalyzer configures the optional deterministic pattern-SAST analyzer. nil ⇒ no SAST
// findings. A setter keeps the existing NewService call sites unchanged.
func (s *Service) SetSASTAnalyzer(a ports.SASTAnalyzer) { s.sastAnalyzer = a }

// SetSecretScanner configures the optional deterministic secret scanner. nil ⇒ no secret scanning.
func (s *Service) SetSecretScanner(sc ports.SecretScanner) { s.secretScanner = sc }

// SetReachability configures the optional deterministic Tier-2 reachability prover. nil ⇒ no
// reachability judgments. Best-effort + opt-in: a no-coverage/un-buildable target leaves the prior
// reachability tier standing (never a false "not reachable"). A setter keeps NewService call sites unchanged.
func (s *Service) SetReachability(r ports.ReachabilityRecorder) { s.reachability = r }

// SetCorrelation configures the optional cross-check disagreement→judgment minter. nil ⇒ no
// correlation judgments. Best-effort + opt-in: a recorder error is ignored (the scan never fails). A setter
// keeps NewService call sites unchanged.
func (s *Service) SetCorrelation(r ports.CorrelationRecorder) { s.correlation = r }

// SetTaint configures the optional deterministic taint-analysis CapSAST proposer. nil ⇒ no taint
// judgments. Best-effort + opt-in: a no-coverage/un-buildable target is ignored (the scan never fails). A
// setter keeps NewService call sites unchanged.
func (s *Service) SetTaint(t ports.TaintScanner) { s.taint = t }

// SetGraphResolver configures the optional transitive-edge resolver (Go via `go mod graph`). nil ⇒
// no resolved Go edges. Best-effort + opt-in: a non-Go target / no module cache / tool error adds no edges
// and never fails the scan. A setter keeps NewService call sites unchanged.
func (s *Service) SetGraphResolver(r ports.DependencyGraphResolver) { s.graphResolver = r }

// SetJVMReachability configures the optional coarse JVM class-reachability tagger. nil ⇒ no
// reachability tagging (components keep an empty/unknown verdict).
func (s *Service) SetJVMReachability(a ports.JVMReachabilityAnalyzer) { s.jvmReach = a }

// SetMavenResolver configures the optional Maven transitive-tree resolver (`mvn dependency:list`). nil ⇒
// Maven projects are scanned from pom.xml only (direct deps, managed versions UNKNOWN, no transitive
// tree → under-reports, flagged INCOMPLETE). Best-effort + opt-in: a non-Maven target / missing mvn /
// resolution error leaves the SBOM unchanged and never fails the scan.
func (s *Service) SetMavenResolver(r ports.MavenResolver) { s.mavenResolver = r }

// SetGradleResolver configures the optional Gradle transitive-tree resolver (`gradle dependencies`). nil
// ⇒ Gradle projects are scanned from the build script only (direct deps, often versionless, no transitive
// tree → under-reports, flagged INCOMPLETE). Best-effort + opt-in: a non-Gradle target / missing gradle /
// resolution error leaves the SBOM unchanged and never fails the scan.
func (s *Service) SetGradleResolver(r ports.GradleResolver) { s.gradleResolver = r }

// mergeResolvedJVM folds a resolver's transitive pkg:maven tree into doc and dedups by identity. Shared by
// the Maven + Gradle resolvers (both emit Maven coordinates). No-op on an empty resolved set — with nothing
// authoritative to substitute, syft's view (including any target/ jars, then the only version source) is
// left intact rather than zeroed out.
//
// completeScopes selects how much of syft's pkg:maven view the resolved tree supersedes:
//
// true (Maven): `mvn dependency:list` enumerates ALL non-test scopes (compile/provided/runtime/system),
// so the resolved set is a complete view of the shipped deps. Drop syft's ENTIRE pkg:maven view —
// including the concretely-versioned jars syft catalogs from a built target/ dir. That last case is the
// real hazard: a Spring Boot fat jar re-lists every dependency as a nested BOOT-INF/lib jar, so a
// from-source scan of an already-built project counts each dependency twice (observed 162 real deps →
// 235 components) and emits UNKNOWN-license noise for the nested jars that lack POM metadata.
// false (Gradle): `gradle dependencies` resolves only runtimeClasspath, which OMITS compileOnly/
// provided/annotationProcessor. Dropping all pkg:maven would silently discard actionable provided/
// compileOnly jars syft cataloged from a built build/ dir (development scope is NOT background). So drop
// only syft's unversioned pom placeholders (superseded by the resolved versions); keep versioned jars
// the runtimeClasspath tree never queried. (Broadening Gradle to also resolve compileClasspath is the
// follow-up that would let it use the complete-scope path too.)
func mergeResolvedJVM(doc *sbom.SBOM, resolved []sbom.Component, completeScopes bool) {
	if len(resolved) == 0 {
		return
	}
	kept := make([]sbom.Component, 0, len(doc.Components))
	for _, c := range doc.Components {
		if strings.HasPrefix(c.PURL, "pkg:maven/") && (completeScopes || !sbom.IsResolvedVersion(c.Version)) {
			continue // resolver owns (this slice of) the JVM tree; drop the redundant syft entries
		}
		kept = append(kept, c)
	}
	doc.Components = sbom.DedupeComponents(append(kept, resolved...))
}

// SetSBOMCrossCheck configures the optional SBOM-producer cross-check: a SECOND SBOM producer plus
// the disagreement→judgment recorder. nil either ⇒ no cross-check. Best-effort + opt-in: the 2nd producer
// runs only for the cross-check and a failure is ignored (the scan never fails). A setter keeps NewService
// call sites unchanged.
func (s *Service) SetSBOMCrossCheck(producer ports.SBOMGenerator, r ports.SBOMCrossCheckRecorder) {
	s.sbomGen2, s.sbomCrossCheck = producer, r
}

// NewService wires the SCA use case. minSeverity is the lowest vuln severity that
// is promoted to a finding; timeout bounds a single scan (0 disables).
func NewService(
	engagements ports.EngagementRepository,
	findings ports.FindingRepository,
	scans ports.ScanRepository,
	results ports.ScanResultStore,
	jobs ports.ScanJobStore,
	runs ports.ScanRunStore,
	ev *evidenceuc.Service,
	ids ports.IDGenerator,
	prov ports.Provenance,
	clock ports.Clock,
	audit ports.AuditLogger,
	minSeverity shared.Severity,
	timeout time.Duration,
	a ports.Acquirer,
	d ports.LanguageDetector,
	s ports.SBOMGenerator,
	sources []ports.DetectionSource,
	r ports.RiskEnricher,
	l ports.LicenseScanner,
	le ports.LicenseEnricher,
) *Service {
	svc := &Service{
		engagements: engagements, findings: findings, scans: scans, results: results, jobs: jobs, runs: runs, evidence: ev, ids: ids, prov: prov, clock: clock, audit: audit,
		minSeverity: minSeverity, timeout: timeout, acquirer: a,
		detector: d, sbomGen: s, sources: sources, riskEnricher: r, licScan: l, licEnricher: le,
	}
	// Build the shared execution guard from the service's own scope/clock/audit
	// deps, so every scan is gated + audited through the one chokepoint recon will
	// also use. NewService keeps its (no-error) signature to avoid churn at
	// the 20-param composition root; the guard's only failure mode is a nil dep, and
	// a nil guard FAILS CLOSED — gateAndAudit returns ErrValidation so no scan runs
	// (defended + tested). Revisit if NewService gains an error return.
	if g, err := execution.NewGuard(engagements, clock, audit); err == nil {
		svc.guard = g
	}
	return svc
}

// ScanResult is the aggregate output of an SCA scan.
type ScanResult struct {
	Target    string                   `json:"target"`
	ScanMode  string                   `json:"scan_mode"`
	Languages []ports.DetectedLanguage `json:"languages"`
	SBOM      *sbom.SBOM               `json:"sbom"`
	// Image carries container-image metadata (manifest digest, platform, ordered layer
	// stack with base-image classification) for image scans; nil otherwise. Every vuln on
	// an image is also attributed to its layer (Vulnerability.Layer*) — Epic D.
	Image *sbom.ImageInfo `json:"image,omitempty"`
	// Distro is the captured OS distribution (from OS-package PURLs) + its End-of-Life verdict;
	// nil when the target has no OS packages. An EOL distro receives no security updates — a
	// first-class posture signal for a container/host scan (Epic E).
	Distro            *distro.Status                `json:"distro,omitempty"`
	Vulnerabilities   []vulnerability.Vulnerability `json:"vulnerabilities"`
	Licenses          []ports.LicenseFinding        `json:"licenses"`
	ComponentLicenses []ComponentLicenseAudit       `json:"component_licenses"`
	Findings          []finding.Finding             `json:"findings"`
	// MinSeverity + VulnsBelowThreshold make the severity floor VISIBLE: every detected vuln is
	// kept in Vulnerabilities, but only those at/above MinSeverity become promoted Findings.
	// VulnsBelowThreshold counts the detected-but-not-promoted vulns so a raised floor can never
	// silently hide them ("no silent gap"). Default floor = info ⇒ this is 0 (everything promoted).
	MinSeverity         shared.Severity `json:"min_severity"`
	VulnsBelowThreshold int             `json:"vulns_below_threshold"`
	// UnfixedSuppressed counts vulns not promoted ONLY because --ignore-unfixed is on and they
	// have no available fix (they remain in Vulnerabilities) — surfaced so it's never silent.
	UnfixedSuppressed int `json:"unfixed_suppressed"`
	// SourceWarnings flags a configured detection source that did NOT run (e.g. the Grype
	// binary/DB is missing), so a silently-degraded source can't masquerade as "0 vulns / clean".
	SourceWarnings           []string                 `json:"source_warnings,omitempty"`
	ToolVersions             map[string]string        `json:"tool_versions"`
	VulnDBSnapshot           string                   `json:"vuln_db_snapshot"`
	Completeness             ports.Completeness       `json:"completeness"`
	LicenseCoverage          sbom.LicenseCoverage     `json:"license_coverage"`
	LicenseCoverageBreakdown LicenseCoverageBreakdown `json:"license_coverage_breakdown"`
	Manifest                 ports.ScanManifest       `json:"manifest"`
	RiskMatches              map[string]int           `json:"risk_matches"` // kev/epss match counts (diagnostic)
	FindingQuality           FindingQuality           `json:"finding_quality"`
	// Coverage is the per-ecosystem component tally: components + resolved-version counts per
	// ecosystem, so a thin / partially-resolved ecosystem is VISIBLE rather than hidden behind the single
	// global Completeness number ("no silent gap").
	Coverage []sbom.EcosystemCoverage `json:"coverage"`
	// ReproDigest is a stable content fingerprint of the reproducible output: same target + pinned
	// producer + pinned advisory/DB snapshot ⇒ same digest. Excludes timestamps + per-run metadata.
	ReproDigest string                 `json:"repro_digest"`
	DebugEvents []ports.ScanDebugEvent `json:"debug_events"`
}

const (
	ScanModeFull            = "full"
	ScanModeVulnerabilities = "vulnerabilities"
	ScanModeLicenses        = "licenses"
)

type ScanOptions struct {
	Mode string `json:"mode"`
}

func normalizeScanOptions(opts ScanOptions) (ScanOptions, error) {
	mode := strings.ToLower(strings.TrimSpace(opts.Mode))
	if mode == "" {
		mode = ScanModeFull
	}
	switch mode {
	case ScanModeFull, ScanModeVulnerabilities, ScanModeLicenses:
		opts.Mode = mode
		return opts, nil
	default:
		return ScanOptions{}, fmt.Errorf("%w: unknown scan mode %q", shared.ErrValidation, opts.Mode)
	}
}

func NormalizeScanOptions(opts ScanOptions) (ScanOptions, error) { return normalizeScanOptions(opts) }

func (o ScanOptions) scansVulnerabilities() bool {
	return o.Mode == ScanModeFull || o.Mode == ScanModeVulnerabilities
}

func (o ScanOptions) scansLicenses() bool {
	return o.Mode == ScanModeFull || o.Mode == ScanModeLicenses
}

type ComponentLicenseAudit struct {
	Component     string               `json:"component"`
	Version       string               `json:"version"`
	PURL          string               `json:"purl"`
	Scope         string               `json:"scope"`
	Location      string               `json:"location"`
	License       string               `json:"license"`
	Category      sbom.LicenseCategory `json:"category"`
	Verdict       ports.LicenseVerdict `json:"verdict"`
	Source        string               `json:"source"`
	Confidence    string               `json:"confidence"`
	UnknownReason string               `json:"unknown_reason"`
}

type LicenseCoverageBreakdown struct {
	ByScope           map[string]sbom.LicenseCoverage `json:"by_scope"`
	ByEcosystem       map[string]sbom.LicenseCoverage `json:"by_ecosystem"`
	ProductionUnknown int                             `json:"production_unknown"`
}

type scanDebugTrace struct {
	events   []ports.ScanDebugEvent
	onUpdate func([]ports.ScanDebugEvent)
}

func newScanDebugTrace(onUpdate func([]ports.ScanDebugEvent)) *scanDebugTrace {
	return &scanDebugTrace{events: []ports.ScanDebugEvent{}, onUpdate: onUpdate}
}

func (t *scanDebugTrace) start(stage, step, tool, message string, counts map[string]int) int {
	event := ports.ScanDebugEvent{
		Stage: stage, Step: step, Tool: tool, Message: message,
		Status: ports.ScanDebugRunning, Counts: counts, StartedAt: time.Now().UTC(),
	}
	t.events = append(t.events, event)
	t.publish()
	return len(t.events) - 1
}

func (t *scanDebugTrace) succeed(idx int, message string, counts map[string]int) {
	t.finish(idx, ports.ScanDebugSucceeded, message, counts, "")
}

func (t *scanDebugTrace) fail(idx int, err error) {
	t.finish(idx, ports.ScanDebugFailed, "", nil, truncateErr(err))
}

func (t *scanDebugTrace) finish(idx int, status ports.ScanDebugStatus, message string, counts map[string]int, errText string) {
	if idx < 0 || idx >= len(t.events) {
		return
	}
	finished := time.Now().UTC()
	event := &t.events[idx]
	event.Status = status
	event.FinishedAt = &finished
	event.DurationMS = finished.Sub(event.StartedAt).Milliseconds()
	if event.DurationMS < 0 {
		event.DurationMS = 0
	}
	if message != "" {
		event.Message = message
	}
	if counts != nil {
		event.Counts = counts
	}
	event.Error = errText
	t.publish()
}

func (t *scanDebugTrace) snapshot() []ports.ScanDebugEvent {
	out := make([]ports.ScanDebugEvent, len(t.events))
	copy(out, t.events)
	return out
}

func (t *scanDebugTrace) publish() {
	if t.onUpdate != nil {
		t.onUpdate(t.snapshot())
	}
}

func countComponents(doc *sbom.SBOM) int {
	if doc == nil {
		return 0
	}
	return len(doc.Components)
}

func buildComponentLicenseAudit(comps []sbom.Component, findings []ports.LicenseFinding) []ComponentLicenseAudit {
	policy := map[string]ports.LicenseFinding{}
	for _, f := range findings {
		policy[f.License] = f
	}
	out := make([]ComponentLicenseAudit, 0, len(comps))
	for _, c := range comps {
		if len(c.Licenses) == 0 {
			out = append(out, ComponentLicenseAudit{
				Component:     c.Name,
				Version:       c.Version,
				PURL:          c.PURL,
				Scope:         c.Scope,
				Location:      c.Location,
				Category:      sbom.LicenseUnknown,
				Verdict:       ports.LicenseWarn,
				Source:        c.LicenseSource,
				Confidence:    c.LicenseConfidence,
				UnknownReason: c.UnknownReason,
			})
			continue
		}
		for _, lic := range c.Licenses {
			key := componentLicenseKey(lic)
			if key == "" {
				continue
			}
			category := sbom.LicenseUnknown
			verdict := ports.LicenseWarn
			if f, ok := policy[key]; ok {
				category = f.Category
				verdict = f.Verdict
			}
			out = append(out, ComponentLicenseAudit{
				Component:     c.Name,
				Version:       c.Version,
				PURL:          c.PURL,
				Scope:         c.Scope,
				Location:      c.Location,
				License:       key,
				Category:      category,
				Verdict:       verdict,
				Source:        c.LicenseSource,
				Confidence:    c.LicenseConfidence,
				UnknownReason: c.UnknownReason,
			})
		}
	}
	return out
}

func componentLicenseKey(l sbom.License) string {
	if strings.TrimSpace(l.SPDXID) != "" {
		return strings.TrimSpace(l.SPDXID)
	}
	return strings.TrimSpace(l.Name)
}

func buildLicenseCoverageBreakdown(comps []sbom.Component) LicenseCoverageBreakdown {
	byScopeComps := map[string][]sbom.Component{}
	byEcoComps := map[string][]sbom.Component{}
	productionUnknown := 0
	for _, c := range comps {
		scope := c.Scope
		if scope == "" {
			scope = sbom.ScopeUnknown
		}
		byScopeComps[scope] = append(byScopeComps[scope], c)
		byEcoComps[ecosystemFromPURL(c.PURL)] = append(byEcoComps[ecosystemFromPURL(c.PURL)], c)
		if scope == sbom.ScopeProduction && len(c.Licenses) == 0 {
			productionUnknown++
		}
	}
	byScope := make(map[string]sbom.LicenseCoverage, len(byScopeComps))
	for scope, scoped := range byScopeComps {
		byScope[scope] = sbom.ComputeLicenseCoverage(scoped)
	}
	byEco := make(map[string]sbom.LicenseCoverage, len(byEcoComps))
	for eco, ecoComps := range byEcoComps {
		byEco[eco] = sbom.ComputeLicenseCoverage(ecoComps)
	}
	return LicenseCoverageBreakdown{ByScope: byScope, ByEcosystem: byEco, ProductionUnknown: productionUnknown}
}

func ecosystemFromPURL(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return "(no purl)"
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	idx := strings.Index(rest, "/")
	if idx <= 0 {
		return "(no purl)"
	}
	return strings.ToLower(rest[:idx])
}

// FindingQuality is the honest finding breakdown shown before any vulnerability
// counts: actionable third-party findings vs first-party historical
// advisories, with coverage + confidence so the headline numbers aren't misread.
type FindingQuality struct {
	ThirdParty           int     `json:"third_party"`            // actionable findings
	ThirdPartyCritical   int     `json:"third_party_critical"`   // critical, third-party only
	ThirdPartyHigh       int     `json:"third_party_high"`       // high, third-party only
	FirstPartyHistorical int     `json:"first_party_historical"` // informational, unversioned
	VersionCoveragePct   float64 `json:"version_coverage_pct"`
	PathCoveragePct      float64 `json:"path_coverage_pct"`
	Confidence           string  `json:"confidence"` // high | medium | low

	// Scope + priority breakdown: separates actionable from background
	// without hiding anything.
	RawFindings int            `json:"raw_findings"`
	Actionable  int            `json:"actionable"` // non-background, non-historical
	Background  int            `json:"background"` // example/test/fixture/etc + historical
	Production  int            `json:"production"`
	Development int            `json:"development"`
	ExampleTest int            `json:"example_test"` // example+test+fixture+benchmark+docs
	ByPriority  map[int]int    `json:"by_priority"`  // priority 1..5 -> count
	ByScope     map[string]int `json:"by_scope"`
}

func computeFindingQuality(res *ScanResult) FindingQuality {
	q := FindingQuality{ByPriority: map[int]int{}, ByScope: map[string]int{}}
	q.RawFindings = len(res.Findings)
	for _, f := range res.Findings {
		q.ByScope[nonEmptyScope(f.Scope)]++
		if f.Priority > 0 {
			q.ByPriority[f.Priority]++
		}
		switch f.Scope {
		case sbom.ScopeProduction:
			q.Production++
		case sbom.ScopeDevelopment:
			q.Development++
		case sbom.ScopeExample, sbom.ScopeTest, sbom.ScopeFixture, sbom.ScopeBenchmark, sbom.ScopeDocumentation:
			q.ExampleTest++
		}
		// Actionable vs background: historical advisories + background scopes are
		// background; everything else is actionable.
		if f.Class == finding.ClassFirstPartyHistoric || f.Impact == vulnerability.ImpactBackground || sbom.IsBackgroundScope(f.Scope) {
			q.Background++
		} else {
			q.Actionable++
		}
		if f.Class == finding.ClassFirstPartyHistoric {
			q.FirstPartyHistorical++
			continue
		}
		if f.Class == finding.ClassFirstParty {
			continue // first-party actionable (e.g. SAST) — counted in Actionable above, not a third-party advisory
		}
		q.ThirdParty++
		switch f.Severity {
		case shared.SeverityCritical:
			q.ThirdPartyCritical++
		case shared.SeverityHigh:
			q.ThirdPartyHigh++
		}
	}
	// version coverage: resolved third-party components.
	total, resolved := 0, 0
	for _, c := range res.SBOM.Components {
		if c.FirstParty {
			continue
		}
		total++
		if sbom.IsResolvedVersion(c.Version) {
			resolved++
		}
	}
	if total > 0 {
		q.VersionCoveragePct = float64(resolved) / float64(total) * 100
	} else {
		q.VersionCoveragePct = 100
	}
	// path coverage: vulnerable third-party components with a resolved dependency path.
	pv, pp := 0, 0
	for _, v := range res.Vulnerabilities {
		if v.Unversioned {
			continue
		}
		pv++
		if len(v.Path) >= 1 {
			pp++
		}
	}
	if pv > 0 {
		q.PathCoveragePct = float64(pp) / float64(pv) * 100
	} else {
		q.PathCoveragePct = 100
	}
	switch {
	case res.Completeness.Confident && q.VersionCoveragePct >= 95:
		q.Confidence = "high"
	case q.VersionCoveragePct >= 80:
		q.Confidence = "medium"
	default:
		q.Confidence = "low"
	}
	return q
}

// Scan stages reported on the asynchronous job's progress bar.
const (
	stageAcquire  = "acquiring target"
	stageDetect   = "detecting languages"
	stageSBOM     = "generating SBOM"
	stageVulns    = "scanning vulnerabilities"
	stageRisk     = "prioritizing risk"
	stageLicense  = "scanning licenses"
	stageFindings = "deriving findings"
)

// Scan runs the SCA pipeline synchronously and returns the result (used by the
// CLI). The API uses StartScan. Scope + the authorization window are enforced and
// the action audited BEFORE any tool runs.
func (s *Service) Scan(ctx context.Context, actor string, engagementID shared.ID, req ports.AcquireRequest) (*ScanResult, error) {
	return s.ScanWithOptions(ctx, actor, engagementID, req, ScanOptions{})
}

func (s *Service) ScanWithOptions(ctx context.Context, actor string, engagementID shared.ID, req ports.AcquireRequest, opts ScanOptions) (*ScanResult, error) {
	var err error
	opts, err = normalizeScanOptions(opts)
	if err != nil {
		return nil, err
	}
	req = normalizeLocalTarget(req)
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	if imported, doc, ok, err := s.loadImportedSBOM(ctx, engagementID); err != nil {
		return nil, err
	} else if ok {
		now, err := s.gateImportedSBOMAndAudit(ctx, actor, engagementID, imported, opts)
		if err != nil {
			return nil, err
		}
		return s.runImportedSBOMPipeline(ctx, actor, engagementID, now, imported, doc, opts, func(string, int, []ports.ScanDebugEvent) {})
	}
	now, err := s.gateAndAudit(ctx, actor, engagementID, req, opts)
	if err != nil {
		return nil, err
	}
	return s.runPipeline(ctx, actor, engagementID, now, req, opts, func(string, int, []ports.ScanDebugEvent) {})
}

// StartScan gates + audits the scan, then runs the pipeline ASYNCHRONOUSLY
// (single-instance goroutine; a queue lands later) and returns the job
// immediately. The UI polls the job for progress and can resume after a reload.
func (s *Service) StartScan(ctx context.Context, actor string, engagementID shared.ID, req ports.AcquireRequest) (ports.ScanJob, error) {
	return s.StartScanWithOptions(ctx, actor, engagementID, req, ScanOptions{})
}

func (s *Service) StartScanWithOptions(ctx context.Context, actor string, engagementID shared.ID, req ports.AcquireRequest, opts ScanOptions) (ports.ScanJob, error) {
	if s.jobs == nil || s.ids == nil {
		return ports.ScanJob{}, fmt.Errorf("async scan is not configured: %w", shared.ErrValidation)
	}
	var err error
	opts, err = normalizeScanOptions(opts)
	if err != nil {
		return ports.ScanJob{}, err
	}
	req = normalizeLocalTarget(req)
	var imported importedsbom.Record
	var importedDoc *sbom.SBOM
	var useImported bool
	if imported, importedDoc, useImported, err = s.loadImportedSBOM(ctx, engagementID); err != nil {
		return ports.ScanJob{}, err
	}
	var now time.Time
	if useImported {
		now, err = s.gateImportedSBOMAndAudit(ctx, actor, engagementID, imported, opts)
	} else {
		now, err = s.gateAndAudit(ctx, actor, engagementID, req, opts)
	}
	if err != nil {
		return ports.ScanJob{}, err
	}
	target := req.Value
	kind := kindOrLocal(req.Kind)
	if useImported {
		target = imported.TargetRef
		kind = "imported-sbom"
		_ = importedDoc // loaded now to fail fast; worker reloads the active artifact when executing.
	}
	job := ports.ScanJob{
		ID:           s.ids.NewID().String(),
		EngagementID: engagementID.String(),
		Target:       target,
		Kind:         kind,
		Status:       ports.ScanRunning,
		Stage:        "queued",
		StartedAt:    now,
		DebugEvents:  []ports.ScanDebugEvent{},
	}
	if s.jobs != nil {
		if err := s.jobs.Save(ctx, job); err != nil {
			return ports.ScanJob{}, fmt.Errorf("create scan job: %w", err)
		}
	}
	// defer to the durable queue when configured (an in-process or separate worker
	// claims + runs the pipeline with syft/grype sandboxed) — replaces the bare goroutine,
	// so queued work survives a restart. Without a queue, the in-process goroutine runs it.
	if s.jobQueue != nil {
		payload, mErr := json.Marshal(scaJobPayload{Actor: actor, EngagementID: engagementID.String(), Now: now, Req: req, Options: opts, Job: job})
		if mErr != nil {
			return ports.ScanJob{}, fmt.Errorf("marshal scan job: %w", mErr)
		}
		if _, err := s.jobQueue.Enqueue(ctx, ScanJobKind, payload); err != nil {
			return ports.ScanJob{}, fmt.Errorf("enqueue scan job: %w", err)
		}
		return job, nil
	}
	go s.runScanJob(actor, engagementID, now, req, opts, job)
	return job, nil
}

// ScanJobKind is the durable-queue Kind for an SCA scan.
const ScanJobKind = "sca"

// scaJobPayload is the durable-queue payload for one SCA scan run.
type scaJobPayload struct {
	Actor        string               `json:"actor"`
	EngagementID string               `json:"engagement_id"`
	Now          time.Time            `json:"now"`
	Req          ports.AcquireRequest `json:"req"`
	Options      ScanOptions          `json:"options"`
	Job          ports.ScanJob        `json:"job"`
}

// SetQueue routes SCA scans through the durable job queue: StartScan enqueues and
// a worker claims + calls RunScanJob. Optional — without it, the in-process goroutine runs.
func (s *Service) SetQueue(q ports.JobQueue) { s.jobQueue = q }

// SetRunLock guards against duplicate concurrent execution of the same scan job under
// at-least-once queue redelivery.
func (s *Service) SetRunLock(l ports.RunLocker) { s.runLock = l }

// RunScanJob runs an SCA scan claimed from the durable queue (the worker handler calls
// this). A malformed payload is a hard error (dead-letters); pipeline failures are
// recorded on the ScanJob (not a job error), so the job completes.
func (s *Service) RunScanJob(ctx context.Context, payload []byte) error {
	var p scaJobPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("%w: malformed scan job payload: %v", shared.ErrValidation, err)
	}
	// single-active-execution lease at the JOB boundary (re-audit fix) — a lock ERROR
	// returns an error so the queue REDELIVERS (never silently completes a never-run scan);
	// a held lease means another delivery is running it → complete this one (nil).
	if s.runLock != nil {
		release, ok, lerr := s.runLock.TryLock(ctx, p.Job.ID)
		if lerr != nil {
			return fmt.Errorf("run lock unavailable for scan %s (will retry): %w", p.Job.ID, lerr)
		}
		if !ok {
			return nil
		}
		defer release()
	}
	opts, err := normalizeScanOptions(p.Options)
	if err != nil {
		return err
	}
	s.runScanJob(p.Actor, shared.ID(p.EngagementID), p.Now, p.Req, opts, p.Job)
	return nil
}

// FailStrandedScanJob marks the scan job behind a DEAD-LETTERED sca job failed if it has not
// already reached a terminal state — so a crash/lock-error that exhausts the retries leaves a
// terminal, operator-visible ScanJob (status=failed) instead of one stuck non-terminal with no
// result. It is the worker's DeadLetterer hook for SCA (parity with recon + agent). It takes the
// run lease so it never races a live redelivery and no-ops when the scan is already terminal.
func (s *Service) FailStrandedScanJob(ctx context.Context, payload []byte, cause error) error {
	var p scaJobPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("%w: malformed scan job payload: %v", shared.ErrValidation, err)
	}
	if s.jobs == nil {
		return nil
	}
	if s.runLock != nil {
		release, ok, lerr := s.runLock.TryLock(ctx, p.Job.ID)
		if lerr != nil {
			return fmt.Errorf("run lock for scan %s: %w", p.Job.ID, lerr)
		}
		if !ok {
			return nil // a live delivery owns this scan
		}
		defer release()
	}
	// Load the SPECIFIC dead-lettered job by its id (parity with recon's load-by-runID), so a
	// newer scan for the same engagement cannot mislead the terminal-guard. An absent row means
	// nothing to finalize.
	job, err := s.jobs.GetJob(ctx, p.Job.ID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("load stranded scan job %s: %w", p.Job.ID, err)
	}
	if job.Status == ports.ScanSucceeded || job.Status == ports.ScanFailed {
		return nil // already terminal
	}
	if cause == nil {
		cause = errors.New("scan job dead-lettered after exhausting retries")
	}
	fin := s.clock.Now()
	job.FinishedAt, job.Progress = &fin, 100
	job.Status, job.Stage, job.Error = ports.ScanFailed, "dead-letter", truncateErr(cause)
	return s.jobs.Save(ctx, job)
}

// SweepStaleScans reclaims scan jobs a crashed worker left `running` past staleFor WITHOUT a
// dead-letter event — parity with recon's SweepStaleRuns, using the run lease as the liveness
// signal (acquirable lease ⇒ no live owner ⇒ stranded ⇒ finalize failed). Requires the lease;
// no-ops without it. Returns the number reclaimed.
func (s *Service) SweepStaleScans(ctx context.Context, staleFor time.Duration) (int, error) {
	if s.runLock == nil || s.jobs == nil {
		return 0, nil
	}
	if staleFor <= 0 {
		staleFor = 15 * time.Minute
	}
	stale, err := s.jobs.ListStaleRunning(ctx, s.clock.Now().Add(-staleFor), 100)
	if err != nil {
		return 0, fmt.Errorf("list stale scans: %w", err)
	}
	n := 0
	for _, job := range stale {
		release, ok, lerr := s.runLock.TryLock(ctx, job.ID)
		if lerr != nil || !ok {
			continue // can't acquire or a live owner holds it → leave for next pass
		}
		if fresh, gerr := s.jobs.GetJob(ctx, job.ID); gerr == nil && (fresh.Status == ports.ScanSucceeded || fresh.Status == ports.ScanFailed) {
			release()
			continue
		}
		fin := s.clock.Now()
		job.FinishedAt, job.Progress = &fin, 100
		job.Status, job.Stage, job.Error = ports.ScanFailed, "swept", "scan stranded running past staleFor with no live owner — reclaimed by sweeper"
		_ = s.jobs.Save(ctx, job)
		release()
		n++
	}
	return n, nil
}

// LatestJob returns the engagement's most recent scan job (for the status poll).
func (s *Service) LatestJob(ctx context.Context, engagementID shared.ID) (ports.ScanJob, error) {
	if s.jobs == nil {
		return ports.ScanJob{}, fmt.Errorf("scan job: %w", shared.ErrNotFound)
	}
	return s.jobs.LatestForEngagement(ctx, engagementID)
}

// gateAndAudit enforces scope + the authorization window and records the
// append-only audit entry, all BEFORE any tool runs, by delegating to the shared
// execution guard — the same server-side chokepoint recon uses, never an
// SCA-private copy. The SCA target is matched as a repo (value-exact). Returns
// the scan timestamp.
func (s *Service) gateAndAudit(ctx context.Context, actor string, engagementID shared.ID, req ports.AcquireRequest, opts ScanOptions) (time.Time, error) {
	if s.guard == nil {
		return time.Time{}, fmt.Errorf("%w: execution guard not configured", shared.ErrValidation)
	}
	return s.guard.Authorize(ctx, execution.Request{
		Actor:        actor,
		EngagementID: engagementID,
		Action:       "sca.scan",
		Target:       engagement.Target{Kind: engagement.TargetRepo, Value: req.Value},
		Metadata:     map[string]string{"kind": kindOrLocal(req.Kind), "engagement": engagementID.String(), "mode": opts.Mode},
	})
}

func (s *Service) gateImportedSBOMAndAudit(ctx context.Context, actor string, engagementID shared.ID, record importedsbom.Record, opts ScanOptions) (time.Time, error) {
	if s.guard == nil {
		return time.Time{}, fmt.Errorf("%w: execution guard not configured", shared.ErrValidation)
	}
	target := record.TargetRef
	if target == "" {
		target = record.Filename
	}
	return s.guard.AuthorizeEngagementArtifact(ctx, execution.Request{
		Actor:        actor,
		EngagementID: engagementID,
		Action:       "sca.scan",
		Target:       engagement.Target{Kind: engagement.TargetRepo, Value: target},
		Metadata:     map[string]string{"kind": "imported-sbom", "engagement": engagementID.String(), "mode": opts.Mode, "sbom_sha256": record.SHA256},
	})
}

func (s *Service) loadImportedSBOM(ctx context.Context, engagementID shared.ID) (importedsbom.Record, *sbom.SBOM, bool, error) {
	if s.importedSBOM == nil {
		return importedsbom.Record{}, nil, false, nil
	}
	eng, err := s.engagements.GetByID(ctx, engagementID)
	if err != nil {
		return importedsbom.Record{}, nil, false, fmt.Errorf("load engagement: %w", err)
	}
	record, err := s.importedSBOM.LatestByEngagement(ctx, eng.TenantID, engagementID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return importedsbom.Record{}, nil, false, nil
		}
		return importedsbom.Record{}, nil, false, err
	}
	parsed, err := parseCycloneDX(record.RawJSON)
	if err != nil {
		return importedsbom.Record{}, nil, false, fmt.Errorf("parse imported SBOM artifact: %w", err)
	}
	target := record.TargetRef
	if strings.TrimSpace(target) == "" {
		target = parsed.TargetRef
	}
	if strings.TrimSpace(target) == "" {
		target = importedsbom.DefaultFilename
	}
	doc := &sbom.SBOM{
		ID:               record.ID,
		TargetRef:        target,
		Source:           "imported-cyclonedx",
		GeneratorVersion: parsed.GeneratorVersion,
		Components:       parsed.Components,
		Dependencies:     parsed.Dependencies,
		Raw:              append([]byte(nil), record.RawJSON...),
		Audit:            shared.Audit{CreatedAt: record.CreatedAt, UpdatedAt: record.CreatedAt},
	}
	return record, doc, true, nil
}

// normalizeLocalTarget canonicalizes a LOCAL-filesystem target path — absolute, cleaned,
// OS-native separators — so the scope check and the acquisition see the SAME stable value
// regardless of how the operator typed the path (relative, trailing slash, mixed '/' and '\',
// '.'/'..', drive-letter case on Windows). It runs ONLY for the local kind: filepath.Clean would
// corrupt a git URL (it collapses "https://" to "https:/"), so non-local kinds are returned
// untouched. An empty value, or a path that cannot be made absolute, is left as-is for the
// existing validation to reject. This only canonicalizes — it never widens scope (an out-of-scope
// path still fails the gate); it fixes the cross-OS case where a valid local repo path was matched
// inconsistently against scope.
func normalizeLocalTarget(req ports.AcquireRequest) ports.AcquireRequest {
	if req.Kind != "" && req.Kind != ports.TargetLocal {
		return req
	}
	v := strings.TrimSpace(req.Value)
	// Only canonicalize values that are clearly filesystem paths; a bare logical token
	// (e.g. "myrepo") is left exact so a value-keyed scope entry still matches it.
	if v == "" || !looksLikePath(v) {
		return req
	}
	if abs, err := filepath.Abs(v); err == nil {
		req.Value = filepath.Clean(abs)
	}
	return req
}

// looksLikePath reports whether v is a filesystem path (absolute, dot-relative, or containing a
// separator) rather than a bare logical identifier, so canonicalization only touches real paths.
func looksLikePath(v string) bool {
	return filepath.IsAbs(v) || strings.HasPrefix(v, ".") || strings.ContainsAny(v, `/\`)
}

// runScanJob runs the pipeline on a detached background context (the request that
// started the scan has returned), advancing + finishing the job.
func (s *Service) runScanJob(actor string, engagementID shared.ID, now time.Time, req ports.AcquireRequest, opts ScanOptions, job ports.ScanJob) {
	// Idempotency (audit): the durable queue is at-least-once, so a redelivery can
	// re-invoke a scan a prior delivery already finished. Re-running is read-only (findings
	// dedup by advisory+component+version) but would seal a DUPLICATE "scan" evidence link
	// and write a phantom ScanRun row. If this engagement's latest job is THIS job and is
	// already terminal, skip — the worker then Completes the job. (A newer scan started
	// between deliveries masks this guard; the only cost there is the duplicate seal.)
	if s.jobs != nil {
		if latest, err := s.jobs.LatestForEngagement(context.Background(), engagementID); err == nil &&
			latest.ID == job.ID && (latest.Status == ports.ScanSucceeded || latest.Status == ports.ScanFailed) {
			return
		}
	}
	ctx := context.Background()
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	report := func(stage string, pct int, events []ports.ScanDebugEvent) {
		if s.jobs == nil {
			return
		}
		job.Stage, job.Progress, job.DebugEvents = stage, pct, events
		_ = s.jobs.Save(ctx, job)
	}

	var err error
	if imported, doc, ok, loadErr := s.loadImportedSBOM(ctx, engagementID); loadErr != nil {
		err = loadErr
	} else if ok {
		_, err = s.runImportedSBOMPipeline(ctx, actor, engagementID, now, imported, doc, opts, report)
	} else {
		_, err = s.runPipeline(ctx, actor, engagementID, now, req, opts, report)
	}

	fin := s.clock.Now()
	job.FinishedAt, job.Progress = &fin, 100
	if err != nil {
		job.Status, job.Stage, job.Error = ports.ScanFailed, "failed", truncateErr(err)
	} else {
		job.Status, job.Stage = ports.ScanSucceeded, "done"
	}
	if s.jobs != nil {
		_ = s.jobs.Save(context.Background(), job) // fresh ctx: the timeout ctx may be done
	}
}

// runPipeline is the read-only tool chain (acquire -> detect -> SBOM -> vulns ->
// risk -> licenses -> findings -> persist). report() advances the progress bar.
func (s *Service) runImportedSBOMPipeline(ctx context.Context, actor string, engagementID shared.ID, now time.Time, record importedsbom.Record, doc *sbom.SBOM, opts ScanOptions, report func(stage string, pct int, events []ports.ScanDebugEvent)) (*ScanResult, error) {
	stage, pct := stageSBOM, 35
	trace := newScanDebugTrace(func(events []ports.ScanDebugEvent) { report(stage, pct, events) })
	report(stage, pct, trace.snapshot())
	step := trace.start(stageSBOM, "imported-sbom", "cyclonedx", "Use imported SBOM as scan inventory", map[string]int{"components": countComponents(doc), "dependencies": len(doc.Dependencies)})
	trace.succeed(step, "Imported SBOM loaded", map[string]int{"components": countComponents(doc), "dependencies": len(doc.Dependencies)})

	var raws []vulnerability.RawFinding
	var vulns []vulnerability.Vulnerability
	var riskVersions map[string]string
	var riskMatches map[string]int
	if opts.scansVulnerabilities() {
		stage, pct = stageVulns, 55
		report(stage, pct, trace.snapshot())
		for _, src := range s.sources {
			step = trace.start(stageVulns, src.Name(), src.Name(), "Scan vulnerabilities with "+src.Name(), map[string]int{"components": countComponents(doc)})
			rfs, err := src.Scan(ctx, doc)
			if err != nil {
				trace.fail(step, err)
				return nil, fmt.Errorf("scan vulnerabilities (%s): %w", src.Name(), err)
			}
			raws = append(raws, rfs...)
			trace.succeed(step, "Vulnerability source completed", map[string]int{"components": countComponents(doc), "raw_findings": len(rfs)})
		}
		step = trace.start(stageVulns, "correlate", "", "Correlate and deduplicate vulnerability findings", map[string]int{"raw_findings": len(raws)})
		vulns = vulnerability.Correlate(raws)
		trace.succeed(step, "Vulnerabilities correlated", map[string]int{"raw_findings": len(raws), "vulnerabilities": len(vulns)})
		if s.sevEnricher != nil {
			step = trace.start(stageVulns, "severity-backfill", "severity-enricher", "Backfill unknown severities from NVD", map[string]int{"vulnerabilities": len(vulns)})
			sr := s.sevEnricher.Enrich(ctx, vulns)
			vulns = sr.Vulns
			trace.succeed(step, "Severity backfilled", map[string]int{"vulnerabilities": len(vulns), "backfilled": sr.Matches})
		}
		stage, pct = stageRisk, 75
		report(stage, pct, trace.snapshot())
		if s.riskEnricher != nil {
			step = trace.start(stageRisk, "risk-enrichment", "risk-enricher", "Enrich vulnerabilities with risk signals", map[string]int{"vulnerabilities": len(vulns)})
			r := s.riskEnricher.Enrich(ctx, vulns)
			vulns, riskVersions, riskMatches = r.Vulns, r.Versions, r.Matches
			trace.succeed(step, "Risk enrichment completed", map[string]int{"vulnerabilities": len(vulns)})
		}
		vulnerability.SortByRisk(vulns)
		attachDependencyPaths(doc, vulns)
		classifyVulns(doc, vulns)
	}

	var lics []ports.LicenseFinding
	var licenseCoverage sbom.LicenseCoverage
	var componentLicenses []ComponentLicenseAudit
	var licenseCoverageBreakdown LicenseCoverageBreakdown
	if opts.scansLicenses() {
		stage, pct = stageLicense, 85
		report(stage, pct, trace.snapshot())
		if s.licEnricher != nil {
			step = trace.start(stageLicense, "license-enrichment", "license-enricher", "Enrich component license metadata", map[string]int{"components": countComponents(doc)})
			doc.Components = s.licEnricher.Enrich(ctx, doc.Components)
			trace.succeed(step, "License metadata enrichment completed", map[string]int{"components": countComponents(doc)})
		}
		step = trace.start(stageLicense, "license-policy", "license-policy", "Evaluate component licenses against policy", map[string]int{"components": countComponents(doc)})
		var err error
		lics, err = s.licScan.Scan(ctx, doc)
		if err != nil {
			trace.fail(step, err)
			return nil, fmt.Errorf("scan licenses: %w", err)
		}
		trace.succeed(step, "License policy scan completed", map[string]int{"components": countComponents(doc), "licenses": len(lics)})
		licenseCoverage = sbom.ComputeLicenseCoverage(doc.Components)
		componentLicenses = buildComponentLicenseAudit(doc.Components, lics)
		licenseCoverageBreakdown = buildLicenseCoverageBreakdown(doc.Components)
	}

	stage, pct = stageFindings, 92
	report(stage, pct, trace.snapshot())
	step = trace.start(stageFindings, "derive-findings", "", "Derive findings from imported SBOM scan outputs", map[string]int{"vulnerabilities": len(vulns), "licenses": len(lics)})
	toolVersions := make(map[string]string, len(s.prov.ToolVersions)+len(riskVersions)+2)
	for k, v := range s.prov.ToolVersions {
		toolVersions[k] = v
	}
	for k, v := range riskVersions {
		toolVersions[k] = v
	}
	if doc.GeneratorVersion != "" {
		toolVersions["imported-sbom-generator"] = doc.GeneratorVersion
	}
	toolVersions["imported-sbom"] = record.SpecVersion
	grypeDB := ""
	var sourceWarnings []string
	for _, src := range s.sources {
		p, ok := src.(ports.SourceProvenance)
		if !ok {
			continue
		}
		ver, db := p.Provenance()
		if ver != "" {
			toolVersions[src.Name()] = ver
		}
		if db != "" {
			toolVersions[src.Name()+"-db"] = db
			if src.Name() == "grype" {
				grypeDB = db
			}
		}
		if ver == "" && db == "" && len(doc.Components) > 0 {
			sourceWarnings = append(sourceWarnings, fmt.Sprintf("detection source %q did not run (tool/DB missing or errored) — its vulnerabilities are NOT included", src.Name()))
		}
	}
	snap := ports.ScanSnapshot{ToolVersions: toolVersions, VulnDBSnapshot: s.prov.VulnDBSource + "@" + now.UTC().Format(time.RFC3339), GrypeDBVersion: grypeDB}
	manifest := buildManifest(toolVersions, snap.VulnDBSnapshot, grypeDB, doc)
	manifest.SBOMSHA256 = record.SHA256
	result := &ScanResult{
		Target:                   doc.TargetRef,
		ScanMode:                 opts.Mode,
		SBOM:                     doc,
		Vulnerabilities:          vulns,
		Licenses:                 lics,
		ComponentLicenses:        componentLicenses,
		ToolVersions:             toolVersions,
		VulnDBSnapshot:           snap.VulnDBSnapshot,
		Completeness:             importedCompleteness(doc),
		LicenseCoverage:          licenseCoverage,
		LicenseCoverageBreakdown: licenseCoverageBreakdown,
		Manifest:                 manifest,
		RiskMatches:              riskMatches,
		SourceWarnings:           sourceWarnings,
		DebugEvents:              trace.snapshot(),
	}
	result.Findings = buildFindings(engagementID, result, now, s.minSeverity, s.ignoreUnfixed, nil)
	result.MinSeverity = s.minSeverity
	result.VulnsBelowThreshold = countBelowThreshold(vulns, s.minSeverity)
	result.UnfixedSuppressed = countUnfixedSuppressed(vulns, s.minSeverity, s.ignoreUnfixed)
	result.FindingQuality = computeFindingQuality(result)
	trace.succeed(step, "Findings derived", map[string]int{"vulnerabilities": len(vulns), "licenses": len(lics), "findings": len(result.Findings)})
	result.DebugEvents = trace.snapshot()
	result.Coverage = sbom.CoverageByEcosystem(*result.SBOM)
	result.ReproDigest = ReproDigest(result)

	if opts.scansVulnerabilities() && s.correlation != nil {
		if report := vulnerability.CrossCheck(detectionSourceNames(s.sources), raws); len(report.Disagreements) > 0 {
			_, _ = s.correlation.Record(ctx, engagementID, report)
		}
	}
	if s.runs != nil {
		keys := make([]string, 0, len(result.Findings))
		for _, f := range result.Findings {
			keys = append(keys, f.DedupKey)
		}
		_ = s.runs.Save(ctx, ports.ScanRun{ID: s.newRunID(), EngagementID: engagementID.String(), CreatedAt: now, Manifest: manifest, FindingKeys: keys})
	}
	s.sealEvidence(ctx, actor, engagementID, now, result)
	if s.scans != nil {
		skipped, err := s.scans.SaveScan(ctx, engagementID, doc, vulns, snap)
		if err != nil {
			return nil, fmt.Errorf("persist scan: %w", err)
		}
		if skipped > 0 {
			if err := s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: "sca.scan.vulns_unlinked", Target: doc.TargetRef, Metadata: map[string]string{"engagement": engagementID.String(), "count": strconv.Itoa(skipped)}, At: s.clock.Now()}); err != nil {
				return nil, fmt.Errorf("audit unlinked vulns: %w", err)
			}
		}
	}
	if s.findings != nil {
		if err := s.findings.Upsert(ctx, result.Findings); err != nil {
			return nil, fmt.Errorf("persist findings: %w", err)
		}
	}
	if s.results != nil {
		if previousData, loadErr := s.results.LatestResult(ctx, engagementID); loadErr == nil {
			var previous ScanResult
			if json.Unmarshal(previousData, &previous) == nil {
				mergeCachedScanResult(result, previous, opts)
			}
		}
		if data, mErr := json.Marshal(result); mErr == nil {
			_ = s.results.SaveResult(ctx, engagementID, data)
		}
	}
	return result, nil
}

func importedCompleteness(doc *sbom.SBOM) ports.Completeness {
	resolved := 0
	for _, c := range doc.Components {
		if sbom.IsResolvedVersion(c.Version) {
			resolved++
		}
	}
	return ports.Completeness{ComponentsTotal: len(doc.Components), ComponentsResolved: resolved, Confident: true, Warning: "imported client SBOM used as scan inventory; source-only analyzers skipped"}
}

func (s *Service) runPipeline(ctx context.Context, actor string, engagementID shared.ID, now time.Time, req ports.AcquireRequest, opts ScanOptions, report func(stage string, pct int, events []ports.ScanDebugEvent)) (*ScanResult, error) {
	stage, pct := stageAcquire, 5
	trace := newScanDebugTrace(func(events []ports.ScanDebugEvent) { report(stage, pct, events) })
	report(stage, pct, trace.snapshot())
	step := trace.start(stageAcquire, "acquire", "", "Acquire and prepare target workspace", nil)
	ws, err := s.acquirer.Acquire(ctx, req)
	if err != nil {
		trace.fail(step, err)
		return nil, fmt.Errorf("acquire target: %w", err)
	}
	trace.succeed(step, "Target workspace acquired", nil)
	defer func() { _ = ws.Close() }()

	stage, pct = stageDetect, 20
	report(stage, pct, trace.snapshot())
	step = trace.start(stageDetect, "language-detection", "", "Detect source languages", nil)
	langs, err := s.detector.Detect(ctx, ws.Dir)
	if err != nil {
		trace.fail(step, err)
		return nil, fmt.Errorf("detect languages: %w", err)
	}
	trace.succeed(step, "Languages detected", map[string]int{"languages": len(langs)})
	stage, pct = stageSBOM, 35
	report(stage, pct, trace.snapshot())
	step = trace.start(stageSBOM, "sbom-generation", "sbom", "Generate SBOM", nil)
	doc, err := s.sbomGen.Generate(ctx, ws.Dir)
	if err != nil {
		trace.fail(step, err)
		return nil, fmt.Errorf("generate sbom: %w", err)
	}
	trace.succeed(step, "SBOM generated", map[string]int{"components": countComponents(doc), "dependencies": len(doc.Dependencies)})
	// SBOM producer cross-check: when a 2nd producer is configured, diff the two RAW
	// component sets — BEFORE enrichment, so it compares the PRODUCERS themselves, not a shared post-process —
	// and record components only one producer emitted as ungated CapCorrelation judgments for human review.
	// Best-effort + opt-in: a 2nd-producer error is ignored (the scan never fails); never auto-resolved.
	if s.sbomCrossCheck != nil && s.sbomGen2 != nil {
		step = trace.start(stageSBOM, "sbom-cross-check", "sbom", "Cross-check SBOM producer output", map[string]int{"components": countComponents(doc)})
		if doc2, derr := s.sbomGen2.Generate(ctx, ws.Dir); derr == nil && doc2 != nil {
			disagreements := 0
			if rep := sbom.CrossCheck([]string{doc.Source, doc2.Source}, []*sbom.SBOM{doc, doc2}); len(rep.Disagreements) > 0 {
				disagreements = len(rep.Disagreements)
				_, _ = s.sbomCrossCheck.Record(ctx, engagementID, rep)
			}
			trace.succeed(step, "SBOM cross-check completed", map[string]int{"components": countComponents(doc), "crosscheck_components": countComponents(doc2), "disagreements": disagreements})
		} else if derr != nil {
			trace.fail(step, derr)
		} else {
			trace.succeed(step, "SBOM cross-check skipped", map[string]int{"components": countComponents(doc)})
		}
	}
	// Enrich the SBOM from manifests Syft under-uses: reconstruct
	// Gemfile.lock dependency edges, recover Maven/Gradle deps Syft can't resolve
	// from source (added BEFORE detection so they get vuln + license scanned), and
	// refine scope via pnpm workspace attribution. Best-effort.
	if s.sbomEnricher != nil {
		before := countComponents(doc)
		step = trace.start(stageSBOM, "sbom-enrichment", "manifest-enricher", "Enrich SBOM from manifests", map[string]int{"components": before})
		s.sbomEnricher.Enrich(ctx, ws.Dir, doc)
		trace.succeed(step, "SBOM enrichment completed", map[string]int{"components_before": before, "components": countComponents(doc)})
	}
	// Resolve the FULL Maven dependency tree via `mvn dependency:list` (best-effort + opt-in): a from-source
	// Maven scan otherwise sees only the direct starters with UNKNOWN (parent-BOM-managed) versions and no
	// transitive tree, so it under-reports vs a build-artifact scan. When it resolves, replace syft's
	// unversioned pom-derived Maven placeholders with the resolved tree (direct + transitive, versioned) so
	// detection + licensing run over the real artifacts. A non-Maven target / missing mvn / error is a no-op.
	mavenResolved := false
	var mavenResolveErr, gradleResolveErr error // surfaced as a SourceWarning so a failed resolve is diagnosable
	if s.mavenResolver != nil {
		step = trace.start(stageSBOM, "maven-resolve", "maven-resolver", "Resolve Maven dependency tree", map[string]int{"components": countComponents(doc)})
		resolvedComps, mrr := s.mavenResolver.Resolve(ctx, ws.Dir)
		before := countComponents(doc)
		// Merge whatever resolved — a partial multi-project result still returns the projects that
		// succeeded (alongside a non-nil error), and those must not be discarded.
		if len(resolvedComps) > 0 {
			mergeResolvedJVM(doc, resolvedComps, true) // dependency:list = all non-test scopes → complete
			mavenResolved = true
		}
		switch {
		case mrr != nil:
			mavenResolveErr = mrr // surfaced as a SourceWarning below (partial OR total failure)
			trace.fail(step, mrr)
		case mavenResolved:
			trace.succeed(step, "Maven dependency tree resolved", map[string]int{"components_before": before, "components": countComponents(doc), "resolved": len(resolvedComps)})
		default:
			trace.succeed(step, "Maven resolution skipped (not a Maven project)", map[string]int{"components": countComponents(doc)})
		}
	}
	// Resolve the FULL Gradle dependency tree via `gradle dependencies` (best-effort + opt-in): same
	// gap as Maven (build.gradle alone gives only direct deps, often versionless, no transitive tree).
	// Gradle uses Maven coordinates, so the resolved set is also pkg:maven and merges the same way.
	gradleResolved := false
	if s.gradleResolver != nil {
		step = trace.start(stageSBOM, "gradle-resolve", "gradle-resolver", "Resolve Gradle dependency tree", map[string]int{"components": countComponents(doc)})
		resolvedComps, grr := s.gradleResolver.Resolve(ctx, ws.Dir)
		before := countComponents(doc)
		if len(resolvedComps) > 0 {
			mergeResolvedJVM(doc, resolvedComps, false) // runtimeClasspath only → keep syft's provided/compileOnly jars
			gradleResolved = true
		}
		switch {
		case grr != nil:
			gradleResolveErr = grr
			trace.fail(step, grr)
		case gradleResolved:
			trace.succeed(step, "Gradle dependency tree resolved", map[string]int{"components_before": before, "components": countComponents(doc), "resolved": len(resolvedComps)})
		default:
			trace.succeed(step, "Gradle resolution skipped (not a Gradle project)", map[string]int{"components": countComponents(doc)})
		}
	}
	// Coarse JVM class-reachability, best-effort + opt-in: tag each JVM component with whether the
	// app's own compiled code (transitively) references its classes, so a finding on a dependency the
	// project never wires in can be DEPRIORITIZED. Runs post-resolve over the resolved tree + the built
	// classes in the workspace; a non-JVM / not-built target tags nothing (never a false "unreferenced").
	if s.jvmReach != nil {
		step = trace.start(stageSBOM, "jvm-reachability", "jvm-reachability", "Tag JVM class-reachability", map[string]int{"components": countComponents(doc)})
		if n, rerr := s.jvmReach.Analyze(ctx, ws.Dir, doc.Components); rerr != nil {
			trace.fail(step, rerr)
		} else {
			trace.succeed(step, "JVM reachability tagged", map[string]int{"components": countComponents(doc), "tagged": n})
		}
	}
	// Resolve transitive Go dependency EDGES via `go mod graph`, best-effort + opt-in: go.mod has no
	// edge graph, so this adds pkg:golang edges between existing components. A non-Go target / no module
	// cache / tool error adds nothing and never fails the scan (mirrors the other best-effort tool hooks).
	if s.graphResolver != nil {
		step = trace.start(stageSBOM, "dependency-graph", "graph-resolver", "Resolve dependency graph edges", map[string]int{"components": countComponents(doc)})
		resolved, rerr := s.graphResolver.ResolveEdges(ctx, ws.Dir, doc)
		if rerr != nil {
			trace.fail(step, rerr)
		} else {
			trace.succeed(step, "Dependency graph resolution completed", map[string]int{"components": countComponents(doc), "resolved_edges": resolved})
		}
	}
	// Recover the coordinate of a shaded / metadata-less JAR from its SHA-1, BEFORE detection,
	// so its CVEs are looked up (a JAR with no resolvable coordinate is otherwise skipped by every source).
	// Best-effort + opt-in (an egress call to Maven Central); a miss/throttle is a no-op.
	if s.jarHash != nil {
		step = trace.start(stageSBOM, "jar-hash-identity", "jar-sha1", "Recover shaded-JAR coordinates by SHA-1", map[string]int{"components": countComponents(doc)})
		n := s.jarHash.Resolve(ctx, doc.Components)
		trace.succeed(step, "JAR SHA-1 coordinate recovery completed", map[string]int{"recovered": n})
	}
	// Mark the project's own modules first-party, so advisories matched
	// against their unresolvable versions become historical, not actionable.
	sbom.ClassifyFirstParty(doc.Components, ws.LocalModules)
	var raws []vulnerability.RawFinding
	var vulns []vulnerability.Vulnerability
	var riskVersions map[string]string
	var riskMatches map[string]int
	if opts.scansVulnerabilities() {
		stage, pct = stageVulns, 55
		report(stage, pct, trace.snapshot())
		// Run every detection source against the SAME SBOM, then correlate: OSV + Grype
		// augment each other. The correlator dedups by advisory id and
		// derives multi-source confidence.
		for _, src := range s.sources {
			step = trace.start(stageVulns, src.Name(), src.Name(), "Scan vulnerabilities with "+src.Name(), map[string]int{"components": countComponents(doc)})
			rfs, err := src.Scan(ctx, doc)
			if err != nil {
				trace.fail(step, err)
				return nil, fmt.Errorf("scan vulnerabilities (%s): %w", src.Name(), err)
			}
			raws = append(raws, rfs...)
			trace.succeed(step, "Vulnerability source completed", map[string]int{"components": countComponents(doc), "raw_findings": len(rfs)})
		}
		step = trace.start(stageVulns, "correlate", "", "Correlate and deduplicate vulnerability findings", map[string]int{"raw_findings": len(raws)})
		vulns = vulnerability.Correlate(raws)
		trace.succeed(step, "Vulnerabilities correlated", map[string]int{"raw_findings": len(raws), "vulnerabilities": len(vulns)})
		// Backfill severity for vulns the sources left unknown (e.g. OSV-only distro CVEs with
		// no CVSS) from NVD, BEFORE risk enrichment so risk priority can use the backfilled CVSS.
		// Best-effort + bounded: a slow/absent NVD leaves them unknown.
		if s.sevEnricher != nil {
			step = trace.start(stageVulns, "severity-backfill", "severity-enricher", "Backfill unknown severities from NVD", map[string]int{"vulnerabilities": len(vulns)})
			sr := s.sevEnricher.Enrich(ctx, vulns)
			vulns = sr.Vulns
			trace.succeed(step, "Severity backfilled", map[string]int{"vulnerabilities": len(vulns), "backfilled": sr.Matches})
		}
		stage, pct = stageRisk, 75
		report(stage, pct, trace.snapshot())
		// Enrich with CISA KEV + EPSS and order by real risk priority (risk priority is
		// KEV -> EPSS x CVSS, never raw CVSS). Best-effort: an outage leaves vulns unenriched.
		if s.riskEnricher != nil {
			step = trace.start(stageRisk, "risk-enrichment", "risk-enricher", "Enrich vulnerabilities with risk signals", map[string]int{"vulnerabilities": len(vulns)})
			r := s.riskEnricher.Enrich(ctx, vulns)
			vulns, riskVersions, riskMatches = r.Vulns, r.Versions, r.Matches
			counts := map[string]int{"vulnerabilities": len(vulns)}
			for k, v := range riskMatches {
				counts[k+"_matches"] = v
			}
			trace.succeed(step, "Risk enrichment completed", counts)
		}
		vulnerability.SortByRisk(vulns)
		attachDependencyPaths(doc, vulns)
		classifyVulns(doc, vulns)
	}

	var lics []ports.LicenseFinding
	var licenseCoverage sbom.LicenseCoverage
	var componentLicenses []ComponentLicenseAudit
	var licenseCoverageBreakdown LicenseCoverageBreakdown
	if opts.scansLicenses() {
		stage, pct = stageLicense, 85
		report(stage, pct, trace.snapshot())
		// Recover authoritative Maven coordinates from JAR pom.properties FIRST, so a
		// mis-derived groupId (Syft inferring it from the class namespace, e.g.
		// io.grpc.internal vs io.grpc) doesn't make the registry lookup 404 → "unknown"
		// for a package that is actually published with a known license. Deterministic +
		// offline (reads JARs in the workspace); best-effort.
		if s.licCoord != nil {
			step = trace.start(stageLicense, "coordinate-recovery", "maven-pom", "Recover Maven coordinates from JAR metadata", map[string]int{"components": countComponents(doc)})
			n := s.licCoord.Resolve(ctx, ws.Dir, doc.Components)
			trace.succeed(step, "Maven coordinate recovery completed", map[string]int{"corrected": n})
		}
		// Recover missing licenses from package-registry metadata before
		// classification, so policy + coverage see registry-declared licenses too.
		if s.licEnricher != nil {
			step = trace.start(stageLicense, "license-enrichment", "license-enricher", "Enrich component license metadata", map[string]int{"components": countComponents(doc)})
			doc.Components = s.licEnricher.Enrich(ctx, doc.Components)
			trace.succeed(step, "License metadata enrichment completed", map[string]int{"components": countComponents(doc)})
		}
		// Deterministic OFFLINE fallback: for components the registry left unknown, classify
		// the license TEXT embedded in their JAR (META-INF/LICENSE, …) into an SPDX id
		// Best-effort; reads JARs in the workspace, no network.
		if s.licFile != nil {
			step = trace.start(stageLicense, "license-file-fallback", "jar-license", "Recover licenses from embedded JAR license text", map[string]int{"components": countComponents(doc)})
			n := s.licFile.Resolve(ctx, ws.Dir, doc.Components)
			trace.succeed(step, "License file fallback completed", map[string]int{"resolved": n})
		}
		step = trace.start(stageLicense, "license-policy", "license-policy", "Evaluate component licenses against policy", map[string]int{"components": countComponents(doc)})
		lics, err = s.licScan.Scan(ctx, doc)
		if err != nil {
			trace.fail(step, err)
			return nil, fmt.Errorf("scan licenses: %w", err)
		}
		trace.succeed(step, "License policy scan completed", map[string]int{"components": countComponents(doc), "licenses": len(lics)})
		licenseCoverage = sbom.ComputeLicenseCoverage(doc.Components)
		componentLicenses = buildComponentLicenseAudit(doc.Components, lics)
		licenseCoverageBreakdown = buildLicenseCoverageBreakdown(doc.Components)
	}

	// Reproducibility: the tool versions used + an OSV snapshot marker
	// (source + query time, since OSV.dev is a live DB with no global version). The
	// map is built fresh per scan and shared read-only by the result + the snapshot.
	stage, pct = stageFindings, 92
	report(stage, pct, trace.snapshot())
	step = trace.start(stageFindings, "derive-findings", "", "Derive findings from scan outputs", map[string]int{"vulnerabilities": len(vulns), "licenses": len(lics)})
	toolVersions := make(map[string]string, len(s.prov.ToolVersions)+len(riskVersions)+1)
	for k, v := range s.prov.ToolVersions {
		toolVersions[k] = v
	}
	for k, v := range riskVersions {
		toolVersions[k] = v
	}
	if doc.GeneratorVersion != "" {
		toolVersions["syft"] = doc.GeneratorVersion
	}
	// Detection-source provenance: record each source's tool + DB version so
	// a result is reproducible/explainable ("why did this differ from last month?").
	grypeDB := ""
	var sourceWarnings []string
	// A build-system resolver that ERRORED (vs "not this ecosystem") leaves the transitive tree
	// uncaptured. The scan is already flagged INCOMPLETE, but surface WHY so the operator can act
	// (e.g. unreachable private repo, missing mvn, un-resolvable parent POM) instead of guessing.
	if mavenResolveErr != nil {
		if mavenResolved { // some projects resolved, at least one did not → partial under-count
			sourceWarnings = append(sourceWarnings, fmt.Sprintf(
				"Maven resolution PARTIALLY failed — some project(s)' transitive tree NOT captured: %v", mavenResolveErr))
		} else {
			sourceWarnings = append(sourceWarnings, fmt.Sprintf(
				"Maven dependency resolution failed — transitive tree NOT captured (result INCOMPLETE): %v", mavenResolveErr))
		}
	}
	if gradleResolveErr != nil {
		if gradleResolved {
			sourceWarnings = append(sourceWarnings, fmt.Sprintf(
				"Gradle resolution PARTIALLY failed — some project(s)' transitive tree NOT captured: %v", gradleResolveErr))
		} else {
			sourceWarnings = append(sourceWarnings, fmt.Sprintf(
				"Gradle dependency resolution failed — transitive tree NOT captured (result INCOMPLETE): %v", gradleResolveErr))
		}
	}
	for _, src := range s.sources {
		p, ok := src.(ports.SourceProvenance)
		if !ok {
			continue
		}
		ver, db := p.Provenance()
		if ver != "" {
			toolVersions[src.Name()] = ver
		}
		if db != "" {
			toolVersions[src.Name()+"-db"] = db
			if src.Name() == "grype" {
				grypeDB = db
			}
		}
		// A source that EXPOSES provenance but reports it empty after a scan over a non-empty
		// SBOM did not run (today only Grype degrades silently this way — its binary/DB missing;
		// OSV + the owned store fail the scan loudly instead, so they need no such flag). Surface
		// it so a silently-degraded source can't read as "0 vulns / clean" — a real "missing
		// vulns" cause. Grype resets its provenance every scan, so this can't false-negative on a
		// stale prior success.
		if ver == "" && db == "" && len(doc.Components) > 0 {
			sourceWarnings = append(sourceWarnings, fmt.Sprintf(
				"detection source %q did not run (tool/DB missing or errored) — its vulnerabilities are NOT included", src.Name()))
		}
	}
	snap := ports.ScanSnapshot{
		ToolVersions:   toolVersions,
		VulnDBSnapshot: s.prov.VulnDBSource + "@" + now.UTC().Format(time.RFC3339),
		GrypeDBVersion: grypeDB,
	}
	manifest := buildManifest(toolVersions, snap.VulnDBSnapshot, grypeDB, doc)

	// Maven, once its full tree is resolved (mvn dependency:list), is no longer an under-reporting
	// unresolved ecosystem — drop it from the completeness signal so the scan reads as complete.
	unresolvedEco := ws.UnresolvedEcosystems
	// A successful Maven/Gradle resolution produces the FULL versioned tree — a complete resolving
	// source, equivalent to a lockfile. Drop the ecosystem from the unresolved set AND record a synthetic
	// lockfile marker so completeness reads the scan as confident (no "transitive tree unresolved" or
	// "X of Y pinned" warning) rather than still flagging it incomplete.
	lockfiles := ws.Lockfiles
	if mavenResolved {
		unresolvedEco = removeEcosystem(unresolvedEco, "maven")
		lockfiles = append(append([]string{}, lockfiles...), "maven-dependency-tree")
	}
	if gradleResolved {
		unresolvedEco = removeEcosystem(unresolvedEco, "gradle")
		lockfiles = append(append([]string{}, lockfiles...), "gradle-dependency-tree")
	}

	result := &ScanResult{
		Target:                   req.Value, // report the original target, not the temp dir
		ScanMode:                 opts.Mode,
		Languages:                langs,
		SBOM:                     doc,
		Vulnerabilities:          vulns,
		Licenses:                 lics,
		ComponentLicenses:        componentLicenses,
		ToolVersions:             toolVersions,
		VulnDBSnapshot:           snap.VulnDBSnapshot,
		Completeness:             computeCompleteness(doc, lockfiles, unresolvedEco),
		LicenseCoverage:          licenseCoverage,
		LicenseCoverageBreakdown: licenseCoverageBreakdown,
		Manifest:                 manifest,
		RiskMatches:              riskMatches,
		SourceWarnings:           sourceWarnings,
		Image:                    ws.Image,
		DebugEvents:              trace.snapshot(),
	}
	// Container-image layer attribution (Epic D): join each vuln to the layer that introduced
	// its component, and classify base vs application layers. No-op for non-image scans.
	attributeImageLayers(result.Image, doc, result.Vulnerabilities)
	// Capture the OS distribution from the SBOM's OS-package PURLs and flag it if End-of-Life
	// (no security updates) as of the scan time — a posture signal for container/host scans (Epic E).
	result.Distro = captureDistro(doc, now)
	// Deterministic pattern-SAST over the LIVE workspace: weak crypto / hardcoded secrets /
	// insecure config in first-party source. In-process, read-only, no LLM; findings publish like SCA.
	var sastRaws []ports.SASTRawFinding
	if opts.scansVulnerabilities() && s.sastAnalyzer != nil {
		sastRaws, err = s.sastAnalyzer.AnalyzeSource(ctx, ws.Dir)
		if err != nil {
			return nil, fmt.Errorf("analyze source (sast): %w", err)
		}
	}
	result.Findings = buildFindings(engagementID, result, now, s.minSeverity, s.ignoreUnfixed, sastRaws)
	// Deterministic secret scan over the LIVE workspace: hardcoded credentials, redacted before they
	// leave the scanner. Ungated Kind=secret findings, publishable like SCA. Best-effort.
	if opts.scansVulnerabilities() && s.secretScanner != nil {
		secretRaws, serr := s.secretScanner.ScanFiles(ctx, ws.Dir)
		if serr != nil {
			return nil, fmt.Errorf("scan secrets: %w", serr)
		}
		result.Findings = append(result.Findings, buildSecretFindings(engagementID, secretRaws, now, s.minSeverity)...)
	}
	result.MinSeverity = s.minSeverity
	result.VulnsBelowThreshold = countBelowThreshold(vulns, s.minSeverity)
	result.UnfixedSuppressed = countUnfixedSuppressed(vulns, s.minSeverity, s.ignoreUnfixed)
	result.FindingQuality = computeFindingQuality(result)
	trace.succeed(step, "Findings derived", map[string]int{"vulnerabilities": len(vulns), "licenses": len(lics), "findings": len(result.Findings)})
	result.DebugEvents = trace.snapshot()
	if result.SBOM != nil {
		result.Coverage = sbom.CoverageByEcosystem(*result.SBOM) // per-ecosystem coverage breakdown
	}

	// Deterministic Tier-2 reachability proof, best-effort + opt-in: prove which findings' affected
	// symbols are actually CALLED in the live workspace and mint Tier-2 judgments that supersede weaker
	// (LLM Tier-1.5) reachability claims. A no-coverage/un-buildable target (e.g. non-Go, or no module
	// cache) returns an error here — IGNORED: reachability is an enhancement, so the prior tier stands and
	// the scan is never failed (mirrors the best-effort sbom/risk enrichers). Runs while ws.Dir still exists.
	if opts.scansVulnerabilities() && s.reachability != nil {
		if subs := reachabilitySubjects(result.Findings, result.Vulnerabilities); len(subs) > 0 {
			_, _ = s.reachability.Record(ctx, engagementID, ws.Dir, subs)
		}
	}

	// Deterministic taint-analysis CapSAST proposals, best-effort + opt-in: build the workspace call
	// graph (sandboxed), assemble the taint FlowGraph over the injection catalog, and PROPOSE gated CapSAST
	// judgments (one per injection path × class) for a distinct verifier to gate. Same best-effort contract
	// as reachability — a no-coverage/un-buildable target returns an error here that is IGNORED (taint is an
	// enhancement; the scan is never failed). Runs while ws.Dir still exists.
	if opts.scansVulnerabilities() && s.taint != nil {
		_, _ = s.taint.Scan(ctx, engagementID, ws.Dir)
	}

	// Cross-check disagreement judgments, best-effort + opt-in: where the RUN detection sources
	// disagree on a vuln (one reported it; another that ran did not), mint an ungated CapCorrelation
	// judgment for human review (never auto-resolved). Uses the pre-correlation multi-source raws
	// + the run source names. A recorder error is IGNORED — like reachability, this is an enhancement, not a
	// gate; the scan is never failed. No-op with <2 sources (nothing can disagree).
	if opts.scansVulnerabilities() && s.correlation != nil {
		if report := vulnerability.CrossCheck(detectionSourceNames(s.sources), raws); len(report.Disagreements) > 0 {
			_, _ = s.correlation.Record(ctx, engagementID, report)
		}
	}

	// Reproducibility fingerprint: a stable content digest of the SBOM + findings, so the same
	// inputs (target + pinned producer + pinned advisory/DB snapshot) verifiably yield the same scan.
	result.ReproDigest = ReproDigest(result)

	// Persist this run's manifest + finding keys for history + drift.
	if s.runs != nil {
		keys := make([]string, 0, len(result.Findings))
		for _, f := range result.Findings {
			keys = append(keys, f.DedupKey)
		}
		_ = s.runs.Save(ctx, ports.ScanRun{
			ID:           s.newRunID(),
			EngagementID: engagementID.String(),
			CreatedAt:    now,
			Manifest:     manifest,
			FindingKeys:  keys,
		})
	}

	// Seal this scan into the engagement's append-only hash-chained evidence ledger
	// One tamper-evident link per scan, bound to the prior link.
	s.sealEvidence(ctx, actor, engagementID, now, result)

	// The scan snapshot and the findings are written in SEPARATE transactions. A
	// SaveScan that commits without its findings is tolerated: findings are
	// deterministically re-derivable on the next scan. (P-later: outbox / one txn.)
	if s.scans != nil {
		skipped, err := s.scans.SaveScan(ctx, engagementID, doc, vulns, snap)
		if err != nil {
			return nil, fmt.Errorf("persist scan: %w", err)
		}
		if skipped > 0 {
			// A vuln could not be linked to an SBOM component and was dropped — record it
			// on the append-only audit log (counts only; never advisory/component text).
			if err := s.audit.Record(ctx, ports.AuditEntry{
				Actor:    actor,
				Action:   "sca.scan.vulns_unlinked",
				Target:   req.Value,
				Metadata: map[string]string{"engagement": engagementID.String(), "count": strconv.Itoa(skipped)},
				At:       s.clock.Now(),
			}); err != nil {
				return nil, fmt.Errorf("audit unlinked vulns: %w", err)
			}
		}
	}
	if s.findings != nil {
		if err := s.findings.Upsert(ctx, result.Findings); err != nil {
			return nil, fmt.Errorf("persist findings: %w", err)
		}
	}
	// Cache the full result so the UI can re-display it after a reload (best-effort;
	// a cache-write failure must not fail an otherwise-successful scan).
	if s.results != nil {
		if previousData, loadErr := s.results.LatestResult(ctx, engagementID); loadErr == nil {
			var previous ScanResult
			if json.Unmarshal(previousData, &previous) == nil {
				mergeCachedScanResult(result, previous, opts)
			}
		}
		if data, mErr := json.Marshal(result); mErr == nil {
			_ = s.results.SaveResult(ctx, engagementID, data)
		}
	}
	return result, nil
}

func mergeCachedScanResult(current *ScanResult, previous ScanResult, opts ScanOptions) {
	if current == nil || opts.Mode == ScanModeFull {
		return
	}
	preserved := false
	if !opts.scansVulnerabilities() {
		current.Vulnerabilities = previous.Vulnerabilities
		current.VulnDBSnapshot = previous.VulnDBSnapshot
		current.Findings = mergeFindingsByKind(previous.Findings, current.Findings, true)
		preserved = len(previous.Vulnerabilities) > 0 || hasFindingKind(previous.Findings, false)
	}
	if !opts.scansLicenses() {
		current.Licenses = previous.Licenses
		current.ComponentLicenses = previous.ComponentLicenses
		current.LicenseCoverage = previous.LicenseCoverage
		current.LicenseCoverageBreakdown = previous.LicenseCoverageBreakdown
		current.Findings = mergeFindingsByKind(current.Findings, previous.Findings, true)
		preserved = len(previous.Licenses) > 0 || len(previous.ComponentLicenses) > 0 || hasFindingKind(previous.Findings, true)
	}
	if preserved {
		current.ScanMode = ScanModeFull
	}
}

func mergeFindingsByKind(primary, secondary []finding.Finding, takeLicenseFromSecondary bool) []finding.Finding {
	out := make([]finding.Finding, 0, len(primary)+len(secondary))
	seen := map[string]struct{}{}
	appendIf := func(items []finding.Finding, wantLicense bool) {
		for _, item := range items {
			if isLicenseFinding(item) != wantLicense {
				continue
			}
			if _, ok := seen[item.DedupKey]; ok {
				continue
			}
			seen[item.DedupKey] = struct{}{}
			out = append(out, item)
		}
	}
	appendIf(primary, !takeLicenseFromSecondary)
	appendIf(secondary, takeLicenseFromSecondary)
	return out
}

func hasFindingKind(items []finding.Finding, license bool) bool {
	for _, item := range items {
		if isLicenseFinding(item) == license {
			return true
		}
	}
	return false
}

func isLicenseFinding(item finding.Finding) bool {
	return strings.HasPrefix(item.DedupKey, "license:")
}

// LatestResult returns the cached JSON of the engagement's most recent scan
// (SBOM, vulnerabilities, dependency graph, languages, provenance) so the UI can
// rehydrate the scan tabs after a page reload. shared.ErrNotFound if none.
func (s *Service) LatestResult(ctx context.Context, engagementID shared.ID) ([]byte, error) {
	if s.results == nil {
		return nil, fmt.Errorf("scan result: %w", shared.ErrNotFound)
	}
	return s.results.LatestResult(ctx, engagementID)
}

func kindOrLocal(kind string) string {
	if kind == "" {
		return ports.TargetLocal
	}
	return kind
}

// attachDependencyPaths annotates each vulnerability with the dependency path from
// a top-level dependency down to its component (remediation context), using the
// SBOM's dependency graph.
// classifyVulns marks each vuln first-party / unversioned from its SBOM component
// . Unversioned (no resolvable version) means the advisory cannot be
// confirmed against an affected range — it becomes a historical advisory.
func classifyVulns(doc *sbom.SBOM, vulns []vulnerability.Vulnerability) {
	firstParty := make(map[string]bool, len(doc.Components))
	scopeByCV := make(map[string]string, len(doc.Components))
	reachByCV := make(map[string]string, len(doc.Components))
	for _, c := range doc.Components {
		if c.FirstParty {
			firstParty[c.Name] = true
		}
		if c.Scope != "" {
			scopeByCV[c.Name+"\x00"+c.Version] = c.Scope
		}
		if c.Reachability != "" {
			reachByCV[c.Name+"\x00"+c.Version] = c.Reachability
		}
	}
	for i := range vulns {
		v := &vulns[i]
		v.Unversioned = !sbom.IsResolvedVersion(v.Version)
		if firstParty[v.Component] {
			v.FirstParty = true
		}
		v.Scope = scopeByCV[v.Component+"\x00"+v.Version]
		if v.Scope == "" {
			v.Scope = sbom.ScopeUnknown
		}
		// Finding-quality signals: reachability, impact, priority. The coarse JVM
		// class-reachability verdict rides along and DEPRIORITIZES a vuln on an unreferenced
		// component by one tier (never suppresses — it's a coarse, reflection-blind signal).
		v.ClassReachability = reachByCV[v.Component+"\x00"+v.Version]
		v.Reachability = vulnerability.Reachability(v.Scope, v.Direct)
		v.Impact = vulnerability.Impact(v.Severity, v.Scope)
		v.Priority = vulnerability.RiskPriority(v.Impact, v.Reachability, v.KEV, v.ClassReachability == sbom.ReachabilityUnreferenced)
	}
}

func attachDependencyPaths(doc *sbom.SBOM, vulns []vulnerability.Vulnerability) {
	if len(doc.Dependencies) == 0 {
		return
	}
	idByNV := make(map[string]string, len(doc.Components))
	for _, c := range doc.Components {
		idByNV[c.Name+"@"+c.Version] = sbom.ComponentID(c.Name, c.Version, c.PURL)
	}
	for i := range vulns {
		id := idByNV[vulns[i].Component+"@"+vulns[i].Version]
		if id == "" {
			continue
		}
		path := sbom.PathToRoot(doc.Dependencies, id)
		vulns[i].Path = path
		vulns[i].Direct = len(path) > 0 && len(path) <= 2
	}
}

// computeCompleteness reports whether dependency versions were actually resolved.
// A scan of source WITHOUT a lockfile leaves versions unresolved, so a low/zero
// vulnerability count must not be read as "clean" — never silently
// under-report (a trust signal).
func computeCompleteness(doc *sbom.SBOM, lockfiles, unresolvedEco []string) ports.Completeness {
	total := len(doc.Components)
	resolved, osPkgs, appTotal, appResolved := 0, 0, 0, 0
	for _, c := range doc.Components {
		pinned := isPinnedVersion(c.Version)
		if pinned {
			resolved++
		}
		if isOSPackage(c.PURL) {
			osPkgs++
			continue
		}
		appTotal++ // non-OS (application) dependency
		if pinned {
			appResolved++
		}
	}
	c := ports.Completeness{Lockfiles: lockfiles, ComponentsTotal: total, ComponentsResolved: resolved}
	// Confidence is judged on the APPLICATION (non-OS) components ONLY. OS packages are read
	// installed + fully pinned from the package-manager DB, so they must not DILUTE an
	// unresolved app surface — otherwise a few range-versioned app deps could hide behind many
	// pinned OS packages and falsely read "confident" (a silent under-report).
	appRatio := 1.0
	if appTotal > 0 {
		appRatio = float64(appResolved) / float64(appTotal)
	}
	// A container / OS image scan reads INSTALLED packages from the package-manager DB
	// (dpkg/apk/rpm) — authoritative + pinned, needing NO manifest lockfile. Record the DB as
	// the resolving source so the scan is not mislabeled "INCOMPLETE — provide a lockfile"
	// (nonsensical for a container).
	osScan := osPkgs > 0
	if osScan { // osPackageDB is synthetic — produced only here, so no need to dedup against lockfiles
		c.Lockfiles = append(append([]string{}, lockfiles...), osPackageDB)
	}
	// Confident when a resolving source exists (a manifest lockfile, or the OS DB), the APP
	// components are well-resolved, and no app build system is left unresolved (Gradle/Maven
	// without a lockfile under-reports that ecosystem's transitive tree — honesty fix).
	c.Confident = (len(lockfiles) > 0 || osScan) && appRatio >= 0.8 && len(unresolvedEco) == 0
	switch {
	case len(unresolvedEco) > 0:
		c.Warning = fmt.Sprintf("Unresolved build system(s) present: %s. Their dependencies are NOT fully captured "+
			"(the transitive tree wasn't resolved from source), so this result is INCOMPLETE — a low finding count does NOT mean clean. %s",
			strings.Join(unresolvedEco, ", "), unresolvedRemediation(unresolvedEco))
	case c.Confident:
	case total == 0:
		c.Warning = "No components resolved — the target has no recognized dependency manifests."
	case appTotal > 0 && appRatio < 0.8 && len(lockfiles) == 0:
		// Application dependencies are present without a lockfile (whether or not OS packages
		// are too): their versions are unresolved and under-reported. Reported over the APP
		// components so abundant pinned OS packages can't make it look complete.
		c.Warning = fmt.Sprintf("No application lockfile found; only %d of %d application components have pinned versions. "+
			"Those dependencies are unresolved, so this result is INCOMPLETE for the application — a low vulnerability count does "+
			"NOT mean clean. Provide a lockfile (package-lock.json, yarn.lock, Gemfile.lock, poetry.lock, go.sum, ...) for a complete scan.", appResolved, appTotal)
	default:
		c.Warning = fmt.Sprintf("Only %d of %d components have pinned versions; some dependencies are unresolved and may be under-reported.", resolved, total)
	}
	return c
}

// osPackageDB is the synthetic "resolving source" recorded for a container/OS scan, where the
// OS package-manager DB (dpkg/apk/rpm) — not a manifest lockfile — is the authoritative pinned source.
const osPackageDB = "os-package-db"

// isOSPackage reports whether a PURL is an OS package-manager package (Debian/Ubuntu deb, Alpine
// apk, RHEL/Fedora rpm, Arch alpm) — an installed package read from the OS DB, always pinned.
func isOSPackage(purl string) bool {
	switch ecosystemFromPURL(purl) {
	case "deb", "apk", "rpm", "alpm":
		return true
	}
	return false
}

// captureDistro derives the target's OS distribution from its OS-package PURL "distro" qualifiers
// (Syft sets these from /etc/os-release) and evaluates its End-of-Life status as of asOf (Epic E).
// Returns nil when the target has no OS packages (e.g. a source-only scan). Deterministic + offline.
func captureDistro(doc *sbom.SBOM, asOf time.Time) *distro.Status {
	if doc == nil {
		return nil
	}
	var tags []string
	for _, c := range doc.Components {
		if !isOSPackage(c.PURL) {
			continue
		}
		if tag := purlDistroTag(c.PURL); tag != "" {
			tags = append(tags, tag)
		}
	}
	rel, ok := distro.Detect(tags)
	if !ok {
		return nil
	}
	st := distro.Evaluate(rel, asOf)
	return &st
}

// purlDistroTag extracts the "distro" qualifier value from a PURL ("…?arch=amd64&distro=debian-9" →
// "debian-9"); "" if absent.
func purlDistroTag(purl string) string {
	i := strings.IndexByte(purl, '?')
	if i < 0 {
		return ""
	}
	for _, kv := range strings.Split(purl[i+1:], "&") {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "distro" {
			return v
		}
	}
	return ""
}

// removeEcosystem returns unresolvedEco without the named ecosystem (case-insensitive), preserving order.
func removeEcosystem(unresolvedEco []string, name string) []string {
	out := make([]string, 0, len(unresolvedEco))
	for _, e := range unresolvedEco {
		if !strings.EqualFold(e, name) {
			out = append(out, e)
		}
	}
	return out
}

// unresolvedRemediation gives ECOSYSTEM-ACCURATE guidance for turning an incomplete scan into a
// complete one. Maven has no lockfile, so the generic "write a lockfile" advice (correct for Gradle)
// misleads a Maven user — the fix there is to scan a built artifact or resolve the tree first. This is
// why a Maven-from-source scan under-reports vs a tool that resolves the full dependency tree.
func unresolvedRemediation(unresolvedEco []string) string {
	has := func(name string) bool {
		for _, e := range unresolvedEco {
			if strings.EqualFold(e, name) {
				return true
			}
		}
		return false
	}
	var tips []string
	if has("maven") {
		tips = append(tips, "Maven has no lockfile — scan a BUILT artifact (`mvn package`, then scan the produced JAR or `target/`), "+
			"or resolve the tree first (`mvn dependency:copy-dependencies -DoutputDirectory=target/deps`) and scan that directory")
	}
	if has("gradle") {
		tips = append(tips, "Gradle — generate a lockfile (`gradle dependencies --write-locks`) then re-scan")
	}
	if len(tips) == 0 {
		tips = append(tips, "provide a resolved lockfile or a built artifact, then re-scan")
	}
	return "For a COMPLETE scan: " + strings.Join(tips, "; ") + "."
}

// attributeImageLayers attributes each vulnerability to the container-image layer that
// introduced its component, and classifies the image's base layers (Epic D). No-op for
// non-image scans (img == nil). It joins vulns → SBOM components → layers entirely on data
// already gathered (Syft's per-component layerID + the OCI image config), deterministically.
func attributeImageLayers(img *sbom.ImageInfo, doc *sbom.SBOM, vulns []vulnerability.Vulnerability) {
	if img == nil || doc == nil {
		return
	}
	// component (name@version) -> its layer diff_id; and the set of layers that introduced an
	// APPLICATION (non-OS) package, which marks the base/application boundary.
	compLayer := make(map[string]string, len(doc.Components))
	appLayers := map[string]bool{}
	for _, c := range doc.Components {
		if c.LayerID == "" {
			continue
		}
		compLayer[c.Name+"@"+c.Version] = c.LayerID
		if !isOSPackage(c.PURL) {
			appLayers[c.LayerID] = true
		}
	}
	img.MarkBaseLayers(appLayers)

	// Index the layers by diff_id for a single-pass join; take each vuln's index / base
	// classification / build command from the matched layer itself (the single source of
	// truth set by MarkBaseLayers) rather than re-deriving from the count.
	byDiff := make(map[string]*sbom.ImageLayer, len(img.Layers))
	for i := range img.Layers {
		byDiff[img.Layers[i].DiffID] = &img.Layers[i]
	}
	for i := range vulns {
		v := &vulns[i]
		layerID := compLayer[v.Component+"@"+v.Version]
		if layerID == "" {
			continue // unattributed: LayerID stays empty (the canonical "no layer" signal)
		}
		l, ok := byDiff[layerID]
		if !ok {
			continue // component carried a layerID the image config doesn't list — treat as unattributed
		}
		idx := l.Index
		v.LayerID = layerID
		v.LayerIndex = &idx // pointer ⇒ a genuine layer-0 attribution is never confused with "unset"
		v.InBaseImage = l.InBase
		v.LayerCreatedBy = l.CreatedBy
	}
}

// isPinnedVersion reports whether v looks like a single resolved version (starts
// with a digit, or v<digit>) rather than a range/wildcard (^, ~, >=, *, "latest").
func isPinnedVersion(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	switch c := v[0]; {
	case c >= '0' && c <= '9':
		return true
	case (c == 'v' || c == 'V') && len(v) > 1 && v[1] >= '0' && v[1] <= '9':
		return true
	}
	return false
}

// credInErr matches credentials embedded in a URL (scheme://userinfo@host) that a
// future tool adapter might echo into an error, so they never reach the client via
// job.Error — a second layer beyond the acquirer's own redaction.
var credInErr = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+@`)

// sealEvidence appends one tamper-evident link summarizing this scan to the
// engagement's hash chain. Content is a canonical digest of the run:
// SBOM hash, finding keys, and the manifest — so any later tampering is detectable
// by re-verification. Best-effort: a ledger write must not fail a good scan.
func (s *Service) sealEvidence(ctx context.Context, actor string, engagementID shared.ID, now time.Time, result *ScanResult) {
	if s.evidence == nil {
		return
	}
	keys := make([]string, 0, len(result.Findings))
	for _, f := range result.Findings {
		keys = append(keys, f.DedupKey)
	}
	sort.Strings(keys)
	payload := struct {
		SBOMSHA256 string             `json:"sbom_sha256"`
		Findings   []string           `json:"findings"`
		Manifest   ports.ScanManifest `json:"manifest"`
		SealedAt   string             `json:"sealed_at"`
		Actor      string             `json:"actor"`
	}{result.Manifest.SBOMSHA256, keys, result.Manifest, now.UTC().Format(time.RFC3339), actor}
	content, err := json.Marshal(payload)
	if err != nil {
		return
	}
	// Append through the evidence vault — one tamper-evident chain + verify path per
	// engagement. The vault binds the link to the current head; a transient
	// Head failure fails the seal rather than forking the chain.
	_, _ = s.evidence.Seal(ctx, engagementID, "scan", content, actor)
}

// ReportInsight assembles the scan-level context the executive report needs:
// license coverage, completeness, reproducibility, and evidence integrity. Returns
// a zero-value (HasScan=false) insight when no scan has run.
func (s *Service) ReportInsight(ctx context.Context, engagementID shared.ID) (ports.ReportInsight, error) {
	var ins ports.ReportInsight
	// A scan is optional (recon-only / manual engagements have none); ErrNotFound just
	// means "no scan", any other error is fatal.
	data, err := s.LatestResult(ctx, engagementID)
	if err != nil && !errors.Is(err, shared.ErrNotFound) {
		return ports.ReportInsight{}, err
	}
	if err == nil {
		var res ScanResult
		if err := json.Unmarshal(data, &res); err != nil {
			return ports.ReportInsight{}, fmt.Errorf("decode scan result: %w", err)
		}
		ins = ports.ReportInsight{
			ScanTarget:       res.Target,
			HasScan:          true,
			ScanTime:         res.scanTime(),
			LicenseDetected:  res.LicenseCoverage.Detected,
			LicenseUnknown:   res.LicenseCoverage.Unknown,
			LicensePct:       res.LicenseCoverage.Pct,
			Confident:        res.Completeness.Confident,
			CompletenessNote: res.Completeness.Warning,
			ReproScore:       res.Manifest.ReproScore,
			PinnedInputs:     res.Manifest.PinnedInputs,
			UnpinnedInputs:   res.Manifest.UnpinnedInputs,
			VulnDBSnapshot:   res.VulnDBSnapshot,
			GrypeDBVersion:   res.Manifest.GrypeDBVersion,

			ThirdPartyFindings:   res.FindingQuality.ThirdParty,
			FirstPartyHistorical: res.FindingQuality.FirstPartyHistorical,
			VersionCoveragePct:   res.FindingQuality.VersionCoveragePct,
			PathCoveragePct:      res.FindingQuality.PathCoveragePct,
			RawFindings:          res.FindingQuality.RawFindings,
			Actionable:           res.FindingQuality.Actionable,
			Background:           res.FindingQuality.Background,
			Production:           res.FindingQuality.Production,
			Development:          res.FindingQuality.Development,
			ExampleTest:          res.FindingQuality.ExampleTest,
			PriorityCounts:       res.FindingQuality.ByPriority,
		}
	}
	// Always verify the evidence chain — recon-only and manual engagements seal
	// evidence too. A verification ERROR fails closed (not silently read as "no
	// evidence"), so the report gate can block a custody chain it could not prove.
	ev, err := s.VerifyEvidence(ctx, engagementID)
	if err != nil {
		return ports.ReportInsight{}, fmt.Errorf("verify evidence for report: %w", err)
	}
	ins.EvidenceIntact = ev.Intact
	ins.EvidenceHead = ev.Head
	ins.EvidenceCount = ev.Verified
	if ev.Attestation != nil {
		ins.EvidenceAttested = true
		ins.EvidenceKeyID = ev.Attestation.KeyID
	}
	return ins, nil
}

// EvidenceReport is the engagement's evidence ledger plus its verification status.
type EvidenceReport struct {
	Items       []evidence.Evidence   `json:"items"`
	Intact      bool                  `json:"intact"`
	Head        string                `json:"head"`
	Error       string                `json:"error,omitempty"`
	Verified    int                   `json:"verified"` // number of links verified
	Attestation *evidence.Attestation `json:"attestation,omitempty"`
	Anchored    bool                  `json:"anchored"` // external RFC-3161 timestamp present
	Timestamp   *ports.TimestampToken `json:"timestamp,omitempty"`
}

// VerifyEvidence loads the engagement's evidence chain and verifies its integrity
// (tamper detection). Used by the API + before the report is generated.
func (s *Service) VerifyEvidence(ctx context.Context, engagementID shared.ID) (EvidenceReport, error) {
	if s.evidence == nil {
		return EvidenceReport{Intact: true}, nil
	}
	// Delegate to the evidence vault so a tamper is detected + ALERTED from one
	// place, whether reached via the API or before a report.
	rep, err := s.evidence.Verify(ctx, engagementID)
	if err != nil {
		return EvidenceReport{}, err
	}
	return EvidenceReport{Items: rep.Items, Intact: rep.Intact, Head: rep.Head, Error: rep.Error, Verified: rep.Verified, Attestation: rep.Attestation, Anchored: rep.Anchored, Timestamp: rep.Timestamp}, nil
}

// ScanRuns returns the engagement's scan-run history (newest first) for the
// reproducibility / drift UI.
func (s *Service) ScanRuns(ctx context.Context, engagementID shared.ID) ([]ports.ScanRun, error) {
	if s.runs == nil {
		return nil, nil
	}
	return s.runs.List(ctx, engagementID)
}

// ScanDrift is the difference between two scan runs: which findings appeared or
// disappeared, and the manifest deltas that explain why.
type ScanDrift struct {
	RunA        ports.ScanRun `json:"run_a"`
	RunB        ports.ScanRun `json:"run_b"`
	Added       []string      `json:"added"`       // finding keys in B not in A
	Removed     []string      `json:"removed"`     // finding keys in A not in B
	Unchanged   int           `json:"unchanged"`   // count present in both
	Explanation []string      `json:"explanation"` // manifest deltas that explain the drift
}

// CompareRuns computes the drift between two runs and explains it from the
// manifest deltas (chain-of-custody: "why does this differ from last month?").
func (s *Service) CompareRuns(ctx context.Context, runA, runB string) (ScanDrift, error) {
	if s.runs == nil {
		return ScanDrift{}, fmt.Errorf("scan runs: %w", shared.ErrNotFound)
	}
	a, err := s.runs.Get(ctx, runA)
	if err != nil {
		return ScanDrift{}, err
	}
	b, err := s.runs.Get(ctx, runB)
	if err != nil {
		return ScanDrift{}, err
	}
	return diffRuns(a, b), nil
}

func diffRuns(a, b ports.ScanRun) ScanDrift {
	inA := map[string]bool{}
	for _, k := range a.FindingKeys {
		inA[k] = true
	}
	inB := map[string]bool{}
	for _, k := range b.FindingKeys {
		inB[k] = true
	}
	d := ScanDrift{RunA: a, RunB: b}
	for _, k := range b.FindingKeys {
		if !inA[k] {
			d.Added = append(d.Added, k)
		} else {
			d.Unchanged++
		}
	}
	for _, k := range a.FindingKeys {
		if !inB[k] {
			d.Removed = append(d.Removed, k)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	d.Explanation = explainDrift(a.Manifest, b.Manifest)
	return d
}

// explainDrift lists the manifest inputs that changed between two runs — the
// reasons a result can legitimately differ.
func explainDrift(a, b ports.ScanManifest) []string {
	var out []string
	cmp := func(label, av, bv string) {
		if av != bv {
			out = append(out, fmt.Sprintf("%s changed: %q -> %q", label, av, bv))
		}
	}
	cmp("grype-db", a.GrypeDBVersion, b.GrypeDBVersion)
	cmp("syft", a.ToolVersions["syft"], b.ToolVersions["syft"])
	cmp("grype", a.ToolVersions["grype"], b.ToolVersions["grype"])
	cmp("kev-catalog", a.ToolVersions["kev-catalog"], b.ToolVersions["kev-catalog"])
	cmp("epss-date", a.ToolVersions["epss-date"], b.ToolVersions["epss-date"])
	if a.CorrelationVersion != b.CorrelationVersion {
		out = append(out, fmt.Sprintf("correlation logic changed: v%d -> v%d", a.CorrelationVersion, b.CorrelationVersion))
	}
	if a.SBOMSHA256 != b.SBOMSHA256 {
		out = append(out, "SBOM changed (the target's dependencies differ between runs)")
	}
	if a.VulnDBSnapshot != b.VulnDBSnapshot {
		out = append(out, "OSV.dev is a live source queried per scan — advisories may have changed between runs (unpinned)")
	}
	if len(out) == 0 {
		out = append(out, "no manifest inputs changed — results should be identical")
	}
	return out
}

func nonEmptyScope(s string) string {
	if s == "" {
		return sbom.ScopeUnknown
	}
	return s
}

// newRunID returns an id for a persisted scan run (uses the injected generator
// when available, else a content-free fallback so the CLI path still works).
func (s *Service) newRunID() string {
	if s.ids != nil {
		return s.ids.NewID().String()
	}
	return "run"
}

// buildManifest assembles the reproducibility manifest + score. The
// repro score is the fraction of detection inputs that are version-pinned; the
// live OSV.dev query is honestly counted as unpinned.
func buildManifest(toolVersions map[string]string, vulnDBSnapshot, grypeDB string, doc *sbom.SBOM) ports.ScanManifest {
	m := ports.ScanManifest{
		ToolVersions:       toolVersions,
		VulnDBSnapshot:     vulnDBSnapshot,
		GrypeDBVersion:     grypeDB,
		CorrelationVersion: vulnerability.CorrelationVersion,
	}
	// Hash the NORMALIZED component set (sorted name@version@purl), not doc.Raw:
	// Syft's CycloneDX embeds a random serialNumber + timestamp, so the raw bytes
	// differ between identical scans and would flag spurious drift.
	if doc != nil && len(doc.Components) > 0 {
		ids := make([]string, 0, len(doc.Components))
		for _, c := range doc.Components {
			ids = append(ids, c.Name+"@"+c.Version+"@"+c.PURL)
		}
		sort.Strings(ids)
		sum := sha256.Sum256([]byte(strings.Join(ids, "\n")))
		m.SBOMSHA256 = fmt.Sprintf("%x", sum)
	}
	// Inputs that determine the result, and whether each is version-pinned.
	pin := func(label string, pinned bool) {
		if pinned {
			m.PinnedInputs = append(m.PinnedInputs, label)
		} else {
			m.UnpinnedInputs = append(m.UnpinnedInputs, label)
		}
	}
	pin("syft", toolVersions["syft"] != "")
	pin("grype-db", grypeDB != "")
	pin("kev-catalog", toolVersions["kev-catalog"] != "")
	pin("epss", toolVersions["epss-date"] != "")
	pin("correlation", true)
	pin("sbom", m.SBOMSHA256 != "")
	pin("osv.dev", false) // live source: queried at scan time, not version-pinned
	total := len(m.PinnedInputs) + len(m.UnpinnedInputs)
	if total > 0 {
		m.ReproScore = len(m.PinnedInputs) * 100 / total
	}
	return m
}

// truncateErr renders a scan error for the job status: credential-redacted at the
// client-facing sink, then bounded (rune-safe).
func truncateErr(err error) string {
	s := credInErr.ReplaceAllString(err.Error(), "$1***@")
	r := []rune(s)
	if len(r) > 300 {
		return string(r[:300]) + "…"
	}
	return string(r)
}
