// Package codequality assembles the code-quality findings for a source tree: it runs the deterministic
// maintainability/reliability rule engine and layers on the metric-derived signals (duplication, and
// complexity when an AST backend is available), mapping everything to first-party finding.Finding values
// (Kind=quality/reliability, ungated, publishable like SAST). No LLM, no persistence – a read-only
// producer the CLI (and, later, the scan pipeline + UI) consume.
package codequality

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rating"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// DefaultComplexityThreshold is the cyclomatic complexity above which a function earns a maintainability
// finding (a widely used "refactor" line). Configurable via WithComplexityThreshold.
const DefaultComplexityThreshold = 15

// Service produces code-quality findings. analyzer is required; dup, metrics and inventory are optional
// enrichers.
type Service struct {
	analyzer          ports.CodeAnalyzer
	dup               ports.DuplicationScanner
	metrics           ports.CodeMetricsProvider
	inventory         ports.CodeInventoryScanner
	bugs              ports.BugDetector
	structural        ports.CodeAnalyzer
	complexityMin     int
	includeTestSmells bool
}

// Option configures a Service.
type Option func(*Service)

// WithDuplication adds duplicated-block maintainability findings.
func WithDuplication(d ports.DuplicationScanner) Option { return func(s *Service) { s.dup = d } }

// WithInventory wires the code-size inventory, enabling Report() to compute ratings + a health summary.
func WithInventory(inv ports.CodeInventoryScanner) Option {
	return func(s *Service) { s.inventory = inv }
}

// WithBugs wires the deeper AST bug detector (unreachable code, constant conditions), emitting its
// findings as Kind=reliability. Requires the synapse-ast sidecar; degrades to nothing without it.
func WithBugs(b ports.BugDetector) Option { return func(s *Service) { s.bugs = b } }

// WithStructuralAnalyzer adds language-aware AST findings. It is optional; an unavailable sidecar returns
// no findings through its adapter.
func WithStructuralAnalyzer(a ports.CodeAnalyzer) Option {
	return func(s *Service) { s.structural = a }
}

// bugCWE maps a deeper-bug rule id to its CWE for the finding.
var bugCWE = map[string]string{
	"reliability-unreachable-code":   "CWE-561", // dead code
	"reliability-constant-condition": "CWE-570", // expression is always false/true
}

// WithTestScopedSmells controls whether info-severity code smells located in test code (src/test,
// *_test.*, *.spec.*, __tests__, testdata, ...) are emitted. They are SUPPRESSED by default: a rule like
// commented-out-code fires heavily in tests and otherwise drowns the higher-value findings (complexity,
// duplication, reliability). Pass true to restore full verbosity. Only Info-severity smells are affected;
// medium/high findings (and every non-test finding) are always kept.
//
// Because the filter lives in the single analyze() chokepoint, it also applies to BuildReport and thus to
// rating.Compute: test-scoped Info smells (5 debt-minutes each) are excluded from the technical-debt total
// and the maintainability grade by default, which is intentional (test TODOs are not production debt).
func WithTestScopedSmells(include bool) Option {
	return func(s *Service) { s.includeTestSmells = include }
}

// WithComplexity adds high-complexity maintainability findings (functions over threshold), using the AST
// metrics provider. threshold <= 0 uses DefaultComplexityThreshold.
func WithComplexity(m ports.CodeMetricsProvider, threshold int) Option {
	return func(s *Service) {
		s.metrics = m
		if threshold > 0 {
			s.complexityMin = threshold
		}
	}
}

// New returns a Service. analyzer is required.
func New(analyzer ports.CodeAnalyzer, opts ...Option) *Service {
	s := &Service{analyzer: analyzer, complexityMin: DefaultComplexityThreshold}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Analyze returns the code-quality findings for root, sorted deterministically by dedup key.
func (s *Service) Analyze(ctx context.Context, root string) ([]finding.Finding, error) {
	findings, _, err := s.analyze(ctx, root)
	return findings, err
}

// analyze runs the rule engine + the metric bridges once, returning the findings AND the duplication
// report it computed (so BuildReport reuses it rather than re-scanning the tree). dupReport is the zero
// value when no duplication scanner is wired.
func (s *Service) analyze(ctx context.Context, root string) ([]finding.Finding, measure.DuplicationReport, error) {
	var out []finding.Finding
	var dupReport measure.DuplicationReport

	raws, err := s.analyzer.Analyze(ctx, root)
	if err != nil {
		return nil, measure.DuplicationReport{}, fmt.Errorf("code analysis: %w", err)
	}
	appendRaws := func(raws []ports.CodeAnalysisRawFinding) error {
		for _, r := range raws {
			if r.Kind != "quality" && r.Kind != "reliability" && r.Kind != "sast" {
				return fmt.Errorf("unknown code-analysis finding kind %q", r.Kind)
			}
			if !s.includeTestSmells && r.Severity == shared.SeverityInfo && isTestPath(r.File) {
				continue // low-value info smell in test code – suppressed by default (see WithTestScopedSmells)
			}
			out = append(out, newFinding(r.Kind, r.RuleID, r.CWE, r.Severity, r.Title, r.Description, r.File, r.Line))
		}
		return nil
	}
	if err := appendRaws(raws); err != nil {
		return nil, measure.DuplicationReport{}, err
	}
	if s.structural != nil {
		structural, serr := s.structural.Analyze(ctx, root)
		if serr != nil {
			return nil, measure.DuplicationReport{}, fmt.Errorf("structural analysis: %w", serr)
		}
		if err := appendRaws(structural); err != nil {
			return nil, measure.DuplicationReport{}, err
		}
	}

	if s.dup != nil {
		rep, derr := s.dup.Duplication(ctx, root)
		if derr != nil {
			return nil, measure.DuplicationReport{}, fmt.Errorf("duplication: %w", derr)
		}
		dupReport = rep
		for _, b := range rep.Blocks {
			if len(b.Occurrences) == 0 {
				continue
			}
			o := b.Occurrences[0] // anchor the finding at the first occurrence
			title := fmt.Sprintf("Duplicated block (%d tokens, %d places)", b.Tokens, len(b.Occurrences))
			desc := "This block is duplicated elsewhere; extract it into a shared function/module to avoid divergent edits."
			out = append(out, newFinding("quality", "quality-duplicated-block", "CWE-1041", shared.SeverityLow, title, desc, o.File, o.StartLine))
		}
	}

	if s.metrics != nil {
		rep, available, merr := s.metrics.Complexity(ctx, root)
		if merr != nil {
			return nil, measure.DuplicationReport{}, fmt.Errorf("complexity: %w", merr)
		}
		if available {
			for _, f := range rep.OverCyclomatic(s.complexityMin) {
				title := fmt.Sprintf("High cyclomatic complexity: %d (%s)", f.Cyclomatic, f.Name)
				desc := fmt.Sprintf("Function %q has cyclomatic complexity %d (cognitive %d), above %d. Break it into smaller units to improve testability and readability.", f.Name, f.Cyclomatic, f.Cognitive, s.complexityMin)
				out = append(out, newFinding("quality", "quality-high-complexity", "CWE-1120", shared.SeverityMedium, title, desc, f.File, f.Line))
			}
		}
	}

	if s.bugs != nil {
		bugs, available, berr := s.bugs.Bugs(ctx, root)
		if berr != nil {
			return nil, measure.DuplicationReport{}, fmt.Errorf("bug detection: %w", berr)
		}
		if available {
			for _, b := range bugs {
				out = append(out, newFinding("reliability", b.Rule, bugCWE[b.Rule], shared.SeverityMedium, b.Message, b.Message, b.File, b.Line))
			}
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].DedupKey < out[j].DedupKey })
	return out, dupReport, nil
}

// newFinding maps a raw code-quality signal to a first-party finding. The DedupKey (<kind>:<rule>:<file>:
// <line>) is the same shape the SARIF exporter's firstPartyLoc parses, so the finding gets a file:line
// physical location automatically. The finding is TRANSIENT (read-only CLI/SARIF producer): EngagementID
// and Audit are intentionally unset; a future scan/store wiring must populate them (as the SCA first-party
// builders do) before persisting.
func newFinding(kind, ruleID, cwe string, sev shared.Severity, title, desc, file string, line int) finding.Finding {
	dedup := kind + ":" + ruleID + ":" + file + ":" + strconv.Itoa(line)
	k := finding.KindQuality
	switch kind {
	case "reliability":
		k = finding.KindReliability
	case "sast":
		k = finding.KindSAST
	}
	return finding.Finding{
		ID:          deterministicID(dedup),
		Title:       fmt.Sprintf("%s (%s:%d)", title, file, line),
		Description: desc,
		Severity:    sev,
		CWE:         cwe,
		Sources:     []string{"synapse-codeanalysis"},
		Class:       finding.ClassFirstParty,
		Status:      finding.StatusOpen,
		Kind:        k,
		RuleKey:     ruleID,
		DedupKey:    dedup,
	}
}

func deterministicID(dedupKey string) shared.ID {
	sum := sha256.Sum256([]byte("codequality|" + dedupKey))
	return shared.ID(hex.EncodeToString(sum[:16]))
}

// isTestPath reports whether a source path is test/spec/fixture code, where info-severity smells
// (commented-out code, TODOs) are low-value noise. Matches common directory and filename conventions
// across ecosystems (Go _test.go, JS/TS .test./.spec., Python test_*, Java src/test + *Test.java, ...).
func isTestPath(p string) bool {
	slash := filepath.ToSlash(p)
	q := strings.ToLower(slash)
	// Directory conventions. Deliberately NOT /testing/ or /spec(s)/ – those are common production
	// package/dir names (test helpers that ship in the binary, OpenAPI/language specs).
	for _, seg := range []string{"/test/", "/tests/", "/__tests__/", "/__mocks__/", "/testdata/", "/fixtures/"} {
		if strings.Contains(q, seg) {
			return true
		}
	}
	if strings.HasPrefix(q, "test/") || strings.HasPrefix(q, "tests/") || strings.HasPrefix(q, "testdata/") {
		return true
	}
	base := q
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if strings.HasPrefix(base, "test_") { // python test_foo.py
		return true
	}
	// Dot/underscore-bounded filename conventions (JS/TS .test./.spec., Python _test./_spec.).
	for _, m := range []string{"_test.", ".test.", "_spec.", ".spec."} {
		if strings.Contains(base, m) {
			return true
		}
	}
	// CamelCase suffix conventions (JUnit/Kotlin/C#/Scala). Matched case-sensitively on the ORIGINAL
	// basename so a capital T distinguishes FooTest.java from production files like Latest.java/Contest.java.
	obase := filepath.Base(slash)
	for _, suf := range []string{"Test.java", "Tests.java", "Test.kt", "Tests.kt", "Test.cs", "Tests.cs", "Spec.scala"} {
		if strings.HasSuffix(obase, suf) {
			return true
		}
	}
	return false
}

// Report is the full code-quality dashboard payload for a source tree: the per-language inventory, the
// findings, the duplication summary, and the rolled-up A-E health ratings + technical debt.
type Report struct {
	Inventory   measure.Inventory         `json:"inventory"`
	Findings    []finding.Finding         `json:"findings"`
	Duplication measure.DuplicationReport `json:"duplication"`
	Rating      rating.Report             `json:"rating"`
}

// BuildReport computes the full dashboard report for root. Findings come from Analyze (which already
// bridges duplication + complexity); the inventory + duplication summary + ratings are added for display.
// Missing optional dependencies degrade to empty sections rather than erroring.
func (s *Service) BuildReport(ctx context.Context, root string) (Report, error) {
	findings, dup, err := s.analyze(ctx, root) // reuse the duplication report Analyze already computed
	if err != nil {
		return Report{}, err
	}
	rep := Report{Findings: findings, Duplication: dup}
	if s.inventory != nil {
		inv, ierr := s.inventory.Inventory(ctx, root)
		if ierr != nil {
			return Report{}, fmt.Errorf("inventory: %w", ierr)
		}
		rep.Inventory = inv
	}
	rep.Rating = rating.Compute(findings, rep.Inventory.Totals().CodeLines)
	return rep, nil
}
