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
	"sort"
	"strconv"

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
	analyzer      ports.CodeAnalyzer
	dup           ports.DuplicationScanner
	metrics       ports.CodeMetricsProvider
	inventory     ports.CodeInventoryScanner
	complexityMin int
}

// Option configures a Service.
type Option func(*Service)

// WithDuplication adds duplicated-block maintainability findings.
func WithDuplication(d ports.DuplicationScanner) Option { return func(s *Service) { s.dup = d } }

// WithInventory wires the code-size inventory, enabling Report() to compute ratings + a health summary.
func WithInventory(inv ports.CodeInventoryScanner) Option {
	return func(s *Service) { s.inventory = inv }
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
	for _, r := range raws {
		out = append(out, newFinding(r.Kind, r.RuleID, r.CWE, r.Severity, r.Title, r.Description, r.File, r.Line))
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
	if kind == "reliability" {
		k = finding.KindReliability
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
		DedupKey:    dedup,
	}
}

func deterministicID(dedupKey string) shared.ID {
	sum := sha256.Sum256([]byte("codequality|" + dedupKey))
	return shared.ID(hex.EncodeToString(sum[:16]))
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
