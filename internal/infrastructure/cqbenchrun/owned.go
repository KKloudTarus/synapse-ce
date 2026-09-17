// Package cqbenchrun runs the shipped owned code-quality engine over the cqbench corpus and reduces its
// findings into the engine-agnostic scorecard observations the cqbench reducer consumes. It lives in
// infrastructure because it wires the concrete analyzers (the deterministic rule engine, duplication, and the
// optional synapse-ast sidecar) exactly as the `synapse-cli code-quality` command does, so the benchmark
// measures the same engine the product ships rather than a bespoke test harness.
package cqbenchrun

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ast"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/codeanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/duplication"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/sast"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/codequality"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/cqbench"
)

// OwnedEngine is the identifier the owned code-quality engine records under in a scorecard report.
const OwnedEngine = "synapse-owned"

// RunOwned runs the owned code-quality engine over every corpus case's fixture (rooted at fixturesDir) and
// returns one observation per case, plus a tally of findings that could not be scored (for transparency, so a
// low recall is never quietly a mapping bug). It wires the same engine `synapse-cli code-quality` ships: the
// deterministic rule analyzer plus duplication, and, when the synapse-ast sidecar is present
// (SYNAPSE_AST_BIN), the complexity and AST bug/structural detectors. Without the sidecar those degrade to
// nothing, so a corpus case that depends on AST-only detections is measured as a miss rather than an error.
//
// The finding->issue-type mapping goes through the rule catalog: a finding is scored under the
// SonarQube-compatible rule.Type the catalog assigns its rule key. A finding with no rule key, a key absent
// from the catalog, or (defensively) an unmappable type is skipped and counted, never silently dropped.
func RunOwned(ctx context.Context, corpus cqbench.Corpus, fixturesDir string) ([]cqbench.CaseObservation, map[string]int, error) {
	types, err := ruleTypeIndex(ctx)
	if err != nil {
		return nil, nil, err
	}
	astProvider := ast.New(os.Getenv("SYNAPSE_AST_BIN"))
	svc := codequality.New(
		codeanalysis.New(),
		codequality.WithDuplication(duplication.New(0)),
		codequality.WithComplexity(astProvider, 0),
		codequality.WithBugs(astProvider),
		codequality.WithStructuralAnalyzer(astProvider),
	)
	sastEngine := sast.New() // pattern SAST adds the vulnerability/security_hotspot axis the head-to-head needs
	skipped := map[string]int{}
	out := make([]cqbench.CaseObservation, 0, len(corpus.Cases))
	for _, c := range corpus.Cases {
		root := filepath.Join(fixturesDir, filepath.FromSlash(c.Fixture))
		findings, analyzeErr := svc.Analyze(ctx, root)
		if analyzeErr != nil {
			return nil, nil, fmt.Errorf("owned analyze %q: %w", c.Name, analyzeErr)
		}
		sastFindings, sastErr := sastEngine.AnalyzeSource(ctx, root)
		if sastErr != nil {
			return nil, nil, fmt.Errorf("owned sast %q: %w", c.Name, sastErr)
		}
		issues := make([]cqbench.Issue, 0, len(findings)+len(sastFindings))
		for _, f := range findings {
			it, ok := mapIssueType(types, f, skipped)
			if !ok {
				continue
			}
			if f.SourceLocation == nil {
				skipped["no_location"]++
				continue
			}
			issues = append(issues, cqbench.Issue{File: normalizeFile(root, f.SourceLocation.File), Line: f.SourceLocation.StartLine, Type: it})
		}
		for _, sf := range sastFindings {
			it, ok := sastIssueType(sf.RuleType)
			if !ok {
				skipped["unmappable_sast_type"]++
				continue
			}
			issues = append(issues, cqbench.Issue{File: normalizeFile(root, sf.File), Line: sf.Line, Type: it})
		}
		out = append(out, cqbench.CaseObservation{Case: c.Name, Issues: dedupIssues(issues)})
	}
	return out, skipped, nil
}

// sastIssueType maps a pattern-SAST raw finding's RuleType to a scorecard type. An empty RuleType is a
// security vulnerability, per the ports.SASTRawFinding contract.
func sastIssueType(ruleType string) (cqbench.IssueType, bool) {
	if strings.TrimSpace(ruleType) == "" {
		return cqbench.TypeVulnerability, true
	}
	switch t := cqbench.IssueType(ruleType); t {
	case cqbench.TypeBug, cqbench.TypeVulnerability, cqbench.TypeCodeSmell, cqbench.TypeSecurityHotspot:
		return t, true
	default:
		return "", false
	}
}

// dedupIssues collapses issues sharing an exact (file, line, type) so an engine that reports the same defect
// through two detectors (e.g. the AST structural analyzer and the pattern SAST engine) is not charged a false
// positive for the duplicate. Order is preserved for deterministic output.
func dedupIssues(issues []cqbench.Issue) []cqbench.Issue {
	seen := make(map[cqbench.Issue]struct{}, len(issues))
	out := issues[:0]
	for _, iss := range issues {
		if _, dup := seen[iss]; dup {
			continue
		}
		seen[iss] = struct{}{}
		out = append(out, iss)
	}
	return out
}

// ruleTypeIndex builds the rule-key -> SonarQube-compatible type map from the shipped rule catalog.
func ruleTypeIndex(ctx context.Context) (map[string]rule.Type, error) {
	cat, err := rulecatalog.Default()
	if err != nil {
		return nil, fmt.Errorf("load rule catalog: %w", err)
	}
	rules, err := cat.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list rule catalog: %w", err)
	}
	index := make(map[string]rule.Type, len(rules))
	for _, r := range rules {
		index[string(r.Key)] = r.Type
	}
	return index, nil
}

// mapIssueType resolves a finding to its scorecard issue type through the catalog, recording a skip reason
// when it cannot. rule.Type shares the exact string values cqbench.IssueType uses, so the bridge is a direct
// cast once the type is known valid.
func mapIssueType(types map[string]rule.Type, f finding.Finding, skipped map[string]int) (cqbench.IssueType, bool) {
	if strings.TrimSpace(f.RuleKey) == "" {
		skipped["empty_rule_key"]++
		return "", false
	}
	t, ok := types[f.RuleKey]
	if !ok {
		skipped["unknown_rule_key"]++
		return "", false
	}
	if !t.Valid() {
		skipped["unmappable_type"]++
		return "", false
	}
	return cqbench.IssueType(t), true
}

// normalizeFile turns a finding's reported path into the fixture-relative, forward-slash form the corpus
// labels use. The analyzer reports paths relative to the root it was given, but tolerate an absolute or
// root-prefixed path by trimming the root.
func normalizeFile(root, file string) string {
	file = filepath.ToSlash(file)
	if rel, err := filepath.Rel(root, filepath.FromSlash(file)); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return strings.TrimPrefix(file, "./")
}
