// Command synapse-cli runs Synapse's own SCA pipeline from the command line.
// Its primary use is dogfooding: scan Synapse's own dependencies in CI
// and fail the build on findings at or above a severity threshold.
//
// It runs the SAME engagement-gated Scan path the API uses: an ephemeral
// in-memory engagement covering the target path is created so scope enforcement
// is exercised, not bypassed. Nothing is persisted.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rating"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/acquire"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/cache/sbomcache"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ast"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/bincat"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/codeanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/codeinventory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/coverage"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/duplication"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/enry"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/gitdiff"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/gomodgraph"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/gradleresolve"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/grype"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ignorefile"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jarchecksum"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jarhash"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jarlicense"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jvmreach"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/license"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/licensefile"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/licensemeta"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/manifest"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/mavencoord"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/mavenresolve"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/misconfig"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/nvd"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ospkg"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/osv"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownadvisory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/qualityprofile"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/risk"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/sast"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/secretscan"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/syft"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/vexfile"
	"github.com/KKloudTarus/synapse-ce/internal/platform/buildinfo"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/advisoryingest"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/codequality"
	exportuc "github.com/KKloudTarus/synapse-ce/internal/usecase/export"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "scan":
		runScan()
	case "sync-advisories":
		if len(os.Args) < 3 {
			usage() // missing <dir> exits 2, consistent with scan's missing-path
		}
		if err := syncAdvisories(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "synapse-cli:", err)
			os.Exit(1)
		}
	case "inventory":
		if len(os.Args) < 3 {
			usage() // missing <dir> exits 2
		}
		if err := runInventory(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "synapse-cli:", err)
			os.Exit(1)
		}
	case "metrics":
		if len(os.Args) < 3 {
			usage()
		}
		if err := runMetrics(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "synapse-cli:", err)
			os.Exit(1)
		}
	case "duplication":
		if len(os.Args) < 3 {
			usage()
		}
		if err := runDuplication(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "synapse-cli:", err)
			os.Exit(1)
		}
	case "quality":
		if len(os.Args) < 3 {
			usage()
		}
		if err := runQuality(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "synapse-cli:", err)
			os.Exit(1)
		}
	case "rating":
		if len(os.Args) < 3 {
			usage()
		}
		if err := runRating(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "synapse-cli:", err)
			os.Exit(1)
		}
	case "gate":
		if len(os.Args) < 3 {
			usage()
		}
		if err := runGate(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "synapse-cli:", err)
			os.Exit(1)
		}
	case "coverage":
		if len(os.Args) < 3 {
			usage()
		}
		if err := runCoverage(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "synapse-cli:", err)
			os.Exit(1)
		}
	default:
		usage()
	}
}

// runInventory prints a per-language code-size inventory for a local source tree (the Phase-0
// code-quality surface). Pure-Go, read-only; no engagement/DB needed.
func runInventory(dir string) error {
	// Wire the synapse-ast sidecar so non-Go languages get accurate function counts too. If the binary is
	// absent or built without the tree-sitter backend, the provider reports unavailable and the inventory
	// falls back to Go-only function counts – no error.
	astBin := os.Getenv("SYNAPSE_AST_BIN") // else "synapse-ast" in PATH
	inv, err := codeinventory.New(codeinventory.WithASTProvider(ast.New(astBin))).Inventory(context.Background(), dir)
	if err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	fmt.Printf("\nSynapse code inventory – %s\n", dir)
	if len(inv.Languages) == 0 {
		fmt.Println("  (no source files detected)")
		return nil
	}
	fmt.Printf("  %-16s %8s %10s %10s %8s %10s\n", "language", "files", "code", "comment", "blank", "functions")
	printInvRow := func(li measure.LanguageInventory) {
		fn := "n/a"
		if li.FunctionsKnown {
			fn = strconv.Itoa(li.Functions)
		}
		fmt.Printf("  %-16s %8d %10d %10d %8d %10s\n", li.Language, li.Files, li.CodeLines, li.CommentLines, li.BlankLines, fn)
	}
	for _, li := range inv.Languages {
		printInvRow(li)
	}
	printInvRow(inv.Totals())
	fmt.Println("  functions: Go counted in-process; Java/JavaScript/Python via the synapse-ast sidecar")
	fmt.Println("             (set SYNAPSE_AST_BIN, or have `synapse-ast` on PATH); other languages show n/a")
	return nil
}

// runMetrics prints per-function complexity (cyclomatic + cognitive) hotspots for a local source tree and
// optionally gates on cyclomatic complexity. Backed by the synapse-ast sidecar; if it is absent or built
// without the tree-sitter backend, this reports that and (for the gate) does not fail.
func runMetrics(args []string) error {
	dir := args[0]
	failOn := 0 // 0 = no gate
	top := 10
	for i := 1; i < len(args); i++ {
		switch {
		case args[i] == "--fail-on-complexity" && i+1 < len(args):
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 1 {
				return fmt.Errorf("--fail-on-complexity wants a positive integer, got %q", args[i+1])
			}
			failOn = n
			i++
		case args[i] == "--top" && i+1 < len(args):
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 0 {
				return fmt.Errorf("--top wants a non-negative integer, got %q", args[i+1])
			}
			top = n
			i++
		default:
			return fmt.Errorf("unknown or incomplete option %q", args[i])
		}
	}

	astBin := os.Getenv("SYNAPSE_AST_BIN")
	report, available, err := ast.New(astBin).Complexity(context.Background(), dir)
	if err != nil {
		return fmt.Errorf("metrics: %w", err)
	}
	fmt.Printf("\nSynapse code complexity – %s\n", dir)
	if !available {
		fmt.Println("  the synapse-ast sidecar is unavailable (build it with cgo, or set SYNAPSE_AST_BIN); no complexity computed")
		return nil
	}
	if len(report.Functions) == 0 {
		fmt.Println("  (no functions detected in supported languages)")
		return nil
	}
	if report.Truncated {
		fmt.Println("  ! result truncated at the file cap; counts are a lower bound")
	}
	fmt.Printf("  functions: %d · highest cyclomatic: %d\n", len(report.Functions), report.MaxCyclomatic())
	fmt.Printf("  top %d by cyclomatic complexity:\n", top)
	fmt.Printf("    %-4s %-4s  %-10s %s\n", "cyc", "cog", "language", "function (file:line)")
	for _, f := range report.TopByCyclomatic(top) {
		fmt.Printf("    %-4d %-4d  %-10s %s (%s:%d)\n", f.Cyclomatic, f.Cognitive, f.Language, f.Name, f.File, f.Line)
	}
	if failOn > 0 {
		over := report.OverCyclomatic(failOn)
		if len(over) > 0 {
			return fmt.Errorf("%d function(s) exceed cyclomatic complexity %d (highest %d)", len(over), failOn, report.MaxCyclomatic())
		}
	}
	return nil
}

// runDuplication prints a copy-paste (clone) report for a local source tree and optionally gates on the
// duplicated-lines density. Pure-Go, read-only; no DB, no sidecar.
func runDuplication(args []string) error {
	dir := args[0]
	if strings.HasPrefix(dir, "-") {
		return fmt.Errorf("first argument must be a path, got option %q", dir)
	}
	minTokens := duplication.DefaultMinTokens
	failOnPct := -1.0 // <0 = no gate
	top := 10
	for i := 1; i < len(args); i++ {
		switch {
		case args[i] == "--min-tokens" && i+1 < len(args):
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 1 {
				return fmt.Errorf("--min-tokens wants a positive integer, got %q", args[i+1])
			}
			minTokens = n
			i++
		case args[i] == "--fail-on-duplication" && i+1 < len(args):
			p, err := strconv.ParseFloat(args[i+1], 64)
			if err != nil || p < 0 {
				return fmt.Errorf("--fail-on-duplication wants a non-negative percentage, got %q", args[i+1])
			}
			failOnPct = p
			i++
		case args[i] == "--top" && i+1 < len(args):
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 0 {
				return fmt.Errorf("--top wants a non-negative integer, got %q", args[i+1])
			}
			top = n
			i++
		default:
			return fmt.Errorf("unknown or incomplete option %q", args[i])
		}
	}

	report, err := duplication.New(minTokens).Duplication(context.Background(), dir)
	if err != nil {
		return fmt.Errorf("duplication: %w", err)
	}
	fmt.Printf("\nSynapse code duplication – %s\n", dir)
	if report.Truncated {
		fmt.Println("  ! result truncated at the file cap; metrics are a lower bound")
	}
	fmt.Printf("  duplicated blocks: %d · duplicated lines: %d / %d code lines · density: %.1f%% · files: %d (min-tokens %d)\n",
		len(report.Blocks), report.DuplicatedLines, report.TotalLines, report.Density(), report.Files, minTokens)
	if len(report.Blocks) > 0 {
		fmt.Printf("  top %d duplicated blocks:\n", top)
		for _, b := range report.TopBlocks(top) {
			fmt.Printf("    %d tokens, %d places:\n", b.Tokens, len(b.Occurrences))
			for _, o := range b.Occurrences {
				fmt.Printf("      %s:%d-%d\n", o.File, o.StartLine, o.EndLine)
			}
		}
	}
	if failOnPct >= 0 && report.Density() > failOnPct {
		return fmt.Errorf("duplicated-lines density %.1f%% exceeds %.1f%%", report.Density(), failOnPct)
	}
	return nil
}

// runQuality runs the maintainability + reliability rules (plus duplication and, when the synapse-ast
// sidecar is available, high-complexity) over a local source tree and reports the findings, optionally
// emitting SARIF or gating on severity.
func runQuality(args []string) error {
	dir := args[0]
	if strings.HasPrefix(dir, "-") {
		return fmt.Errorf("first argument must be a path, got option %q", dir)
	}
	failOn := ""
	sarifOut := false
	complexityMin := codequality.DefaultComplexityThreshold
	for i := 1; i < len(args); i++ {
		switch {
		case args[i] == "--fail-on" && i+1 < len(args):
			failOn = args[i+1]
			i++
		case args[i] == "--min-complexity" && i+1 < len(args):
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 1 {
				return fmt.Errorf("--min-complexity wants a positive integer, got %q", args[i+1])
			}
			complexityMin = n
			i++
		case args[i] == "--sarif":
			sarifOut = true
		default:
			return fmt.Errorf("unknown or incomplete option %q", args[i])
		}
	}
	if failOn != "" {
		switch shared.Severity(failOn) {
		case "critical", "high", "medium", "low", "info":
		default:
			return fmt.Errorf("invalid --fail-on %q (want critical|high|medium|low|info)", failOn)
		}
	}

	svc := codequality.New(
		codeanalysis.New(),
		codequality.WithDuplication(duplication.New(0)),
		codequality.WithComplexity(ast.New(os.Getenv("SYNAPSE_AST_BIN")), complexityMin),
		codequality.WithBugs(ast.New(os.Getenv("SYNAPSE_AST_BIN"))),
	)
	findings, err := svc.Analyze(context.Background(), dir)
	if err != nil {
		return fmt.Errorf("quality: %w", err)
	}

	if sarifOut {
		out, merr := exportuc.MarshalSARIF(findings, buildinfo.App(), exportuc.SARIFOptions{})
		if merr != nil {
			return fmt.Errorf("encode sarif: %w", merr)
		}
		if _, werr := os.Stdout.Write(append(out, '\n')); werr != nil {
			return fmt.Errorf("write sarif: %w", werr)
		}
	} else {
		fmt.Printf("\nSynapse code quality – %s\n", dir)
		byKind := map[finding.Kind]int{}
		for _, f := range findings {
			byKind[f.Kind]++
		}
		fmt.Printf("  findings: %d (quality: %d, reliability: %d)\n", len(findings), byKind[finding.KindQuality], byKind[finding.KindReliability])
		for _, f := range findings {
			fmt.Printf("    [%-8s %-11s] %s\n", f.Severity, f.Kind, f.Title)
		}
	}

	if failOn != "" {
		gate := shared.SeverityRank(shared.Severity(failOn))
		over := 0
		for _, f := range findings {
			if shared.SeverityRank(f.Severity) >= gate {
				over++
			}
		}
		if over > 0 {
			return fmt.Errorf("%d code-quality finding(s) at or above %s", over, failOn)
		}
	}
	return nil
}

// runRating computes the deterministic A-E health grades (security / reliability / maintainability) and
// the technical-debt estimate for a local source tree, from the code-quality findings + first-party SAST
// + the code-size inventory. Read-only, no DB.
func runRating(args []string) error {
	dir := args[0]
	if strings.HasPrefix(dir, "-") {
		return fmt.Errorf("first argument must be a path, got option %q", dir)
	}
	jsonOut := false
	failBelow := ""
	for i := 1; i < len(args); i++ {
		switch {
		case args[i] == "--json":
			jsonOut = true
		case args[i] == "--fail-below" && i+1 < len(args):
			failBelow = strings.ToUpper(args[i+1])
			i++
		default:
			return fmt.Errorf("unknown or incomplete option %q", args[i])
		}
	}
	ctx := context.Background()

	inv, err := codeinventory.New().Inventory(ctx, dir)
	if err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	loc := inv.Totals().CodeLines

	svc := codequality.New(
		codeanalysis.New(),
		codequality.WithDuplication(duplication.New(0)),
		codequality.WithComplexity(ast.New(os.Getenv("SYNAPSE_AST_BIN")), codequality.DefaultComplexityThreshold),
		codequality.WithBugs(ast.New(os.Getenv("SYNAPSE_AST_BIN"))),
	)
	findings, err := svc.Analyze(ctx, dir)
	if err != nil {
		return fmt.Errorf("code quality: %w", err)
	}
	// First-party security signal for the security grade (SCA dep vulns fold in when rating runs over a
	// full scan's findings; this standalone command uses the SAST analyzer).
	sastRaws, err := sast.New().AnalyzeSource(ctx, dir)
	if err != nil {
		return fmt.Errorf("sast: %w", err)
	}
	for _, sr := range sastRaws {
		findings = append(findings, finding.Finding{Kind: finding.KindSAST, Severity: sr.Severity})
	}

	rep := rating.Compute(findings, loc)

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return fmt.Errorf("encode json: %w", err)
		}
	} else {
		fmt.Printf("\nSynapse code health – %s\n", dir)
		fmt.Printf("  security:        %s\n", rep.Security)
		fmt.Printf("  reliability:     %s\n", rep.Reliability)
		fmt.Printf("  maintainability: %s\n", rep.Maintainability)
		fmt.Printf("  technical debt:  %dh %dm (ratio %.1f%% of ~%d code lines)\n", rep.TechDebtMinutes/60, rep.TechDebtMinutes%60, rep.DebtRatioPct, rep.LinesOfCode)
	}

	if failBelow != "" {
		order := map[string]int{"A": 1, "B": 2, "C": 3, "D": 4, "E": 5}
		threshold, ok := order[failBelow]
		if !ok {
			return fmt.Errorf("--fail-below wants a grade A-E, got %q", failBelow)
		}
		worst := 0
		for _, g := range []rating.Grade{rep.Security, rep.Reliability, rep.Maintainability} {
			if order[string(g)] > worst {
				worst = order[string(g)]
			}
		}
		if worst > threshold {
			return fmt.Errorf("a health grade is below %s (security %s, reliability %s, maintainability %s)", failBelow, rep.Security, rep.Reliability, rep.Maintainability)
		}
	}
	return nil
}

// runGate is the unified Clean-as-You-Code quality gate: it gathers the code-quality + first-party
// security findings, applies the rule profile (.synapse-rules.yaml), optionally scopes to new/changed
// code (git diff vs a base ref), builds the metric snapshot (+ ratings + duplication density), and
// evaluates the quality gate (.synapse-gate.yaml or the built-in default). Exits non-zero when the gate
// fails, printing the exact conditions that failed.
func runGate(args []string) error {
	dir := args[0]
	if strings.HasPrefix(dir, "-") {
		return fmt.Errorf("first argument must be a path, got option %q", dir)
	}
	newCodeOnly := false
	base := "origin/main"
	gatePath := filepath.Join(dir, ".synapse-gate.yaml")
	rulesPath := filepath.Join(dir, ".synapse-rules.yaml")
	covPath := ""
	markdown := false
	for i := 1; i < len(args); i++ {
		switch {
		case args[i] == "--new-code-only":
			newCodeOnly = true
		case args[i] == "--base" && i+1 < len(args):
			base = args[i+1]
			i++
		case args[i] == "--gate" && i+1 < len(args):
			gatePath = args[i+1]
			i++
		case args[i] == "--rules" && i+1 < len(args):
			rulesPath = args[i+1]
			i++
		case args[i] == "--coverage" && i+1 < len(args):
			covPath = args[i+1]
			i++
		case args[i] == "--format" && i+1 < len(args):
			if args[i+1] != "markdown" && args[i+1] != "text" {
				return fmt.Errorf("--format wants text|markdown, got %q", args[i+1])
			}
			markdown = args[i+1] == "markdown"
			i++
		default:
			return fmt.Errorf("unknown or incomplete option %q", args[i])
		}
	}
	ctx := context.Background()

	// 1. Gather findings: code quality (quality+reliability, + duplication/complexity bridges) + SAST.
	svc := codequality.New(
		codeanalysis.New(),
		codequality.WithDuplication(duplication.New(0)),
		codequality.WithComplexity(ast.New(os.Getenv("SYNAPSE_AST_BIN")), codequality.DefaultComplexityThreshold),
		codequality.WithBugs(ast.New(os.Getenv("SYNAPSE_AST_BIN"))),
	)
	findings, err := svc.Analyze(ctx, dir)
	if err != nil {
		return fmt.Errorf("code quality: %w", err)
	}
	sastRaws, err := sast.New().AnalyzeSource(ctx, dir)
	if err != nil {
		return fmt.Errorf("sast: %w", err)
	}
	for _, sr := range sastRaws {
		findings = append(findings, finding.Finding{
			Kind:     finding.KindSAST,
			Severity: sr.Severity,
			DedupKey: "sast:" + sr.RuleID + ":" + sr.File + ":" + strconv.Itoa(sr.Line),
		})
	}

	// 2. Apply the rule profile (enable/disable + severity override).
	profile, _, err := qualityprofile.LoadProfile(rulesPath)
	if err != nil {
		return fmt.Errorf("load rules profile: %w", err)
	}
	findings = profile.Apply(findings)

	// 3. Scope to new/changed code if requested (Clean as You Code): the gate then judges only what this
	// change introduced. Ratings are computed over the SAME scope, so "reliability_rating A" means "no
	// reliability issue in new code", the adoption-friendly semantic.
	scoped := findings
	var changed gitdiff.ChangedLines
	if newCodeOnly {
		var derr error
		changed, derr = gitdiff.Changed(ctx, dir, base)
		if derr != nil {
			return fmt.Errorf("new-code diff: %w", derr)
		}
		scoped = filterNewCode(findings, changed)
	}

	// 4. Ratings over the scope (security/reliability are worst-severity, so correctly new-code-scoped;
	// maintainability's debt ratio still divides by whole-repo LOC) + whole-codebase duplication density.
	inv, err := codeinventory.New().Inventory(ctx, dir)
	if err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	rep := rating.Compute(scoped, inv.Totals().CodeLines)
	dupRep, err := duplication.New(0).Duplication(ctx, dir)
	if err != nil {
		return fmt.Errorf("duplication: %w", err)
	}

	// 5. Coverage (optional): overall line coverage, or coverage on new code when scoping to a diff.
	coverageMeasured := false
	var snapCoverage float64
	if covPath != "" {
		covRep, lc, cerr := coverage.Parse(covPath)
		if cerr != nil {
			return fmt.Errorf("coverage: %w", cerr)
		}
		if newCodeOnly && changed != nil {
			if pct, ok := lc.NewCodePercent(changed); ok {
				snapCoverage = pct
				coverageMeasured = true
			} else {
				// No changed line matched the report (paths differ, or the diff touched no measurable
				// line). Note it so an operator is not misled by a silently-absent coverage condition.
				fmt.Fprintln(os.Stderr, "synapse-cli: note: coverage report matched no changed line (check its paths are repo-relative); coverage condition skipped")
			}
		} else {
			snapCoverage = covRep.Percent()
			coverageMeasured = true
		}
	}

	// 6. Build the snapshot + evaluate the gate.
	snap := buildSnapshot(scoped, rep, dupRep.Density())
	if coverageMeasured {
		snap[qualitygate.MetricCoveragePct] = snapCoverage
	}
	gate, found, err := qualityprofile.LoadGate(gatePath)
	if err != nil {
		return fmt.Errorf("load gate: %w", err)
	}
	if !found {
		gate = qualitygate.Default()
	}
	result := qualitygate.Evaluate(gate, snap)

	scopeLabel := "whole codebase"
	if newCodeOnly {
		scopeLabel = "new code vs " + base
	}
	covLabel := "n/a"
	if coverageMeasured {
		covLabel = fmt.Sprintf("%.1f%%", snapCoverage)
	}
	if markdown {
		printGateMarkdown(dir, scopeLabel, rep, dupRep.Density(), covLabel, result)
	} else {
		fmt.Printf("\nSynapse quality gate – %s (%s)\n", dir, scopeLabel)
		fmt.Printf("  ratings: security %s · reliability %s · maintainability %s · duplication %.1f%% · coverage %s\n", rep.Security, rep.Reliability, rep.Maintainability, dupRep.Density(), covLabel)
		for _, cr := range result.Results {
			mark := "PASS"
			if !cr.Passed {
				mark = "FAIL"
			}
			fmt.Printf("  [%s] %s (actual %g)\n", mark, cr.Condition, cr.Actual)
		}
	}
	if !result.Passed {
		return fmt.Errorf("quality gate FAILED: %d condition(s) not met", len(result.Failures()))
	}
	if !markdown {
		fmt.Println("  quality gate PASSED")
	}
	return nil
}

// runCoverage parses a coverage report (lcov / cobertura / jacoco, auto-detected) and prints the overall
// line coverage + the least-covered files, optionally gating on a minimum percentage.
func runCoverage(args []string) error {
	path := args[0]
	if strings.HasPrefix(path, "-") {
		return fmt.Errorf("first argument must be a report file, got option %q", path)
	}
	failBelow := -1.0
	top := 10
	for i := 1; i < len(args); i++ {
		switch {
		case args[i] == "--fail-below" && i+1 < len(args):
			p, err := strconv.ParseFloat(args[i+1], 64)
			if err != nil || p < 0 || p > 100 {
				return fmt.Errorf("--fail-below wants a percentage 0-100, got %q", args[i+1])
			}
			failBelow = p
			i++
		case args[i] == "--top" && i+1 < len(args):
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 0 {
				return fmt.Errorf("--top wants a non-negative integer, got %q", args[i+1])
			}
			top = n
			i++
		default:
			return fmt.Errorf("unknown or incomplete option %q", args[i])
		}
	}
	rep, _, err := coverage.Parse(path)
	if err != nil {
		return fmt.Errorf("coverage: %w", err)
	}
	fmt.Printf("\nSynapse coverage – %s\n", path)
	fmt.Printf("  line coverage: %.1f%% (%d/%d lines, %d files)\n", rep.Percent(), rep.CoveredLines, rep.TotalLines, len(rep.Files))
	least := rep.LeastCovered(top)
	if len(least) > 0 {
		fmt.Printf("  least covered:\n")
		for _, f := range least {
			fmt.Printf("    %6.1f%%  %s (%d/%d)\n", f.Percent(), f.File, f.CoveredLines, f.TotalLines)
		}
	}
	if failBelow >= 0 && rep.Percent() < failBelow {
		return fmt.Errorf("line coverage %.1f%% is below %.1f%%", rep.Percent(), failBelow)
	}
	return nil
}

// printGateMarkdown renders the gate result as a Markdown summary suitable for a PR comment (gh pr comment
// --body-file). Failed conditions are listed first so a reviewer sees the blockers immediately.
func printGateMarkdown(dir, scope string, rep rating.Report, dupDensity float64, coverage string, result qualitygate.Result) {
	status := "✅ **Quality gate passed**"
	if !result.Passed {
		status = "❌ **Quality gate failed**"
	}
	fmt.Printf("## Synapse quality gate\n\n%s _(%s)_\n\n", status, scope)
	fmt.Printf("| Rating | Grade |\n|---|---|\n| Security | %s |\n| Reliability | %s |\n| Maintainability | %s |\n", rep.Security, rep.Reliability, rep.Maintainability)
	fmt.Printf("\nDuplication %.1f%% · Coverage %s\n\n", dupDensity, coverage)
	fmt.Printf("| Condition | Actual | |\n|---|---|---|\n")
	for _, cr := range result.Results {
		mark := "✅"
		if !cr.Passed {
			mark = "❌"
		}
		fmt.Printf("| `%s` | %g | %s |\n", cr.Condition, cr.Actual, mark)
	}
}

// filterNewCode keeps only line-anchored findings that sit on a changed line.
func filterNewCode(findings []finding.Finding, changed gitdiff.ChangedLines) []finding.Finding {
	var out []finding.Finding
	for _, f := range findings {
		file, line, ok := qualitygate.FileLineOf(f.DedupKey)
		if !ok {
			continue // not line-anchored (e.g. SCA): not attributable to a changed line
		}
		if changed.Has(file, line) {
			out = append(out, f)
		}
	}
	return out
}

// buildSnapshot turns the scoped findings + ratings + duplication into gate metrics.
func buildSnapshot(scoped []finding.Finding, rep rating.Report, dupDensity float64) qualitygate.Snapshot {
	s := qualitygate.Snapshot{}
	securityKind := map[finding.Kind]bool{
		finding.KindSCA: true, finding.KindSAST: true, finding.KindSecret: true,
		finding.KindMisconfig: true, finding.KindExploitation: true, finding.KindDAST: true,
	}
	for _, f := range scoped {
		s[qualitygate.MetricNewIssues]++
		switch f.Severity {
		case shared.SeverityCritical:
			s[qualitygate.MetricNewCritical]++
		case shared.SeverityHigh:
			s[qualitygate.MetricNewHigh]++
		case shared.SeverityMedium:
			s[qualitygate.MetricNewMedium]++
		}
		if f.Kind == finding.KindSecret {
			s[qualitygate.MetricNewSecret]++
		}
		if securityKind[f.Kind] {
			s[qualitygate.MetricNewVulnerability]++
		}
	}
	s[qualitygate.MetricDuplicationPct] = dupDensity
	s[qualitygate.MetricSecurityRating] = gradeNum(rep.Security)
	s[qualitygate.MetricReliability] = gradeNum(rep.Reliability)
	s[qualitygate.MetricMaintainability] = gradeNum(rep.Maintainability)
	return s
}

func gradeNum(g rating.Grade) float64 {
	switch g {
	case rating.GradeA:
		return 1
	case rating.GradeB:
		return 2
	case rating.GradeC:
		return 3
	case rating.GradeD:
		return 4
	case rating.GradeE:
		return 5
	}
	return 0
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  synapse-cli scan <path|image-ref> [--image] [--offline] [--json] [--sarif] [--mode full|vulnerabilities|licenses] [--fail-on critical|high|medium|low|info] [--ignore-unfixed] [--detection-priority comprehensive|precise]")
	fmt.Fprintln(os.Stderr, "      --sarif    write a SARIF 2.1.0 report to stdout (for GitHub code-scanning upload); --fail-on still sets the exit code")
	fmt.Fprintln(os.Stderr, "      --image    treat the argument as a container image reference (pulled via crane) instead of a local path")
	fmt.Fprintln(os.Stderr, "      --offline  skip the live OSV.dev source; detect with Grype's offline DB only (air-gapped / fast)")
	fmt.Fprintln(os.Stderr, "  synapse-cli inventory <path>             # per-language code-size inventory (files, code/comment/blank lines, functions) – no DB")
	fmt.Fprintln(os.Stderr, "  synapse-cli metrics <path> [--fail-on-complexity N] [--top N]  # per-function cyclomatic+cognitive complexity (needs the synapse-ast sidecar)")
	fmt.Fprintln(os.Stderr, "  synapse-cli duplication <path> [--min-tokens N] [--fail-on-duplication PCT] [--top N]  # copy-paste detection (blocks, lines, density) – no DB")
	fmt.Fprintln(os.Stderr, "  synapse-cli quality <path> [--fail-on SEV] [--min-complexity N] [--sarif]  # maintainability + reliability findings (+ duplication, + complexity via synapse-ast) – no DB")
	fmt.Fprintln(os.Stderr, "  synapse-cli rating <path> [--json] [--fail-below GRADE]  # A-E health grades (security/reliability/maintainability) + technical debt – no DB")
	fmt.Fprintln(os.Stderr, "  synapse-cli gate <path> [--new-code-only] [--base REF] [--gate FILE] [--rules FILE] [--coverage FILE] [--format text|markdown]  # Clean-as-You-Code quality gate")
	fmt.Fprintln(os.Stderr, "  synapse-cli coverage <lcov|cobertura|jacoco file> [--fail-below PCT] [--top N]  # parse a coverage report (auto-detected)")
	fmt.Fprintln(os.Stderr, "  synapse-cli sync-advisories <dir>        # ingest a local OSV dump into the owned advisory store (requires SYNAPSE_DB_DSN)")
	fmt.Fprintln(os.Stderr, "  synapse-cli sync-advisories --remote     # fetch + ingest app ecosystems from the OSV bulk bucket (requires SYNAPSE_DB_DSN)")
	fmt.Fprintln(os.Stderr, "  synapse-cli sync-advisories --remote-distros # fetch + ingest OS-package advisories (Debian/Alpine) from OSV (large; requires SYNAPSE_DB_DSN)")
	fmt.Fprintln(os.Stderr, "  synapse-cli sync-advisories --csaf <dir> # ingest a local CSAF 2.0 advisory dump (requires SYNAPSE_DB_DSN)")
	fmt.Fprintln(os.Stderr, "  synapse-cli sync-advisories --oval <dir> # ingest a local Ubuntu OVAL dump (com.ubuntu.*.cve.oval.xml[.bz2]; requires SYNAPSE_DB_DSN)")
	os.Exit(2)
}

func runScan() {
	if len(os.Args) < 3 {
		usage()
	}
	failOn := shared.Severity("high")
	mode := scauc.ScanModeFull
	priority := ""
	ignoreUnfixed := false
	image := false
	offline := false
	jsonOut := false
	sarifOut := false
	for i := 3; i < len(os.Args); i++ {
		switch {
		case os.Args[i] == "--fail-on" && i+1 < len(os.Args):
			failOn = shared.Severity(os.Args[i+1])
			i++
		case os.Args[i] == "--mode" && i+1 < len(os.Args):
			mode = os.Args[i+1]
			i++
		case os.Args[i] == "--detection-priority" && i+1 < len(os.Args):
			priority = os.Args[i+1]
			i++
		case os.Args[i] == "--ignore-unfixed":
			ignoreUnfixed = true
		case os.Args[i] == "--image":
			image = true
		case os.Args[i] == "--offline":
			offline = true
		case os.Args[i] == "--json":
			jsonOut = true
		case os.Args[i] == "--sarif":
			sarifOut = true
		default:
			fmt.Fprintf(os.Stderr, "synapse-cli: unknown or incomplete option %q\n", os.Args[i])
			os.Exit(2)
		}
	}
	switch failOn {
	case "critical", "high", "medium", "low", "info":
	default:
		fmt.Fprintf(os.Stderr, "synapse-cli: invalid --fail-on %q (want critical|high|medium|low|info)\n", failOn)
		os.Exit(2)
	}
	if priority == "" { // resolve the configured default here so an invalid env value gets this same exit-2 message
		priority = os.Getenv("SYNAPSE_DETECTION_PRIORITY")
	}
	if _, err := scauc.NormalizeScanOptions(scauc.ScanOptions{Mode: mode, DetectionPriority: priority}); err != nil {
		fmt.Fprintf(os.Stderr, "synapse-cli: %v (mode want full|vulnerabilities|licenses; detection-priority want comprehensive|precise)\n", err)
		os.Exit(2)
	}
	if jsonOut && sarifOut {
		fmt.Fprintln(os.Stderr, "synapse-cli: choose only one of --json or --sarif")
		os.Exit(2)
	}
	if err := run(os.Args[2], failOn, mode, priority, ignoreUnfixed, image, offline, jsonOut, sarifOut); err != nil {
		fmt.Fprintln(os.Stderr, "synapse-cli:", err)
		os.Exit(1)
	}
}

// syncAdvisories ingests a local OSV advisory dump into the owned advisory store. It requires a
// Postgres DSN: the owned store is durable reference data, so ingesting into an ephemeral in-memory store
// would do nothing. Migrations are applied first (the advisories tables may not exist yet), then a DirFeed
// over the dump directory streams every parseable advisory into the store via the narrow AdvisoryWriter.
func syncAdvisories(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: synapse-cli sync-advisories <dir>|--remote|--remote-distros|--csaf <dir>|--oval <dir> (requires SYNAPSE_DB_DSN)")
	}
	cfg := config.Load()
	if cfg.DBDSN == "" {
		return fmt.Errorf("SYNAPSE_DB_DSN is required: ingesting into an ephemeral in-memory store does nothing")
	}
	// Select the feed: --remote fetches the OSV bulk bucket; otherwise read a local OSV dump directory. Both
	// stream into the same Postgres-backed store via the same ingester.
	var feed ports.AdvisoryFeed
	var src string
	switch {
	case args[0] == "--remote":
		feed = ownadvisory.NewRemoteFeed(cfg.OSVBulkURL, nil, nil) // default bucket + the covered app ecosystems
		src = "OSV bulk bucket"
	case args[0] == "--remote-distros":
		// OS-package advisories (Debian/Alpine) – large zips, fetched only on explicit request (Epic B).
		feed = ownadvisory.NewRemoteFeed(cfg.OSVBulkURL, ownadvisory.DistroBulkEcosystems, nil)
		src = "OSV bulk bucket (distros)"
	case args[0] == "--csaf":
		if len(args) < 2 {
			return fmt.Errorf("usage: synapse-cli sync-advisories --csaf <dir>")
		}
		feed = ownadvisory.NewCSAFDirFeed(args[1])
		src = "CSAF dir " + args[1]
	case args[0] == "--oval":
		if len(args) < 2 {
			return fmt.Errorf("usage: synapse-cli sync-advisories --oval <dir>")
		}
		feed = ownadvisory.NewOVALDirFeed(args[1])
		src = "Ubuntu OVAL dir " + args[1]
	default:
		feed = ownadvisory.NewDirFeed(args[0])
		src = args[0]
	}
	ctx := context.Background()
	if err := postgres.Migrate(ctx, cfg.DBDSN); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	pool, err := postgres.Connect(ctx, cfg.DBDSN)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()
	ingest, err := advisoryingest.NewService(feed, postgres.NewAdvisoryRepository(pool))
	if err != nil {
		return err
	}
	stats, err := ingest.Ingest(ctx)
	if err != nil {
		return fmt.Errorf("ingest from %s: %w", src, err)
	}
	fmt.Printf("synapse-cli: ingested %d advisories, skipped %d (unparseable/unmatchable) (from %s)\n", stats.Ingested, stats.Skipped, src)
	return nil
}

// stderrAudit keeps scan actions attributable without a database
// – the entry is written to the CI log rather than persisted.
type stderrAudit struct{}

func (stderrAudit) Record(_ context.Context, e ports.AuditEntry) error {
	fmt.Fprintf(os.Stderr, "audit: actor=%s action=%s target=%s\n", e.Actor, e.Action, e.Target)
	return nil
}

var _ ports.AuditLogger = stderrAudit{}

func run(path string, failOn shared.Severity, mode, priority string, ignoreUnfixed, image, offline, jsonOut, sarifOut bool) error {
	// An image target is an OCI reference (acquired via crane → OCI layout); a local
	// target is a filesystem path that must be absolute for the scope check.
	target := strings.TrimSpace(path)
	if !image {
		abs, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("resolve path: %w", err)
		}
		target = abs
	}
	ctx := context.Background()
	cfg := config.Load()
	if priority == "" { // the --detection-priority flag falls back to the configured default
		priority = cfg.DetectionPriority
	}
	clock := idgen.SystemClock{}
	ids := idgen.RandomID{}

	engRepo := memory.NewEngagementRepository()
	prov := ports.Provenance{
		ToolVersions: map[string]string{
			"go-enry": buildinfo.Module("github.com/go-enry/go-enry/v2"),
			"synapse": buildinfo.App(),
		},
		VulnDBSource: "osv.dev",
	}
	// Grype (offline DB) always; live OSV unless --offline / SYNAPSE_OFFLINE (air-gapped / fast path).
	detectionSources := []ports.DetectionSource{grype.New(cfg.GrypeBin, cfg.GrypeDBDir)}
	if offline || cfg.Offline {
		// Make the reduced-coverage mode visible: the operator chose lower recall for speed.
		fmt.Fprintln(os.Stderr, "synapse-cli: offline mode – live OSV disabled; detecting with Grype's offline DB only")
	} else {
		detectionSources = append([]ports.DetectionSource{osv.New(cfg.OSVBaseURL, nil)}, detectionSources...)
	}
	sca := scauc.NewService(
		engRepo, memory.NewFindingRepository(), memory.NewScanRepository(), nil, nil, nil, nil, nil, prov, clock, stderrAudit{},
		shared.Severity(cfg.FindingMinSeverity), cfg.ScanTimeout, acquire.New().WithMaxWorkspaceBytes(cfg.MaxWorkspaceBytes).WithImageRootFS(cfg.ImageRootFSEnabled),
		enry.New(), syft.New(cfg.SyftBin),
		detectionSources,
		risk.New(cfg.KEVURL, cfg.EPSSURL, nil), license.New(), licensemeta.NewChain(licensemeta.NewOSMetadata(), licensemeta.New(cfg.DepsDevURL, nil), licensemeta.NewPyPI("", nil)),
	)
	sca.SetSBOMEnricher(manifest.New())
	sca.SetMavenCoordResolver(mavencoord.New())   // recover real Maven coords from JAR pom.properties (offline) before license lookup
	sca.SetJarChecksumResolver(jarchecksum.New()) // capture JAR artifact SHA-1 from the workspace (Syft omits it from CycloneDX)
	// SHA-1 coordinate recovery for shaded/metadata-less JARs: offline trivy-java-db index
	// (SYNAPSE_JARHASH_DB_PATH) first, online Maven Central (SYNAPSE_JARHASH_ONLINE_ENABLED) as fallback.
	var jhResolvers []ports.JarHashResolver
	if cfg.JarHashDBPath != "" {
		if off, err := jarhash.NewOffline(cfg.JarHashDBPath); err != nil {
			fmt.Fprintf(os.Stderr, "synapse-cli: JAR SHA-1 offline DB %q not usable: %v\n", cfg.JarHashDBPath, err)
		} else {
			jhResolvers = append(jhResolvers, off)
			fmt.Fprintf(os.Stderr, "synapse-cli: JAR SHA-1 OFFLINE index ON (%s)\n", cfg.JarHashDBPath)
		}
	}
	if cfg.JarHashOnlineEnabled {
		jhResolvers = append(jhResolvers, jarhash.New(cfg.JarHashBaseURL, nil))
		fmt.Fprintln(os.Stderr, "synapse-cli: JAR SHA-1 ONLINE Maven Central ON (fallback after offline)")
	}
	if len(jhResolvers) > 0 {
		sca.SetJarHashResolver(jarhash.NewChain(jhResolvers...))
	}
	// Maven full-tree resolution (`mvn dependency:list`) – resolves managed versions + transitive deps a
	// from-source pom scan can't, so a Maven project is handled straight from pom.xml (no manual build).
	// The CLI dogfoods a TRUSTED local project, so this is ON BY DEFAULT; set
	// SYNAPSE_MAVEN_RESOLVE_ENABLED=false to opt out. Best-effort: a missing mvn / non-Maven target / error
	// is a no-op (falls back to the pom-only result + the INCOMPLETE warning). Runs mvn directly.
	mavenOn := cfg.MavenResolveEnabled
	if _, set := os.LookupEnv("SYNAPSE_MAVEN_RESOLVE_ENABLED"); !set {
		mavenOn = true // CLI default-on (trusted local); the API stays opt-in + sandbox-gated
	}
	if mavenOn {
		sca.SetMavenResolver(mavenresolve.New(cfg.MvnBin).WithRepoHosts(cfg.MavenRepoHosts).WithLocalRepo(cfg.MavenLocalRepo))
		// Transparency: the CLI runs mvn UNSANDBOXED (it evaluates the project's POM/plugin config) – make
		// that visible so it's never a silent host-exec (the API stays sandbox-gated).
		fmt.Fprintln(os.Stderr, "synapse-cli: Maven resolver ON – runs `mvn` UNSANDBOXED over the project if it has a pom.xml (trusted-local assumption; set SYNAPSE_MAVEN_RESOLVE_ENABLED=false to disable)")
	}
	// Gradle full-tree resolution – same default-on-for-CLI model as Maven (trusted local project),
	// handled straight from build.gradle. Opt out with SYNAPSE_GRADLE_RESOLVE_ENABLED=false. Best-effort.
	gradleOn := cfg.GradleResolveEnabled
	if _, set := os.LookupEnv("SYNAPSE_GRADLE_RESOLVE_ENABLED"); !set {
		gradleOn = true
	}
	if gradleOn {
		sca.SetGradleResolver(gradleresolve.New(cfg.GradleBin).WithRepoHosts(cfg.MavenRepoHosts).WithGradleHome(cfg.GradleHome))
		// Gradle evaluates build.gradle (arbitrary Groovy/Kotlin) – even higher-risk than mvn; surface it.
		fmt.Fprintln(os.Stderr, "synapse-cli: Gradle resolver ON – runs `gradle` UNSANDBOXED over the project if it has a build.gradle, which executes the build script (trusted-local assumption; set SYNAPSE_GRADLE_RESOLVE_ENABLED=false to disable)")
	}
	// Coarse JVM class-reachability – default-on for the CLI (read-only bytecode parsing, no exec);
	// tags each JVM component reachable/unreferenced from the app's compiled closure. Opt out with
	// SYNAPSE_JVM_REACHABILITY_ENABLED=false. Best-effort; a not-built project tags nothing.
	jvmReachOn := cfg.JVMReachabilityEnabled
	if _, set := os.LookupEnv("SYNAPSE_JVM_REACHABILITY_ENABLED"); !set {
		jvmReachOn = true
	}
	if jvmReachOn {
		sca.SetJVMReachability(jvmreach.New())
	}
	if cfg.SASTEnabled {
		sca.SetSASTAnalyzer(sast.New()) // deterministic pattern-SAST (CI-friendly)
	}
	if cfg.SecretScanEnabled {
		sca.SetSecretScanner(secretscan.New()) // deterministic, redacted secret scan (CI-friendly)
	}
	if cfg.MisconfigEnabled {
		// Trusted-local model (like the CLI's maven/gradle resolvers): render Helm charts via a direct
		// `helm template` exec. It runs the chart's templates on the host, so use it only on a project you trust.
		sca.SetMisconfigScanner(misconfig.New().WithHelmDirect()) // deterministic IaC/config misconfig scan (CI-friendly)
	}
	if cfg.ImageRootFSEnabled {
		sca.SetOSPackageCataloger(ospkg.New())         // owned dpkg/apk cataloging from the materialized image rootfs
		sca.SetInstalledPackageCataloger(bincat.New()) // owned Go-binary + Python dist-info cataloging from the rootfs
	}
	if cfg.SuppressionEnabled {
		sca.SetSuppressionLoader(ignorefile.New()) // repo-committed .synapseignore accepted-risk policy (CI-friendly)
	}
	if cfg.VEXEnabled {
		sca.SetVEXLoader(vexfile.New()) // in-repo OpenVEX (.synapse.vex.json) accepted-risk assertions (CI-friendly)
	}
	if cfg.ComplianceEnabled {
		sca.SetComplianceEnabled(true) // attach the AppSec-baseline benchmark (per-control PASS/FAIL)
	}
	if cfg.GoModGraphEnabled {
		// Transitive pkg:golang edges via `go mod graph` (reads go.mod only, never compiles; GOPROXY=off +
		// GOTOOLCHAIN=local). Runs unsandboxed here, matching the CLI's trusted-local model for its other
		// resolvers; best-effort (a non-Go target / no module cache adds no edges, never fails the scan).
		sca.SetGraphResolver(gomodgraph.New(cfg.GoBin))
	}
	sca.SetDBMaxAgeDays(cfg.DBMaxAgeDays) // warn on stale reference DBs (KEV/EPSS/vuln-DB); 0 disables
	if cfg.ScanCacheEnabled {
		if dir := cfg.ResolveScanCacheDir(); dir != "" {
			sca.SetSBOMCache(sbomcache.New(dir)) // content+version-addressed generated-SBOM cache (CI-friendly)
		}
	}
	// JAR-embedded licenses + workspace LICENSE files for every ecosystem.
	sca.SetLicenseFileResolver(licensefile.NewChain(jarlicense.New(), licensefile.New()))
	// Backfill unknown vuln severities from NVD CVSS (best-effort; set SYNAPSE_NVD_API_KEY for throughput).
	sca.SetSeverityEnricher(nvd.New(cfg.NVDAPIURL, cfg.NVDAPIKey, nil).WithBudget(cfg.NVDBudget))
	// --ignore-unfixed (or SYNAPSE_IGNORE_UNFIXED) drops vulns with no upstream fix – the
	// classic distro-noise reducer for OS-package scans (matches Trivy's --ignore-unfixed).
	sca.SetIgnoreUnfixed(ignoreUnfixed || cfg.IgnoreUnfixed)

	// Ephemeral engagement covering the target so the real (gated) Scan path runs.
	eng, err := engagement.New(ids.NewID(), "", "synapse-cli dogfood", "", clock.Now())
	if err != nil {
		return fmt.Errorf("build ephemeral engagement: %w", err)
	}
	scopeKind, acqKind := engagement.TargetRepo, ports.TargetLocal
	if image {
		scopeKind, acqKind = engagement.TargetImage, ports.TargetImage
	}
	eng.Scope.InScope = []engagement.Target{{Kind: scopeKind, Value: target}}
	if err := engRepo.Create(ctx, eng); err != nil {
		return fmt.Errorf("register ephemeral engagement: %w", err)
	}

	res, err := sca.ScanWithOptions(ctx, "synapse-cli", eng.ID, ports.AcquireRequest{Kind: acqKind, Value: target}, scauc.ScanOptions{Mode: mode, DetectionPriority: priority})
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	switch {
	case sarifOut:
		// SARIF 2.1.0 for a code-scanning uploader (e.g. GitHub codeql-action/upload-sarif), to stdout so
		// nothing else mixes in. Covers every finding kind (SCA/SAST/secret/misconfig); first-party kinds
		// carry a file:line physical location. Map each component@version to the manifest it was found in
		// so SCA findings get a physical location too (GitHub rejects logical-only locations). The
		// --fail-on gate below still sets the exit code, so the same run both annotates and gates.
		manifestByComp := map[string]string{}
		if res.SBOM != nil {
			for _, c := range res.SBOM.Components {
				// SBOM Location is often workspace-rooted with a leading "/" (Syft's dir-scan convention);
				// a code-scanning UI wants a repo-relative path, so drop any leading slash (a no-op when
				// absent). If two components share name@version, last write wins – any declaring manifest
				// is fine for the annotation.
				if loc := strings.TrimPrefix(c.Location, "/"); loc != "" {
					manifestByComp[c.Name+"@"+c.Version] = loc
				}
			}
		}
		manifestFor := func(f finding.Finding) string {
			if _, comp, ver, ok := vulnerability.ParseDedupKey(f.DedupKey); ok {
				return manifestByComp[comp+"@"+ver]
			}
			return ""
		}
		// Map each vulnerability's dedup key to its fixed version so a code-scanning alert shows the
		// remediation. Keyed by the same dedup key the finding carries (advisory + component + version),
		// because different advisories on the same component are fixed in different releases.
		fixByKey := map[string]string{}
		for _, v := range res.Vulnerabilities {
			if v.FixedVersion != "" {
				fixByKey[vulnerability.DedupKey(v.ID, v.Component, v.Version)] = v.FixedVersion
			}
		}
		fixFor := func(f finding.Finding) string { return fixByKey[f.DedupKey] }
		out, err := exportuc.MarshalSARIF(res.Findings, res.ToolVersions["synapse"], exportuc.SARIFOptions{Manifest: manifestFor, Fix: fixFor})
		if err != nil {
			return fmt.Errorf("encode sarif: %w", err)
		}
		if _, err := os.Stdout.Write(append(out, '\n')); err != nil {
			return fmt.Errorf("write sarif: %w", err)
		}
	case jsonOut:
		// Machine-readable full scan result (for CI / tooling / cross-scanner comparison), to stdout so the
		// human report never mixes in. The --fail-on gate below still sets the exit code.
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return fmt.Errorf("encode json result: %w", err)
		}
	default:
		printReport(target, res)
	}

	gate := shared.SeverityRank(failOn)
	accepted := res.SuppressedKeys() // .synapseignore/VEX accepted-risk: reported + sealed, but exempt from the gate
	verify := res.NeedsVerifyKeys()  // precise-mode needs-verify: lower-confidence, exempt from the gate too
	over := 0
	for _, f := range res.Findings {
		if accepted[f.DedupKey] || verify[f.DedupKey] {
			continue
		}
		if shared.SeverityRank(f.Severity) >= gate {
			over++
		}
	}
	if over > 0 {
		return fmt.Errorf("%d finding(s) at or above %s", over, failOn)
	}
	return nil
}

func printReport(target string, res *scauc.ScanResult) {
	fmt.Printf("\nSynapse SCA dogfood – %s\n", target)
	fmt.Printf("  tools: %v · vuln-db: %s\n", res.ToolVersions, res.VulnDBSnapshot)
	if w := res.Completeness.Warning; w != "" {
		fmt.Printf("  ! INCOMPLETE SCAN: %s\n", w)
	} else {
		fmt.Printf("  completeness: confident (%d/%d components resolved; lockfiles %v)\n",
			res.Completeness.ComponentsResolved, res.Completeness.ComponentsTotal, res.Completeness.Lockfiles)
	}
	if res.SBOM != nil {
		fmt.Printf("  components: %d\n", len(res.SBOM.Components))
	}
	if img := res.Image; img != nil { // Epic D: container layer attribution + base-image estimate
		fmt.Printf("  image: %s", img.Reference)
		if img.Digest != "" {
			fmt.Printf(" @ %s", img.Digest)
		}
		fmt.Printf(" (%s/%s)\n", img.OS, img.Architecture)
		fmt.Printf("    layers: %d total – %d base (estimated OS/distro), %d application\n",
			len(img.Layers), img.BaseLayerCount, len(img.Layers)-img.BaseLayerCount)
	}
	if d := res.Distro; d != nil { // Epic E: captured OS distribution + End-of-Life flag
		name := d.ID + " " + d.Version
		if d.Codename != "" {
			name += " (" + d.Codename + ")"
		}
		switch {
		case d.EndOfLife:
			fmt.Printf("  distro: %s – ! END-OF-LIFE since %s (no security updates; %s)\n", name, d.EOLDate, d.Source)
		case d.Known:
			fmt.Printf("  distro: %s – supported until %s\n", name, d.EOLDate)
		default:
			fmt.Printf("  distro: %s – EOL status unknown (not in the curated table)\n", name)
		}
	}
	if len(res.Coverage) > 0 { // per-ecosystem breakdown so a thin ecosystem isn't hidden behind the global number
		fmt.Printf("  coverage by ecosystem:\n")
		for _, c := range res.Coverage {
			fmt.Printf("    %-12s %d/%d resolved\n", c.Ecosystem, c.Resolved, c.Components)
		}
	}
	if q := res.SBOMQuality; len(q.Elements) > 0 { // NTIA + semantic describe-quality of the SBOM (distinct from coverage)
		mark := "NTIA minimum elements present"
		if !q.NTIAMet {
			mark = "! NTIA GAPS"
		}
		fmt.Printf("  sbom quality: %d/100 (NTIA %d/100) – %s\n", q.Score, q.NTIAScore, mark)
		for _, e := range q.Elements { // surface each thin score-feeding dimension so the gap is actionable
			if e.Category != sbom.QualityCategoryCompliance && e.Score < 100 && e.Detail != "" {
				fmt.Printf("    %-26s %3d/100 – %s\n", e.Label, e.Score, e.Detail)
			}
		}
		// Compliance-only signals gate a profile but deliberately do NOT feed the blended score above; label them
		// so a "100/100" headline beside a "0/100" strong-checksum line does not read as a contradiction.
		firstCompliance := true
		for _, e := range q.Elements {
			if e.Category != sbom.QualityCategoryCompliance || e.Score >= 100 || e.Detail == "" {
				continue
			}
			if firstCompliance {
				fmt.Printf("    profile-only signals (do not affect the score above):\n")
				firstCompliance = false
			}
			fmt.Printf("      %-24s %3d/100 – %s\n", e.Label, e.Score, e.Detail)
		}
		for _, p := range q.Profiles { // explicit per-standard PASS/FAIL a regulated buyer can cite
			fmt.Printf("    %s\n", p.Summary)
		}
	}
	fmt.Printf("  vulnerabilities: %d", len(res.Vulnerabilities))
	if counts := countVulnSeverity(res); counts != "" {
		fmt.Printf(" (%s)", counts)
	}
	fmt.Println()
	if denied, warned := countLicenses(res.Licenses); denied+warned > 0 {
		fmt.Printf("  licenses: %d denied, %d warned\n", denied, warned)
	}
	if reach, unref := countReachability(res.SBOM.Components); reach+unref > 0 {
		fmt.Printf("  reachability (JVM, coarse): %d referenced, %d unreferenced by app code\n", reach, unref)
	}
	fmt.Printf("  findings (promoted): %d\n", len(res.Findings))
	if res.VulnsBelowThreshold > 0 {
		fmt.Printf("  ! %d detected vulnerabilities are BELOW the '%s' severity floor and were NOT promoted "+
			"(set SYNAPSE_FINDING_MIN_SEVERITY=info to promote every detected vuln)\n", res.VulnsBelowThreshold, res.MinSeverity)
	}
	if res.UnfixedSuppressed > 0 {
		fmt.Printf("  ! %d detected vulnerabilities have NO upstream fix and were suppressed by --ignore-unfixed\n", res.UnfixedSuppressed)
	}
	for _, w := range res.SourceWarnings {
		fmt.Printf("  ! %s\n", w)
	}
	if n := len(res.SuppressedFindings); n > 0 {
		fmt.Printf("  accepted-risk via .synapseignore: %d (still reported + evidence-sealed; exempt from --fail-on)\n", n)
		for _, s := range res.SuppressedFindings {
			reason := s.Reason
			if reason == "" {
				reason = "(no reason given)"
			}
			fmt.Printf("    - %s  [%s]  %s\n", s.Title, s.RuleID, reason)
		}
	}
	for _, id := range res.ExpiredSuppressions {
		fmt.Printf("  ! .synapseignore rule %q has EXPIRED – no longer accepted; the finding trips --fail-on again. Refresh or remove it\n", id)
	}
	for _, id := range res.MalformedSuppressions {
		fmt.Printf("  ! .synapseignore rule %q has an UNPARSEABLE exp: date – not applied (fail-safe). Fix it to YYYY-MM-DD\n", id)
	}
	if n := len(res.NeedsVerification); n > 0 {
		fmt.Printf("  needs-verify (precise): %d single-source vuln(s) quarantined – still reported + sealed, exempt from --fail-on\n", n)
		for _, v := range res.NeedsVerification {
			fmt.Printf("    - %s\n", v.Title)
		}
	}
	for _, f := range res.Findings {
		kev := ""
		if f.KEV {
			kev = " [KEV]"
		}
		fmt.Printf("    %-9s risk %5.2f  %s%s\n", f.Severity, f.RiskScore, f.Title, kev)
	}
	if c := res.Compliance; c != nil {
		scope := ""
		if c.MinSeverity != "" && c.MinSeverity != "info" {
			scope = " (evaluated over findings ≥ " + c.MinSeverity
			if c.IgnoreUnfixed {
				scope += ", unfixed excluded"
			}
			scope += ")"
		} else if c.IgnoreUnfixed {
			scope = " (unfixed vulns excluded)"
		}
		fmt.Printf("\n  compliance: %s v%s – %d/%d controls passing%s\n", c.Title, c.Version, c.Passed, c.Passed+c.Failed, scope)
		for _, r := range c.Results {
			status := "PASS"
			if !r.Passed {
				status = "FAIL"
			}
			fmt.Printf("    [%s] %-14s %s\n", status, r.Control.ID, r.Control.Title)
			for _, e := range r.Evidence {
				fmt.Printf("           - %s\n", e)
			}
		}
	}
	fmt.Println()
}

func countVulnSeverity(res *scauc.ScanResult) string {
	order := []shared.Severity{"critical", "high", "medium", "low", "info"}
	n := map[shared.Severity]int{}
	for _, v := range res.Vulnerabilities {
		n[v.Severity]++
	}
	out := ""
	for _, s := range order {
		if n[s] > 0 {
			if out != "" {
				out += ", "
			}
			out += fmt.Sprintf("%s %d", s, n[s])
		}
	}
	return out
}

func countLicenses(lics []ports.LicenseFinding) (denied, warned int) {
	for _, l := range lics {
		switch l.Verdict {
		case ports.LicenseDeny:
			denied++
		case ports.LicenseWarn:
			warned++
		}
	}
	return denied, warned
}

// countReachability tallies the coarse JVM class-reachability verdicts. Both are 0 when no JVM
// reachability was computed (non-JVM / not-built / disabled), so the caller prints nothing.
func countReachability(comps []sbom.Component) (referenced, unreferenced int) {
	for _, c := range comps {
		switch c.Reachability {
		case sbom.ReachabilityReachable:
			referenced++
		case sbom.ReachabilityUnreferenced:
			unreferenced++
		}
	}
	return referenced, unreferenced
}
