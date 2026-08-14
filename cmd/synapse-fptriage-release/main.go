// Command synapse-fptriage-release creates an immutable, versioned ledger of independently
// approved AI-triage promotions and rollbacks. It never changes runtime configuration.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

func main() {
	manifestPath := flag.String("manifest", "", "versioned PM/Security release manifest JSON")
	ledgerPath := flag.String("ledger", "", "existing release ledger JSON (required for rollback; optional for first promotion)")
	comparisonPath := flag.String("comparison", "", "passing candidate comparison JSON (promotion only)")
	baselinePath := flag.String("baseline", "", "baseline synapse-ai-triage-evaluation-v3 report (promotion only)")
	candidatePath := flag.String("candidate", "", "candidate synapse-ai-triage-evaluation-v3 report (promotion only)")
	outputPath := flag.String("output", "", "new path for the append-only release ledger")
	printDigest := flag.Bool("print-review-digest", false, "print the digest PM/Security must approve without writing a ledger")
	flag.Parse()

	if err := run(*manifestPath, *ledgerPath, *comparisonPath, *baselinePath, *candidatePath, *outputPath, *printDigest, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "synapse-fptriage-release: %v\n", err)
		os.Exit(1)
	}
}

func run(manifestPath, ledgerPath, comparisonPath, baselinePath, candidatePath, outputPath string, printDigest bool, stdout io.Writer) error {
	manifestPath, ledgerPath, comparisonPath = strings.TrimSpace(manifestPath), strings.TrimSpace(ledgerPath), strings.TrimSpace(comparisonPath)
	baselinePath, candidatePath, outputPath = strings.TrimSpace(baselinePath), strings.TrimSpace(candidatePath), strings.TrimSpace(outputPath)
	if manifestPath == "" {
		return fmt.Errorf("--manifest is required")
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read release manifest: %w", err)
	}
	manifest, err := sca.LoadAIEvaluationReleaseManifest(manifestBytes)
	if err != nil {
		return err
	}

	var ledger sca.AIEvaluationReleaseLedger
	if ledgerPath != "" {
		ledgerBytes, err := os.ReadFile(ledgerPath)
		if err != nil {
			return fmt.Errorf("read release ledger: %w", err)
		}
		ledger, err = sca.LoadAIEvaluationReleaseLedger(ledgerBytes)
		if err != nil {
			return err
		}
	}

	var evidence *sca.AIEvaluationPromotionEvidence
	if manifest.Action == sca.AIEvaluationReleasePromote {
		if comparisonPath == "" || baselinePath == "" || candidatePath == "" {
			return fmt.Errorf("promotion requires --comparison, --baseline, and --candidate")
		}
		loaded, err := loadPromotionEvidence(comparisonPath, baselinePath, candidatePath)
		if err != nil {
			return err
		}
		evidence = &loaded
	} else {
		if ledgerPath == "" {
			return fmt.Errorf("rollback requires --ledger")
		}
		if comparisonPath != "" || baselinePath != "" || candidatePath != "" {
			return fmt.Errorf("rollback must not supply promotion comparison or evaluation reports")
		}
	}

	if printDigest {
		digest, err := sca.AIEvaluationReleaseReviewDigest(ledger, evidence, manifest)
		if err != nil {
			return err
		}
		return writeReleaseJSON(stdout, map[string]string{"version": manifest.Version, "action": manifest.Action, "reviewed_sha256": digest})
	}
	if outputPath == "" || outputPath == "-" {
		return fmt.Errorf("--output must be a new ledger file path")
	}
	for _, input := range []string{manifestPath, ledgerPath, comparisonPath, baselinePath, candidatePath} {
		if input != "" && sameReleasePath(outputPath, input) {
			return fmt.Errorf("--output must not overwrite an input artifact")
		}
	}
	updated, err := sca.ApplyAIEvaluationRelease(ledger, evidence, manifest)
	if err != nil {
		return err
	}
	return writeReleaseLedger(outputPath, updated)
}

func loadPromotionEvidence(comparisonPath, baselinePath, candidatePath string) (sca.AIEvaluationPromotionEvidence, error) {
	comparisonBytes, err := os.ReadFile(comparisonPath)
	if err != nil {
		return sca.AIEvaluationPromotionEvidence{}, fmt.Errorf("read comparison: %w", err)
	}
	comparison, err := sca.LoadAIEvaluationComparison(comparisonBytes)
	if err != nil {
		return sca.AIEvaluationPromotionEvidence{}, err
	}
	baselineBytes, err := os.ReadFile(baselinePath)
	if err != nil {
		return sca.AIEvaluationPromotionEvidence{}, fmt.Errorf("read baseline report: %w", err)
	}
	baseline, err := sca.LoadAIEvaluationReport(baselineBytes)
	if err != nil {
		return sca.AIEvaluationPromotionEvidence{}, fmt.Errorf("baseline report: %w", err)
	}
	candidateBytes, err := os.ReadFile(candidatePath)
	if err != nil {
		return sca.AIEvaluationPromotionEvidence{}, fmt.Errorf("read candidate report: %w", err)
	}
	candidate, err := sca.LoadAIEvaluationReport(candidateBytes)
	if err != nil {
		return sca.AIEvaluationPromotionEvidence{}, fmt.Errorf("candidate report: %w", err)
	}
	evidence := sca.AIEvaluationPromotionEvidence{BaselineReport: baseline, CandidateReport: candidate, Comparison: comparison}
	if err := evidence.Validate(); err != nil {
		return sca.AIEvaluationPromotionEvidence{}, err
	}
	return evidence, nil
}

func writeReleaseLedger(path string, ledger sca.AIEvaluationReleaseLedger) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create release ledger: %w", err)
	}
	if err := writeReleaseJSON(file, ledger); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("sync release ledger: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close release ledger: %w", err)
	}
	return nil
}

func writeReleaseJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("write release artifact: %w", err)
	}
	return nil
}

func sameReleasePath(a, b string) bool {
	a, b = canonicalReleasePath(a), canonicalReleasePath(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func canonicalReleasePath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	abs = filepath.Clean(abs)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(resolved)
	}
	// The output normally does not exist yet. Resolve its parent so a symlinked directory
	// cannot alias an input artifact and bypass the explicit overwrite guard.
	if parent, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		return filepath.Join(parent, filepath.Base(abs))
	}
	return abs
}
