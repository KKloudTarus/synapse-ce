// Command synapse-fptriage-compare validates and compares two deterministic AI false-positive triage
// shadow reports. It emits promotion-review evidence but never changes a runtime model or prompt.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

var errPromotionBlocked = errors.New("candidate is blocked from promotion review")

func main() {
	defaults := sca.DefaultAIEvaluationPromotionPolicy()
	baselinePath := flag.String("baseline", "", "baseline synapse-ai-triage-evaluation-v2 report")
	candidatePath := flag.String("candidate", "", "candidate synapse-ai-triage-evaluation-v2 report")
	outputPath := flag.String("output", "-", "comparison report path, or - for stdout")
	failOnBlocked := flag.Bool("fail-on-blocked", true, "exit non-zero after writing a blocked comparison")
	minimumPrecision := flag.Int("minimum-precision-bps", defaults.MinimumPrecisionBasisPoints, "minimum candidate precision in basis points")
	maximumEscape := flag.Int("maximum-fn-escape-bps", defaults.MaximumFalseNegativeEscapeRateBasisPoints, "maximum candidate false-negative escape rate in basis points")
	maximumPrecisionDrop := flag.Int("maximum-precision-drop-bps", defaults.MaximumPrecisionDropBasisPoints, "maximum precision drop versus baseline in basis points")
	maximumRecallDrop := flag.Int("maximum-recall-drop-bps", defaults.MaximumRecallDropBasisPoints, "maximum recall drop versus baseline in basis points")
	maximumCoverageDrop := flag.Int("maximum-coverage-drop-bps", defaults.MaximumCoverageDropBasisPoints, "maximum coverage drop versus baseline in basis points")
	maximumVerifierCoverageDrop := flag.Int("maximum-verifier-coverage-drop-bps", defaults.MaximumVerifierCoverageDropBasisPoints, "maximum verifier-comparison coverage drop versus baseline in basis points")
	maximumDisagreementIncrease := flag.Int("maximum-disagreement-increase-bps", defaults.MaximumDisagreementIncreaseBasisPoints, "maximum disagreement-rate increase versus baseline in basis points")
	flag.Parse()

	policy := sca.AIEvaluationPromotionPolicy{
		MinimumPrecisionBasisPoints:               *minimumPrecision,
		MaximumFalseNegativeEscapeRateBasisPoints: *maximumEscape,
		MaximumPrecisionDropBasisPoints:           *maximumPrecisionDrop,
		MaximumRecallDropBasisPoints:              *maximumRecallDrop,
		MaximumCoverageDropBasisPoints:            *maximumCoverageDrop,
		MaximumVerifierCoverageDropBasisPoints:    *maximumVerifierCoverageDrop,
		MaximumDisagreementIncreaseBasisPoints:    *maximumDisagreementIncrease,
	}
	if err := run(*baselinePath, *candidatePath, *outputPath, policy, *failOnBlocked); err != nil {
		fmt.Fprintf(os.Stderr, "synapse-fptriage-compare: %v\n", err)
		os.Exit(1)
	}
}

func run(baselinePath, candidatePath, outputPath string, policy sca.AIEvaluationPromotionPolicy, failOnBlocked bool) error {
	if baselinePath == "" || candidatePath == "" {
		return fmt.Errorf("--baseline and --candidate are required")
	}
	if err := validateOutputPath(outputPath, baselinePath, candidatePath); err != nil {
		return err
	}
	baselineData, err := os.ReadFile(baselinePath)
	if err != nil {
		return fmt.Errorf("read baseline report: %w", err)
	}
	baseline, err := sca.LoadAIEvaluationReport(baselineData)
	if err != nil {
		return fmt.Errorf("load baseline report: %w", err)
	}
	candidateData, err := os.ReadFile(candidatePath)
	if err != nil {
		return fmt.Errorf("read candidate report: %w", err)
	}
	candidate, err := sca.LoadAIEvaluationReport(candidateData)
	if err != nil {
		return fmt.Errorf("load candidate report: %w", err)
	}
	comparison, err := sca.CompareAIEvaluationReports(baseline, candidate, policy)
	if err != nil {
		return err
	}
	if err := writeComparison(outputPath, comparison); err != nil {
		return err
	}
	if comparison.Status == "blocked" && failOnBlocked {
		return fmt.Errorf("%w (%d failure(s); comparison %s)", errPromotionBlocked, len(comparison.Failures), comparison.ComparisonID)
	}
	return nil
}

func validateOutputPath(outputPath string, inputPaths ...string) error {
	if outputPath == "-" {
		return nil
	}
	outputAbs, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve comparison output path: %w", err)
	}
	if info, statErr := os.Lstat(outputAbs); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("comparison output must not be a symlink")
	}
	outputInfo, outputStatErr := os.Stat(outputAbs)
	for _, inputPath := range inputPaths {
		inputAbs, err := filepath.Abs(inputPath)
		if err != nil {
			return fmt.Errorf("resolve evaluation input path: %w", err)
		}
		sameName := outputAbs == inputAbs
		if runtime.GOOS == "windows" {
			sameName = strings.EqualFold(outputAbs, inputAbs)
		}
		if sameName {
			return fmt.Errorf("comparison output must not overwrite an evaluation input")
		}
		if outputStatErr == nil {
			if inputInfo, statErr := os.Stat(inputAbs); statErr == nil && os.SameFile(outputInfo, inputInfo) {
				return fmt.Errorf("comparison output must not alias an evaluation input")
			}
		}
	}
	return nil
}

func writeComparison(outputPath string, comparison sca.AIEvaluationComparison) error {
	var (
		out *os.File
		err error
	)
	if outputPath == "-" {
		out = os.Stdout
	} else {
		out, err = os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("create comparison report: %w", err)
		}
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(comparison); err != nil {
		if out != os.Stdout {
			_ = out.Close()
		}
		return fmt.Errorf("write comparison report: %w", err)
	}
	if out != os.Stdout {
		if err := out.Close(); err != nil {
			return fmt.Errorf("close comparison report (it may be incomplete): %w", err)
		}
	}
	return nil
}
