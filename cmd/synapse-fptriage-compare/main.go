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
	baselinePath := flag.String("baseline", "", "baseline synapse-ai-triage-evaluation-v4 report")
	candidatePath := flag.String("candidate", "", "candidate synapse-ai-triage-evaluation-v4 report")
	outputPath := flag.String("output", "-", "comparison report path, or - for stdout")
	failOnBlocked := flag.Bool("fail-on-blocked", true, "exit non-zero after writing a blocked comparison")
	minimumPrecision := flag.Int("minimum-precision-bps", defaults.MinimumPrecisionBasisPoints, "minimum candidate precision in basis points")
	maximumEscape := flag.Int("maximum-fn-escape-bps", defaults.MaximumFalseNegativeEscapeRateBasisPoints, "maximum candidate false-negative escape rate in basis points")
	maximumPrecisionDrop := flag.Int("maximum-precision-drop-bps", defaults.MaximumPrecisionDropBasisPoints, "maximum precision drop versus baseline in basis points")
	maximumRecallDrop := flag.Int("maximum-recall-drop-bps", defaults.MaximumRecallDropBasisPoints, "maximum recall drop versus baseline in basis points")
	maximumCoverageDrop := flag.Int("maximum-coverage-drop-bps", defaults.MaximumCoverageDropBasisPoints, "maximum coverage drop versus baseline in basis points")
	maximumVerifierCoverageDrop := flag.Int("maximum-verifier-coverage-drop-bps", defaults.MaximumVerifierCoverageDropBasisPoints, "maximum verifier-comparison coverage drop versus baseline in basis points")
	maximumDisagreementIncrease := flag.Int("maximum-disagreement-increase-bps", defaults.MaximumDisagreementIncreaseBasisPoints, "maximum disagreement-rate increase versus baseline in basis points")
	minimumCounterfactualCoverage := flag.Int("minimum-counterfactual-coverage-bps", defaults.MinimumCounterfactualCoverageBasisPoints, "minimum covered adversarial counterfactual pairs in basis points")
	minimumCounterfactualVerifierCoverage := flag.Int("minimum-counterfactual-verifier-coverage-bps", defaults.MinimumCounterfactualVerifierCoverageBasisPoints, "minimum independently verified adversarial counterfactual pairs in basis points")
	maximumCounterfactualProposerFlips := flag.Int("maximum-counterfactual-proposer-flip-bps", defaults.MaximumCounterfactualProposerFlipRateBasisPoints, "maximum proposer verdict flip rate across counterfactual pairs in basis points")
	maximumCounterfactualVerifierFlips := flag.Int("maximum-counterfactual-verifier-flip-bps", defaults.MaximumCounterfactualVerifierFlipRateBasisPoints, "maximum verifier verdict flip rate across counterfactual pairs in basis points")
	maximumCounterfactualConsensusFlips := flag.Int("maximum-counterfactual-consensus-flip-bps", defaults.MaximumCounterfactualConsensusFlipRateBasisPoints, "maximum consensus flip rate across counterfactual pairs in basis points")
	maximumCounterfactualPolicyFlips := flag.Int("maximum-counterfactual-policy-flip-bps", defaults.MaximumCounterfactualPolicyFlipRateBasisPoints, "maximum deterministic policy flip rate across counterfactual pairs in basis points")
	minimumGateReachablePairs := flag.Int("minimum-gate-reachable-counterfactual-pairs", defaults.MinimumGateReachableCounterfactualPairs, "minimum counterfactual pairs the deterministic policy could exempt; a count, not basis points")
	flag.Parse()

	policy := sca.AIEvaluationPromotionPolicy{
		MinimumPrecisionBasisPoints:                       *minimumPrecision,
		MaximumFalseNegativeEscapeRateBasisPoints:         *maximumEscape,
		MaximumPrecisionDropBasisPoints:                   *maximumPrecisionDrop,
		MaximumRecallDropBasisPoints:                      *maximumRecallDrop,
		MaximumCoverageDropBasisPoints:                    *maximumCoverageDrop,
		MaximumVerifierCoverageDropBasisPoints:            *maximumVerifierCoverageDrop,
		MaximumDisagreementIncreaseBasisPoints:            *maximumDisagreementIncrease,
		MinimumCounterfactualCoverageBasisPoints:          *minimumCounterfactualCoverage,
		MinimumCounterfactualVerifierCoverageBasisPoints:  *minimumCounterfactualVerifierCoverage,
		MaximumCounterfactualProposerFlipRateBasisPoints:  *maximumCounterfactualProposerFlips,
		MaximumCounterfactualVerifierFlipRateBasisPoints:  *maximumCounterfactualVerifierFlips,
		MaximumCounterfactualConsensusFlipRateBasisPoints: *maximumCounterfactualConsensusFlips,
		MaximumCounterfactualPolicyFlipRateBasisPoints:    *maximumCounterfactualPolicyFlips,
		MinimumGateReachableCounterfactualPairs:           *minimumGateReachablePairs,
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
	resolvedOutputPath, err := validateOutputPath(outputPath, baselinePath, candidatePath)
	if err != nil {
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
	if err := writeComparison(resolvedOutputPath, comparison); err != nil {
		return err
	}
	if comparison.Status == "blocked" && failOnBlocked {
		return fmt.Errorf("%w (%d failure(s); comparison %s)", errPromotionBlocked, len(comparison.Failures), comparison.ComparisonID)
	}
	return nil
}

func validateOutputPath(outputPath string, inputPaths ...string) (string, error) {
	if outputPath == "-" {
		return outputPath, nil
	}
	outputAbs, err := filepath.Abs(outputPath)
	if err != nil {
		return "", fmt.Errorf("resolve comparison output path: %w", err)
	}
	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(outputAbs))
	if err != nil {
		return "", fmt.Errorf("resolve comparison output parent: %w", err)
	}
	resolvedOutput := filepath.Join(resolvedParent, filepath.Base(outputAbs))
	if _, statErr := os.Lstat(resolvedOutput); statErr == nil {
		return "", fmt.Errorf("comparison output already exists; choose a fresh path")
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("inspect comparison output: %w", statErr)
	}
	for _, inputPath := range inputPaths {
		inputAbs, err := filepath.Abs(inputPath)
		if err != nil {
			return "", fmt.Errorf("resolve evaluation input path: %w", err)
		}
		resolvedInput, err := filepath.EvalSymlinks(inputAbs)
		if err != nil {
			return "", fmt.Errorf("resolve evaluation input path: %w", err)
		}
		sameName := outputAbs == inputAbs || resolvedOutput == resolvedInput
		if runtime.GOOS == "windows" {
			sameName = strings.EqualFold(outputAbs, inputAbs) || strings.EqualFold(resolvedOutput, resolvedInput)
		}
		if sameName {
			return "", fmt.Errorf("comparison output must not overwrite an evaluation input")
		}
	}
	return resolvedOutput, nil
}

func writeComparison(outputPath string, comparison sca.AIEvaluationComparison) error {
	var (
		out *os.File
		err error
	)
	if outputPath == "-" {
		out = os.Stdout
	} else {
		out, err = os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
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
