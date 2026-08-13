// Command synapse-fptriage-drift compares a saved AI-triage observability
// distribution with a versioned, human-approved baseline. It only emits drift
// evidence; it never changes runtime model, prompt, or quality-gate behavior.
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

var errDriftAlert = errors.New("AI triage distribution requires review")

func main() {
	baselinePath := flag.String("baseline", "", "versioned human-approved drift baseline JSON")
	observedPath := flag.String("observed", "", "saved AI triage observability response or distribution snapshot")
	outputPath := flag.String("output", "-", "drift report path, or - for stdout")
	failOnAlert := flag.Bool("fail-on-alert", true, "exit non-zero after writing a drift or insufficient-sample report")
	flag.Parse()

	if err := run(*baselinePath, *observedPath, *outputPath, *failOnAlert); err != nil {
		fmt.Fprintf(os.Stderr, "synapse-fptriage-drift: %v\n", err)
		os.Exit(1)
	}
}

func run(baselinePath, observedPath, outputPath string, failOnAlert bool) error {
	if strings.TrimSpace(baselinePath) == "" || strings.TrimSpace(observedPath) == "" {
		return fmt.Errorf("--baseline and --observed are required")
	}
	if err := validateOutputPath(outputPath, baselinePath, observedPath); err != nil {
		return err
	}
	baselineData, err := os.ReadFile(baselinePath)
	if err != nil {
		return fmt.Errorf("read drift baseline: %w", err)
	}
	baseline, err := sca.LoadAITriageDriftBaseline(baselineData)
	if err != nil {
		return fmt.Errorf("load drift baseline: %w", err)
	}
	observedData, err := os.ReadFile(observedPath)
	if err != nil {
		return fmt.Errorf("read observed distribution: %w", err)
	}
	observed, err := sca.LoadAITriageDistributionSnapshot(observedData)
	if err != nil {
		return fmt.Errorf("load observed distribution: %w", err)
	}
	report, err := sca.DetectAITriageDistributionDrift(baseline, observed)
	if err != nil {
		return err
	}
	if err := writeReport(outputPath, report); err != nil {
		return err
	}
	if report.Status != "stable" && failOnAlert {
		return fmt.Errorf("%w (%s; report %s)", errDriftAlert, report.Status, report.ReportID)
	}
	return nil
}

func validateOutputPath(outputPath string, inputPaths ...string) error {
	if outputPath == "-" {
		return nil
	}
	outputAbs, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve drift output path: %w", err)
	}
	if info, statErr := os.Lstat(outputAbs); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("drift output must not be a symlink")
	}
	outputInfo, outputStatErr := os.Stat(outputAbs)
	for _, inputPath := range inputPaths {
		inputAbs, err := filepath.Abs(inputPath)
		if err != nil {
			return fmt.Errorf("resolve drift input path: %w", err)
		}
		sameName := outputAbs == inputAbs
		if runtime.GOOS == "windows" {
			sameName = strings.EqualFold(outputAbs, inputAbs)
		}
		if sameName {
			return fmt.Errorf("drift output must not overwrite an input")
		}
		if outputStatErr == nil {
			if inputInfo, statErr := os.Stat(inputAbs); statErr == nil && os.SameFile(outputInfo, inputInfo) {
				return fmt.Errorf("drift output must not alias an input")
			}
		}
	}
	return nil
}

func writeReport(outputPath string, report sca.AITriageDriftReport) error {
	var (
		out *os.File
		err error
	)
	if outputPath == "-" {
		out = os.Stdout
	} else {
		out, err = os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("create drift report: %w", err)
		}
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		if out != os.Stdout {
			_ = out.Close()
		}
		return fmt.Errorf("write drift report: %w", err)
	}
	if out != os.Stdout {
		if err := out.Close(); err != nil {
			return fmt.Errorf("close drift report (it may be incomplete): %w", err)
		}
	}
	return nil
}
