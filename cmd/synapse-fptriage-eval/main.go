// Command synapse-fptriage-eval runs the production false-positive triager in shadow mode over a
// versioned, human-reviewed golden dataset and emits a deterministic machine-readable report.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/llm/openai"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fptriage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

func main() {
	datasetPath := flag.String("dataset", "internal/usecase/sca/testdata/fptriage-golden-v1.json", "versioned golden dataset JSON")
	outputPath := flag.String("output", "-", "report path, or - for stdout")
	flag.Parse()

	if err := run(context.Background(), *datasetPath, *outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "synapse-fptriage-eval: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, datasetPath, outputPath string) error {
	b, err := os.ReadFile(datasetPath)
	if err != nil {
		return fmt.Errorf("read dataset: %w", err)
	}
	dataset, err := sca.LoadAIEvaluationDataset(b)
	if err != nil {
		return err
	}

	cfg := config.Load()
	if strings.TrimSpace(cfg.FPTriageModel) == "" || strings.TrimSpace(cfg.VerifierModel) == "" {
		return fmt.Errorf("SYNAPSE_FP_TRIAGE_MODEL and a distinct SYNAPSE_VERIFIER_MODEL are required")
	}
	proposer, err := openai.New(cfg.LLMBaseURL, cfg.LLMAPIKey, cfg.FPTriageModel, cfg.LLMTimeout)
	if err != nil {
		return fmt.Errorf("create proposer: %w", err)
	}
	verifier, err := openai.New(cfg.LLMBaseURL, cfg.LLMAPIKey, cfg.VerifierModel, cfg.LLMTimeout)
	if err != nil {
		return fmt.Errorf("create verifier: %w", err)
	}
	coord := fptriage.New(proposer, cfg.FPTriageModel).WithVerifier(verifier, cfg.VerifierModel)
	if coord.VerifierModel() == "" {
		return fmt.Errorf("verifier %q is not distinct from proposer %q after canonicalization", cfg.VerifierModel, cfg.FPTriageModel)
	}
	reader := sca.NewAIEvaluationSourceReader(dataset)
	triager := fptriage.NewTriager(coord, func(string) ports.SourceSnippetReader { return reader })
	report, err := sca.EvaluateFPTriage(ctx, dataset, sca.AIEvaluationRun{
		ProposerModel: coord.ProposerModel(), VerifierModel: coord.VerifierModel(),
		PromptVersion: fptriage.EvaluationPromptVersion(), PolicyVersion: sca.EvaluationPolicyVersion(),
	}, triager)
	if err != nil {
		return err
	}

	var out *os.File
	if outputPath == "-" {
		out = os.Stdout
	} else {
		out, err = os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("create report: %w", err)
		}
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(report); err != nil {
		if out != os.Stdout {
			_ = out.Close()
		}
		return fmt.Errorf("write report: %w", err)
	}
	// Close is REPORTED, not deferred-and-dropped. A write can fail at flush time, so a discarded
	// Close error means a truncated evaluation report written with exit status 0 -- and this report is
	// the artefact someone reads to decide whether AI triage is good enough to enforce. Reporting a
	// partial report as a success is the one outcome this command must not produce.
	if out != os.Stdout {
		if err := out.Close(); err != nil {
			return fmt.Errorf("close report (it may be incomplete): %w", err)
		}
	}
	return nil
}
