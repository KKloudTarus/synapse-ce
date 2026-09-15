package main

import (
	"flag"
	"fmt"
	"os"
)

type options struct {
	mode string

	repositoryRoot           string
	sourceFreezeTemplate     string
	sourcePlanTemplate       string
	sourceFreezeOutput       string
	sourcePlanOutput         string
	catalog                  string
	catalogOutput            string
	oracle                   string
	ratchet                  string
	binaryReference          string
	binaryPath               string
	engine                   string
	manifestTemplateDir      string
	manifestOutputDir        string
	capabilityOutputDir      string
	sbomRoot                 string
	baselineRatchet          string
	baselineResult           string
	ratchetOutput            string
	reviewCaptureLocator     string
	reviewCaptureOutput      string
	adjudication             string
	reviewOutput             string
	oracleCandidate          string
	crossCheck               string
	accountableReview        string
	finalOracleFreeze        string
	cyclePolicy              string
	planOutput               string
	candidateRoot            string
	implementationCommit     string
	publicationControlOutput string
	rawRetentionRoot         string
	runID                    string
	runAttempt               string
	cleanupOutput            string
	dockerBinary             string
	ledger                   string
	result                   string
	publicationManifest      string
	cleanupReceipt           string
	receiptOutput            string
	inventoryOutput          string
	markdownOutput           string
	artifactName             string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "synapse-sca-inputs:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	var option options
	flags := flag.NewFlagSet("synapse-sca-inputs", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.StringVar(&option.mode, "mode", "", "materialization mode")
	flags.StringVar(&option.repositoryRoot, "repository-root", "", "trusted repository asset root")
	flags.StringVar(&option.sourceFreezeTemplate, "source-freeze-template", "", "source freeze template")
	flags.StringVar(&option.sourcePlanTemplate, "source-plan-template", "", "source evidence plan template")
	flags.StringVar(&option.sourceFreezeOutput, "source-freeze-output", "", "generated source freeze")
	flags.StringVar(&option.sourcePlanOutput, "source-plan-output", "", "generated source evidence plan")
	flags.StringVar(&option.catalog, "catalog", "", "benchmark catalog")
	flags.StringVar(&option.catalogOutput, "catalog-output", "", "generated benchmark catalog")
	flags.StringVar(&option.oracle, "oracle", "", "benchmark oracle")
	flags.StringVar(&option.ratchet, "ratchet", "", "strict ratchet")
	flags.StringVar(&option.binaryReference, "binary-reference", "", "catalog reference for the benchmark binary")
	flags.StringVar(&option.binaryPath, "binary-path", "", "built benchmark binary")
	flags.StringVar(&option.engine, "engine", "", "engine whose ratchet identities use the binary")
	flags.StringVar(&option.manifestTemplateDir, "manifest-template-dir", "", "capture manifest template directory")
	flags.StringVar(&option.manifestOutputDir, "manifest-output-dir", "", "generated manifest directory")
	flags.StringVar(&option.capabilityOutputDir, "capability-output-dir", "", "generated capability statement directory")
	flags.StringVar(&option.sbomRoot, "sbom-root", "", "canonical SBOM directory")
	flags.StringVar(&option.baselineRatchet, "baseline-ratchet", "", "ratchet used by the validated baseline")
	flags.StringVar(&option.baselineResult, "baseline-result", "", "validated baseline result")
	flags.StringVar(&option.ratchetOutput, "ratchet-output", "", "generated strict ratchet")
	flags.StringVar(&option.reviewCaptureLocator, "review-capture-locator", "", "repository-relative sanitized review capture")
	flags.StringVar(&option.reviewCaptureOutput, "review-capture-output", "", "retained sanitized review capture")
	flags.StringVar(&option.adjudication, "adjudication", "", "adjudication record")
	flags.StringVar(&option.reviewOutput, "review-output", "", "generated accountable review")
	flags.StringVar(&option.oracleCandidate, "oracle-candidate", "", "oracle candidate")
	flags.StringVar(&option.crossCheck, "cross-check", "", "automated cross-check")
	flags.StringVar(&option.accountableReview, "accountable-review", "", "accountable review")
	flags.StringVar(&option.finalOracleFreeze, "final-oracle-freeze", "", "final oracle freeze")
	flags.StringVar(&option.cyclePolicy, "cycle-policy", "", "cycle policy")
	flags.StringVar(&option.planOutput, "plan-output", "", "generated cycle plan")
	flags.StringVar(&option.candidateRoot, "candidate-root", "", "sanitized candidate root")
	flags.StringVar(&option.implementationCommit, "implementation-commit", "", "exact implementation commit")
	flags.StringVar(&option.publicationControlOutput, "publication-control-output", "", "generated publication control")
	flags.StringVar(&option.rawRetentionRoot, "raw-retention-root", "", "protected raw retention root")
	flags.StringVar(&option.runID, "run-id", "", "trusted run identifier")
	flags.StringVar(&option.runAttempt, "run-attempt", "", "trusted run attempt")
	flags.StringVar(&option.cleanupOutput, "cleanup-output", "", "generated cleanup receipt")
	flags.StringVar(&option.dockerBinary, "docker-binary", "docker", "Docker CLI path")
	flags.StringVar(&option.ledger, "ledger", "", "cycle ledger")
	flags.StringVar(&option.result, "result", "", "benchmark result")
	flags.StringVar(&option.publicationManifest, "publication-manifest", "", "publication manifest")
	flags.StringVar(&option.cleanupReceipt, "cleanup-receipt", "", "cleanup receipt")
	flags.StringVar(&option.receiptOutput, "receipt-output", "", "generated candidate receipt")
	flags.StringVar(&option.inventoryOutput, "inventory-output", "", "generated candidate inventory")
	flags.StringVar(&option.markdownOutput, "markdown-output", "", "generated audit-safe Markdown summary")
	flags.StringVar(&option.artifactName, "artifact-name", "", "accepted Actions artifact name")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}

	switch option.mode {
	case "source-freeze":
		return materializeSourceFreeze(option)
	case "binary-pin":
		return materializeBinaryPin(option)
	case "manifest-set":
		return materializeManifestSet(option)
	case "ratchet":
		return materializeRatchet(option)
	case "accountable-review":
		return materializeAccountableReview(option)
	case "plan":
		return materializePlan(option)
	case "publication-control":
		return materializePublicationControl(option)
	case "cleanup":
		return cleanupRunnerState(option)
	case "receipt":
		return materializeCandidateReceipt(option)
	default:
		return fmt.Errorf("unsupported mode %q", option.mode)
	}
}
