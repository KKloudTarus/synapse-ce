// Command synapse-sca-cycle coordinates an auditable SCA evidence cycle.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	capture "github.com/KKloudTarus/synapse-ce/internal/infrastructure/scabench"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/toolrunner"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

type runnerFactory func(capture.RuntimeLimits) (ports.ToolRunner, error)

type stringList []string

func (items *stringList) String() string { return strings.Join(*items, ",") }
func (items *stringList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("path is required")
	}
	*items = append(*items, value)
	return nil
}

func main() {
	os.Exit(executeCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func executeCLI(args []string, stdout, stderr io.Writer) int {
	return executeCLIWithDeps(args, stdout, stderr, productionRunner)
}

func executeCLIWithDeps(args []string, stdout, stderr io.Writer, newRunner runnerFactory) int {
	flags := flag.NewFlagSet("synapse-sca-cycle", flag.ContinueOnError)
	flags.SetOutput(stderr)
	mode := flags.String("mode", "", "cycle mode: sandbox-probe, source-native-evidence, oracle-candidate, oracle-cross-check, oracle-adjudicate, oracle-freeze, prepare, cell, ledger, verify, finalize, or publication")
	repositoryRoot := flags.String("repository-root", "", "absolute repository root for public source verification")
	planPath := flags.String("plan", "", "cycle plan JSON")
	freezePath := flags.String("source-freeze", "", "source freeze JSON")
	candidatePath := flags.String("oracle-candidate", "", "scanner-free oracle candidate JSON")
	crossCheckPath := flags.String("cross-check", "", "automated scanner-blinded cross-check JSON")
	adjudicationPath := flags.String("adjudication", "", "resolved adjudication JSON")
	accountableReviewPath := flags.String("accountable-review", "", "explicit accountable review JSON")
	finalOracleFreezePath := flags.String("final-oracle-freeze", "", "approved final oracle freeze JSON")
	sourceEvidencePath := flags.String("source-case-evidence", "", "generated frozen repository-resolvable source case evidence JSON")
	sourceEvidencePlanPath := flags.String("source-evidence-plan", "", "benchmark-only source evidence selection plan JSON")
	sourceEvidenceOutputPath := flags.String("source-evidence-output", "", "new generated source case evidence JSON")
	nativeEvidencePath := flags.String("native-evidence", "", "generated complete target-native comparison evidence JSON")
	nativeEvidenceOutputPath := flags.String("native-evidence-output", "", "new generated complete target-native comparison evidence JSON")
	oracleOutputPath := flags.String("oracle-output", "", "new scanner-free oracle stage output JSON")
	catalogPath := flags.String("catalog", "", "catalog JSON")
	oraclePath := flags.String("oracle", "", "approved oracle JSON")
	ratchetPath := flags.String("ratchet", "", "ratchet JSON")
	ledgerPath := flags.String("ledger", "", "cycle ledger JSON")
	publicationControlPath := flags.String("publication-control", "", "immutable pre-reduction publication control JSON")
	publicationOutputPath := flags.String("publication-output", "", "new publication manifest JSON")
	manifestPath := flags.String("capture-manifest", "", "capture manifest JSON")
	outputPath := flags.String("output", "", "new cell bundle directory")
	bundlePath := flags.String("bundle", "", "existing bundle directory to validate")
	repetition := flags.Int("repetition", 0, "positive planned repetition")
	retentionLocator := flags.String("retention-locator", "", "protected raw-bundle locator")
	retentionPolicy := flags.String("retention-policy", "", "protected raw-bundle retention policy")
	captureRecordOutput := flags.String("capture-record-output", "", "new machine-readable captured-slot record JSON")
	ledgerOutput := flags.String("ledger-output", "", "new complete cycle ledger JSON")
	resultOutput := flags.String("result-output", "", "new canonical result JSON path")
	reportOutput := flags.String("report-output", "", "new rendered result path")
	comparisonOutput := flags.String("comparison-output", "", "new full-bundle comparison JSON path")
	falsifierOutput := flags.String("falsifier-output", "", "new falsifier result JSON path")
	evidenceSummaryOutput := flags.String("evidence-summary-output", "", "new candidate evidence summary JSON path")
	falsifierSpecPath := flags.String("falsifier-spec", "", "falsifier spec JSON")
	var observationPaths, comparisonPairs, captureRecordPaths stringList
	flags.Var(&observationPaths, "observation", "one normalized observation envelope (repeat for every planned slot)")
	flags.Var(&comparisonPairs, "comparison-pair", "engine,left-bundle,right-bundle (repeat for every planned cell)")
	flags.Var(&captureRecordPaths, "capture-record", "one generated captured-slot record JSON (repeat for every planned slot)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle: positional arguments are not supported")
		return 1
	}
	switch *mode {
	case "sandbox-probe":
		return runSandboxProbe(stdout, stderr, newRunner)
	case "source-native-evidence":
		return runSourceNativeEvidence(*repositoryRoot, *freezePath, *catalogPath, *sourceEvidencePlanPath, *sourceEvidenceOutputPath, *nativeEvidenceOutputPath, stdout, stderr)
	case "oracle-candidate", "oracle-cross-check", "oracle-adjudicate", "oracle-freeze":
		return runOracleStage(*mode, *repositoryRoot, *freezePath, *sourceEvidencePath, *nativeEvidencePath, *candidatePath, *crossCheckPath, *adjudicationPath, *accountableReviewPath, *oraclePath, *oracleOutputPath, stdout, stderr)
	case "prepare":
		if len(observationPaths) != 0 || len(comparisonPairs) != 0 || *sourceEvidencePath != "" || *oracleOutputPath != "" || *catalogPath != "" || *oraclePath != "" || *ratchetPath != "" || *ledgerPath != "" || *publicationControlPath != "" || *publicationOutputPath != "" || *manifestPath != "" || *sourceEvidencePlanPath != "" || *sourceEvidenceOutputPath != "" || *nativeEvidencePath != "" || *nativeEvidenceOutputPath != "" || *captureRecordOutput != "" || *ledgerOutput != "" || len(captureRecordPaths) != 0 || *outputPath != "" || *bundlePath != "" || *repetition != 0 || *retentionLocator != "" || *retentionPolicy != "" || *resultOutput != "" || *reportOutput != "" || *comparisonOutput != "" || *falsifierOutput != "" || *evidenceSummaryOutput != "" || *falsifierSpecPath != "" {
			_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle: prepare accepts source and oracle inputs only")
			return 1
		}
		return runPrepare(*repositoryRoot, *planPath, *freezePath, *candidatePath, *crossCheckPath, *adjudicationPath, *accountableReviewPath, *finalOracleFreezePath, stdout, stderr)
	case "cell":
		return runCell(*repositoryRoot, *planPath, *freezePath, *candidatePath, *crossCheckPath, *adjudicationPath, *accountableReviewPath, *finalOracleFreezePath, *catalogPath, *manifestPath, *nativeEvidencePath, *captureRecordOutput, *outputPath, *repetition, bench.ProtectedBundleDestination{Locator: *retentionLocator, Retention: *retentionPolicy}, stdout, stderr, newRunner)
	case "ledger":
		return runLedger(*planPath, *ledgerOutput, captureRecordPaths, stdout, stderr)
	case "verify":
		return runVerify(*bundlePath, stdout, stderr)
	case "finalize":
		return runFinalize(finalizeInputs{planPath: *planPath, ledgerPath: *ledgerPath, catalogPath: *catalogPath, oraclePath: *oraclePath, ratchetPath: *ratchetPath, resultOutput: *resultOutput, reportOutput: *reportOutput, comparisonOutput: *comparisonOutput, falsifierOutput: *falsifierOutput, falsifierSpecPath: *falsifierSpecPath, observationPaths: observationPaths, comparisonPairs: comparisonPairs}, stdout, stderr)
	case "publication":
		return runPublication(publicationInputs{planPath: *planPath, ledgerPath: *ledgerPath, controlPath: *publicationControlPath, reviewPath: *accountableReviewPath, sourceEvidencePath: *sourceEvidencePath, nativeEvidencePath: *nativeEvidencePath, candidatePath: *candidatePath, crossCheckPath: *crossCheckPath, adjudicationPath: *adjudicationPath, finalOracleFreezePath: *finalOracleFreezePath, ratchetPath: *ratchetPath, comparisonPath: *comparisonOutput, falsifierPath: *falsifierOutput, resultPath: *resultOutput, reportPath: *reportOutput, outputPath: *publicationOutputPath, summaryOutputPath: *evidenceSummaryOutput}, stdout, stderr)
	default:
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle: -mode must select sandbox-probe, source-native-evidence, an oracle stage, prepare, cell, ledger, verify, finalize, or publication")
		return 1
	}
}

func runOracleStage(stage, repositoryRoot, freezePath, sourceEvidencePath, nativeEvidencePath, candidatePath, crossCheckPath, adjudicationPath, reviewPath, oraclePath, outputPath string, stdout, stderr io.Writer) int {
	var record any
	var err error
	switch stage {
	case "oracle-candidate":
		if repositoryRoot == "" || freezePath == "" || sourceEvidencePath == "" || outputPath == "" {
			err = errors.New("oracle-candidate requires -repository-root, -source-freeze, -source-case-evidence, and -oracle-output")
			break
		}
		freeze, freezeErr := decodeSourceFreeze(freezePath)
		if freezeErr != nil {
			err = freezeErr
			break
		}
		source, sourceErr := decodeSourceCaseEvidence(sourceEvidencePath)
		if sourceErr != nil {
			err = sourceErr
			break
		}
		candidate, buildErr := bench.BuildOracleCandidate(freeze, source)
		if buildErr != nil {
			err = buildErr
			break
		}
		if verifyErr := capture.VerifyFreshCycleAssets(repositoryRoot, freeze, candidate); verifyErr != nil {
			err = verifyErr
			break
		}
		record = candidate
	case "oracle-cross-check":
		if sourceEvidencePath == "" || nativeEvidencePath == "" || candidatePath == "" || outputPath == "" {
			err = errors.New("oracle-cross-check requires -source-case-evidence, -native-evidence, -oracle-candidate, and -oracle-output")
			break
		}
		source, sourceErr := decodeSourceCaseEvidence(sourceEvidencePath)
		if sourceErr != nil {
			err = sourceErr
			break
		}
		native, nativeErr := decodeNativeEvidence(nativeEvidencePath)
		if nativeErr != nil {
			err = nativeErr
			break
		}
		candidate, candidateErr := decodeOracleCandidate(candidatePath)
		if candidateErr != nil {
			err = candidateErr
			break
		}
		record, err = bench.BuildAutomatedCrossCheck(source, native, candidate)
	case "oracle-adjudicate":
		if candidatePath == "" || crossCheckPath == "" || outputPath == "" {
			err = errors.New("oracle-adjudicate requires -oracle-candidate, -cross-check, and -oracle-output")
			break
		}
		candidate, candidateErr := decodeOracleCandidate(candidatePath)
		if candidateErr != nil {
			err = candidateErr
			break
		}
		check, checkErr := decodeAutomatedCrossCheck(crossCheckPath)
		if checkErr != nil {
			err = checkErr
			break
		}
		record, err = bench.AdjudicateOracleCandidate(candidate, check)
	case "oracle-freeze":
		if repositoryRoot == "" || freezePath == "" || candidatePath == "" || crossCheckPath == "" || adjudicationPath == "" || reviewPath == "" || oraclePath == "" || outputPath == "" {
			err = errors.New("oracle-freeze requires repository, source, candidate, cross-check, adjudication, accountable review, legacy oracle, and output inputs")
			break
		}
		freeze, freezeErr := decodeSourceFreeze(freezePath)
		if freezeErr != nil {
			err = freezeErr
			break
		}
		candidate, candidateErr := decodeOracleCandidate(candidatePath)
		if candidateErr != nil {
			err = candidateErr
			break
		}
		check, checkErr := decodeAutomatedCrossCheck(crossCheckPath)
		if checkErr != nil {
			err = checkErr
			break
		}
		adjudication, adjudicationErr := decodeAdjudication(adjudicationPath)
		if adjudicationErr != nil {
			err = adjudicationErr
			break
		}
		review, reviewErr := decodeAccountableReview(reviewPath)
		if reviewErr != nil {
			err = reviewErr
			break
		}
		if verifyErr := capture.VerifyAccountableReviewCapture(repositoryRoot, review); verifyErr != nil {
			err = verifyErr
			break
		}
		oracle, oracleErr := decodeOracle(oraclePath)
		if oracleErr != nil {
			err = oracleErr
			break
		}
		finalOracle, freezeErr := bench.FreezeFinalOracle(freeze, candidate, check, adjudication, review, oracle)
		if freezeErr != nil {
			err = freezeErr
			break
		}
		if verifyErr := capture.VerifyFreshCycleAssets(repositoryRoot, freeze, candidate); verifyErr != nil {
			err = verifyErr
			break
		}
		record = finalOracle
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle:", err)
		return 1
	}
	body, err := bench.CanonicalJSON(record)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle:", err)
		return 1
	}
	if err := writeOnce(outputPath, body); err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle:", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "scanner-free oracle stage completed")
	return 0
}

// runSourceNativeEvidence derives scanner-free source cases and all target-native
// comparison predicates from frozen repository assets. The Docker client is used
// only to start the digest-pinned, network-disabled target boundary.
func runSourceNativeEvidence(repositoryRoot, freezePath, catalogPath, planPath, sourceOutputPath, nativeOutputPath string, stdout, stderr io.Writer) int {
	if runtime.GOOS != "linux" {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle: source-native-evidence requires Linux target OCI execution")
		return 1
	}
	if repositoryRoot == "" || freezePath == "" || catalogPath == "" || planPath == "" || sourceOutputPath == "" || nativeOutputPath == "" {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle: source-native-evidence requires -repository-root, -source-freeze, -catalog, -source-evidence-plan, -source-evidence-output, and -native-evidence-output")
		return 1
	}
	if sourceOutputPath == nativeOutputPath {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle: source and native evidence outputs must differ")
		return 1
	}
	for _, path := range []string{sourceOutputPath, nativeOutputPath} {
		if _, err := os.Lstat(path); err == nil {
			_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle: output already exists")
			return 1
		} else if !errors.Is(err, os.ErrNotExist) {
			_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle:", err)
			return 1
		}
	}
	freeze, err := decodeSourceFreeze(freezePath)
	if err == nil {
		var catalog bench.Catalog
		catalog, err = decodeCatalog(catalogPath)
		if err == nil {
			var plan bench.SourceEvidencePlan
			plan, err = decodeSourceEvidencePlan(planPath)
			if err == nil {
				docker := toolrunner.NewExecRunner(2*time.Minute, 1<<20)
				source, native, buildErr := capture.BuildSourceNativeEvidence(context.Background(), repositoryRoot, freeze, catalog, plan, func(target bench.Target) (ports.NativeVersionComparator, error) {
					targetRunner, runnerErr := capture.NewDigestPinnedOCITargetRunner(docker, target.OCIRef, target.Digest)
					if runnerErr != nil {
						return nil, runnerErr
					}
					return capture.NewTargetNativeVersionComparator(targetRunner, target.Digest)
				})
				if buildErr != nil {
					err = buildErr
				} else {
					sourceBody, sourceErr := bench.CanonicalJSON(source)
					nativeBody, nativeErr := bench.CanonicalJSON(native)
					if sourceErr != nil {
						err = sourceErr
					} else if nativeErr != nil {
						err = nativeErr
					} else if writeErr := writeOnce(sourceOutputPath, sourceBody); writeErr != nil {
						err = writeErr
					} else if writeErr := writeOnce(nativeOutputPath, nativeBody); writeErr != nil {
						_ = os.Remove(sourceOutputPath)
						err = writeErr
					}
				}
			}
		}
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle:", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "scanner-free source and target-native evidence generated")
	return 0
}

// runSandboxProbe proves the actual direct-cgroup Bubblewrap path is usable for
// a child process. It intentionally does not inspect the host process Seccomp
// field: the runner installs per-child BPF filters.
func runSandboxProbe(stdout, stderr io.Writer, newRunner runnerFactory) int {
	if runtime.GOOS != "linux" {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle: sandbox probe requires Linux")
		return 1
	}
	runner, err := newRunner(capture.RuntimeLimits{TimeoutSeconds: 10, MaxOutputBytes: 16 << 10, MemoryBytes: 64 << 20, PIDsMax: 16})
	if err == nil {
		_, err = runner.Run(context.Background(), ports.ToolSpec{Name: "/usr/bin/true", Timeout: 5 * time.Second, MaxOutputBytes: 16 << 10, MemMaxBytes: 64 << 20, PidsMax: 16})
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle:", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "direct-cgroup Bubblewrap sandbox probe completed")
	return 0
}

func runPrepare(repositoryRoot, planPath, freezePath, candidatePath, crossCheckPath, adjudicationPath, reviewPath, finalOracleFreezePath string, stdout, stderr io.Writer) int {
	inputs, err := loadFrozenCycleInputs(repositoryRoot, planPath, freezePath, candidatePath, crossCheckPath, adjudicationPath, reviewPath, finalOracleFreezePath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle:", err)
		return 1
	}
	if err := capture.ValidateCycleInputsAtRepository(repositoryRoot, inputs.plan, inputs.freeze, inputs.candidate, inputs.crossCheck, inputs.adjudication, inputs.review, inputs.finalOracle); err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle:", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "cycle inputs prepared")
	return 0
}

func runCell(repositoryRoot, planPath, freezePath, candidatePath, crossCheckPath, adjudicationPath, reviewPath, finalOracleFreezePath, catalogPath, manifestPath, nativeEvidencePath, captureRecordOutput, outputPath string, repetition int, retention bench.ProtectedBundleDestination, stdout, stderr io.Writer, newRunner runnerFactory) int {
	if catalogPath == "" || manifestPath == "" || nativeEvidencePath == "" || captureRecordOutput == "" || outputPath == "" || repetition < 1 || retention.Locator == "" || retention.Retention == "" {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle: cell requires a complete review-gated oracle chain, catalog, capture manifest, generated native evidence, capture record output, bundle output, repetition, and retention fields")
		return 1
	}
	for _, path := range []string{outputPath, captureRecordOutput} {
		if _, err := os.Lstat(path); err == nil {
			_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle: output already exists")
			return 1
		}
	}
	inputs, err := loadFrozenCycleInputs(repositoryRoot, planPath, freezePath, candidatePath, crossCheckPath, adjudicationPath, reviewPath, finalOracleFreezePath)
	var captured capture.CycleCellCapture
	if err == nil {
		err = capture.ValidateCycleInputsAtRepository(repositoryRoot, inputs.plan, inputs.freeze, inputs.candidate, inputs.crossCheck, inputs.adjudication, inputs.review, inputs.finalOracle)
	}
	if err == nil {
		var catalog bench.Catalog
		catalog, err = decodeCatalog(catalogPath)
		if err == nil {
			var manifest capture.CaptureManifest
			manifest, err = decodeCaptureManifest(manifestPath)
			if err == nil {
				var nativeSet bench.NativeEvidenceSet
				nativeSet, err = decodeNativeEvidence(nativeEvidencePath)
				if err == nil {
					var freezeDigest string
					freezeDigest, err = bench.DigestSourceFreeze(inputs.freeze)
					if err == nil && (nativeSet.CycleID != inputs.plan.CycleID || nativeSet.SourceFreezeDigest != freezeDigest) {
						err = errors.New("generated native evidence does not bind the frozen cycle source")
					}
					if err == nil {
						native, exists := nativeSet.Target(manifest.TargetID)
						if !exists {
							err = fmt.Errorf("generated native evidence has no target %q", manifest.TargetID)
						} else {
							var runner ports.ToolRunner
							if manifest.Capability == nil {
								runner, err = newRunner(manifest.Limits)
							}
							if err == nil {
								captured, err = capture.CaptureCycleCell(context.Background(), capture.CycleCellInput{RepositoryRoot: repositoryRoot, SourceFreeze: inputs.freeze, OracleCandidate: inputs.candidate, CrossCheck: inputs.crossCheck, Adjudication: inputs.adjudication, AccountableReview: inputs.review, FinalOracleFreeze: inputs.finalOracle, Plan: inputs.plan, Repetition: repetition, Catalog: catalog, Manifest: manifest, Output: outputPath, Retention: retention, NativeEvidence: native, Runner: runner})
								if err == nil {
									var body []byte
									body, err = bench.CanonicalJSON(captured)
									if err == nil {
										err = writeOnce(captureRecordOutput, body)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle:", err)
		return 1
	}
	switch exitCode := cycleCellExitCode(captured.Outcome); exitCode {
	case 0:
		_, _ = fmt.Fprintln(stdout, "cycle cell captured")
		return 0
	case 2:
		_, _ = fmt.Fprintln(stdout, "cycle cell retained failed attempt")
		return 2
	default:
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle: captured cell has no accepted or retained-failure outcome")
		return 1
	}
}

func cycleCellExitCode(outcome bench.CycleAttemptOutcome) int {
	switch outcome {
	case bench.CycleAttemptAccepted:
		return 0
	case bench.CycleAttemptFailed:
		return 2
	default:
		return 1
	}
}

type frozenCycleInputs struct {
	plan         bench.CyclePlan
	freeze       bench.SourceFreeze
	candidate    bench.OracleCandidate
	crossCheck   bench.AutomatedCrossCheck
	adjudication bench.AdjudicationRecord
	review       bench.AccountableReview
	finalOracle  bench.FinalOracleFreeze
}

func loadFrozenCycleInputs(repositoryRoot, planPath, freezePath, candidatePath, crossCheckPath, adjudicationPath, reviewPath, finalOracleFreezePath string) (frozenCycleInputs, error) {
	if repositoryRoot == "" || planPath == "" || freezePath == "" || candidatePath == "" || crossCheckPath == "" || adjudicationPath == "" || reviewPath == "" || finalOracleFreezePath == "" {
		return frozenCycleInputs{}, errors.New("complete review-gated frozen oracle inputs are required")
	}
	plan, err := decodeCyclePlan(planPath)
	if err != nil {
		return frozenCycleInputs{}, err
	}
	freeze, err := decodeSourceFreeze(freezePath)
	if err != nil {
		return frozenCycleInputs{}, err
	}
	candidate, err := decodeOracleCandidate(candidatePath)
	if err != nil {
		return frozenCycleInputs{}, err
	}
	crossCheck, err := decodeAutomatedCrossCheck(crossCheckPath)
	if err != nil {
		return frozenCycleInputs{}, err
	}
	adjudication, err := decodeAdjudication(adjudicationPath)
	if err != nil {
		return frozenCycleInputs{}, err
	}
	review, err := decodeAccountableReview(reviewPath)
	if err != nil {
		return frozenCycleInputs{}, err
	}
	finalOracle, err := decodeFinalOracleFreeze(finalOracleFreezePath)
	if err != nil {
		return frozenCycleInputs{}, err
	}
	return frozenCycleInputs{plan: plan, freeze: freeze, candidate: candidate, crossCheck: crossCheck, adjudication: adjudication, review: review, finalOracle: finalOracle}, nil
}

func runLedger(planPath, outputPath string, recordPaths stringList, stdout, stderr io.Writer) int {
	if planPath == "" || outputPath == "" || len(recordPaths) == 0 {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle: ledger requires -plan, -ledger-output, and every -capture-record")
		return 1
	}
	if _, err := os.Lstat(outputPath); err == nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle: ledger output already exists")
		return 1
	}
	plan, err := decodeCyclePlan(planPath)
	if err == nil {
		captures := make([]capture.CycleCellCapture, 0, len(recordPaths))
		for _, path := range recordPaths {
			var record capture.CycleCellCapture
			record, err = decodeCycleCellCapture(path)
			if err != nil {
				break
			}
			captures = append(captures, record)
		}
		if err == nil {
			var ledger bench.CycleLedger
			ledger, err = capture.BuildCycleLedger(plan, captures)
			if err == nil {
				var body []byte
				body, err = bench.CanonicalJSON(ledger)
				if err == nil {
					err = writeOnce(outputPath, body)
				}
			}
		}
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle:", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "cycle ledger created")
	return 0
}

func runVerify(bundlePath string, stdout, stderr io.Writer) int {
	if bundlePath == "" {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle: verify requires -bundle")
		return 1
	}
	if err := capture.ValidateBundle(bundlePath); err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle:", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "bundle verified")
	return 0
}

type finalizeInputs struct {
	planPath, ledgerPath, catalogPath, oraclePath, ratchetPath                       string
	resultOutput, reportOutput, comparisonOutput, falsifierOutput, falsifierSpecPath string
	observationPaths, comparisonPairs                                                stringList
}

func runFinalize(input finalizeInputs, stdout, stderr io.Writer) int {
	if input.planPath == "" || input.ledgerPath == "" || input.catalogPath == "" || input.oraclePath == "" || input.ratchetPath == "" || input.resultOutput == "" || input.reportOutput == "" || input.comparisonOutput == "" || input.falsifierOutput == "" || input.falsifierSpecPath == "" {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle: finalize requires cycle records, outputs, and -falsifier-spec")
		return 1
	}
	plan, err := decodeCyclePlan(input.planPath)
	if err == nil {
		var ledger bench.CycleLedger
		ledger, err = decodeCycleLedger(input.ledgerPath)
		if err == nil {
			var catalog bench.Catalog
			catalog, err = decodeCatalog(input.catalogPath)
			if err == nil {
				var oracle bench.Oracle
				oracle, err = decodeOracle(input.oraclePath)
				if err == nil {
					var ratchet bench.Ratchet
					ratchet, err = decodeRatchet(input.ratchetPath)
					if err == nil {
						err = finalizeWithArtifacts(plan, ledger, catalog, oracle, ratchet, input)
					}
				}
			}
		}
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle:", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "cycle finalized")
	return 0
}

func finalizeWithArtifacts(plan bench.CyclePlan, ledger bench.CycleLedger, catalog bench.Catalog, oracle bench.Oracle, ratchet bench.Ratchet, input finalizeInputs) error {
	count := plan.Repetitions * len(plan.Cells)
	if len(input.observationPaths) != count || len(input.comparisonPairs) != len(plan.Cells) {
		return fmt.Errorf("finalize input does not cover every planned observation and comparison")
	}
	repetitions := make([][]bench.Observation, plan.Repetitions)
	for index, path := range input.observationPaths {
		set, err := decodeObservation(path)
		if err != nil || len(set.Observations) != 1 {
			return fmt.Errorf("decode observation %d", index+1)
		}
		repetitions[index/len(plan.Cells)] = append(repetitions[index/len(plan.Cells)], set.Observations[0])
	}
	pairs := make([]capture.BundleComparisonPair, 0, len(input.comparisonPairs))
	for _, text := range input.comparisonPairs {
		engine, left, right, err := parseTriple(text)
		if err != nil {
			return fmt.Errorf("comparison pair: %w", err)
		}
		pairs = append(pairs, capture.BundleComparisonPair{Engine: bench.Engine(engine), LeftPath: left, RightPath: right})
	}
	comparisons, err := capture.CompareCycleBundles(pairs)
	if err != nil {
		return err
	}
	spec, err := decodeFalsifierSpec(input.falsifierSpecPath)
	if err != nil {
		return err
	}
	falsifiers, err := capture.RunFalsifierSpec(spec)
	if err != nil {
		return err
	}
	finalized, err := capture.FinalizeCycle(capture.CycleFinalizationInput{Plan: plan, Ledger: ledger, Catalog: catalog, Oracle: oracle, Ratchet: ratchet, Repetitions: repetitions, Comparisons: comparisons, FalsifierSpec: spec, Falsifiers: falsifiers})
	if err != nil {
		return err
	}
	comparisonBody, err := bench.CanonicalJSON(comparisons)
	if err != nil {
		return err
	}
	falsifierBody, err := bench.CanonicalJSON(falsifiers)
	if err != nil {
		return err
	}
	if err := writeOnce(input.comparisonOutput, comparisonBody); err != nil {
		return err
	}
	if err := writeOnce(input.falsifierOutput, falsifierBody); err != nil {
		return err
	}
	if err := writeOnce(input.resultOutput, finalized.ResultBytes); err != nil {
		return err
	}
	return writeOnce(input.reportOutput, finalized.Rendered)
}

type publicationInputs struct {
	planPath, ledgerPath, controlPath, reviewPath, sourceEvidencePath, nativeEvidencePath string
	candidatePath, crossCheckPath, adjudicationPath, finalOracleFreezePath, ratchetPath   string
	comparisonPath, falsifierPath, resultPath, reportPath, outputPath, summaryOutputPath  string
}

func runPublication(input publicationInputs, stdout, stderr io.Writer) int {
	for _, path := range []string{input.planPath, input.ledgerPath, input.controlPath, input.reviewPath, input.sourceEvidencePath, input.nativeEvidencePath, input.candidatePath, input.crossCheckPath, input.adjudicationPath, input.finalOracleFreezePath, input.ratchetPath, input.comparisonPath, input.falsifierPath, input.resultPath, input.reportPath, input.outputPath, input.summaryOutputPath} {
		if path == "" {
			_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle: publication requires controls, finalized artifacts, and outputs")
			return 1
		}
	}
	plan, err := decodeCyclePlan(input.planPath)
	if err == nil {
		var ledger bench.CycleLedger
		ledger, err = decodeCycleLedger(input.ledgerPath)
		if err == nil {
			var review bench.AccountableReview
			review, err = decodeAccountableReview(input.reviewPath)
			if err == nil {
				var control bench.PublicationControl
				control, err = decodePublicationControl(input.controlPath)
				if err == nil {
					err = verifyControlArtifact(control, "ratchet", input.ratchetPath)
					if err == nil {
						err = writePublication(plan, ledger, review, control, input)
					}
				}
			}
		}
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "synapse-sca-cycle:", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "publication manifest and evidence summary written")
	return 0
}

func writePublication(plan bench.CyclePlan, ledger bench.CycleLedger, review bench.AccountableReview, control bench.PublicationControl, input publicationInputs) error {
	artifactPaths := []struct {
		kind, locator, path string
	}{
		{"source_evidence", "publication/source-case-evidence.json", input.sourceEvidencePath},
		{"native_evidence", "publication/native-evidence.json", input.nativeEvidencePath},
		{"oracle_candidate", "publication/oracle-candidate.json", input.candidatePath},
		{"cross_check", "publication/cross-check.json", input.crossCheckPath},
		{"adjudication", "publication/adjudication.json", input.adjudicationPath},
		{"accountable_review", "publication/accountable-review.json", input.reviewPath},
		{"oracle_freeze", "publication/final-oracle-freeze.json", input.finalOracleFreezePath},
		{"comparison", "publication/comparisons.json", input.comparisonPath},
		{"falsifier_result", "publication/falsifiers.json", input.falsifierPath},
		{"result", "publication/result.json", input.resultPath},
		{"report", "publication/report.md", input.reportPath},
		{"ledger", "publication/cycle-ledger.json", input.ledgerPath},
	}
	generated := make([]bench.PublicationArtifact, 0, len(artifactPaths))
	references := make(map[string]bench.ContentReference, len(artifactPaths))
	for _, artifact := range artifactPaths {
		reference, err := contentReferenceForFile(artifact.locator, artifact.path)
		if err != nil {
			return fmt.Errorf("reference publication artifact %q: %w", artifact.kind, err)
		}
		generated = append(generated, bench.PublicationArtifact{Kind: artifact.kind, Reference: reference})
		references[artifact.kind] = reference
	}
	manifest, err := bench.BuildPublicationManifest(plan, ledger, review, control, generated)
	if err != nil {
		return err
	}
	manifestBody, err := bench.CanonicalJSON(manifest)
	if err != nil {
		return fmt.Errorf("encode publication manifest: %w", err)
	}
	if err := writeOnce(input.outputPath, manifestBody); err != nil {
		return err
	}
	planDigest, err := bench.DigestCyclePlan(plan)
	if err != nil {
		return err
	}
	ledgerDigest, err := bench.DigestCycleLedger(ledger)
	if err != nil {
		return err
	}
	manifestDigest, err := bench.DigestPublicationManifest(manifest)
	if err != nil {
		return err
	}
	bundleDigest, err := bench.DigestBundleEvidence(manifest.Repetitions)
	if err != nil {
		return err
	}
	summary, err := bench.NewCandidateEvidenceSummary(plan.CycleID, plan.FinalOracleDigest, planDigest, ledgerDigest, manifestDigest, bundleDigest, references["comparison"].Digest, references["falsifier_result"].Digest, references["result"].Digest, references["report"].Digest)
	if err != nil {
		return err
	}
	summaryBody, err := bench.CanonicalJSON(summary)
	if err != nil {
		return fmt.Errorf("encode candidate evidence summary: %w", err)
	}
	return writeOnce(input.summaryOutputPath, summaryBody)
}

func verifyControlArtifact(control bench.PublicationControl, kind, path string) error {
	var reference *bench.ContentReference
	for _, artifact := range control.Artifacts {
		if artifact.Kind != kind {
			continue
		}
		if reference != nil {
			return fmt.Errorf("publication control has multiple %q artifacts", kind)
		}
		copy := artifact.Reference
		reference = &copy
	}
	if reference == nil {
		return fmt.Errorf("publication control has no %q artifact", kind)
	}
	actual, err := contentReferenceForFile(reference.Locator, path)
	if err != nil {
		return err
	}
	if actual != *reference {
		return fmt.Errorf("publication control %q artifact does not match its committed content", kind)
	}
	return nil
}

const maxPublicationArtifactBytes int64 = 64 << 20

func contentReferenceForFile(locator, path string) (bench.ContentReference, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return bench.ContentReference{}, fmt.Errorf("inspect artifact: %w", err)
	}
	if !before.Mode().IsRegular() || before.Size() > maxPublicationArtifactBytes {
		return bench.ContentReference{}, errors.New("publication artifact must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return bench.ContentReference{}, fmt.Errorf("open artifact: %w", err)
	}
	hash := sha256.New()
	size, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return bench.ContentReference{}, fmt.Errorf("hash artifact: %w", copyErr)
	}
	if closeErr != nil {
		return bench.ContentReference{}, fmt.Errorf("close artifact: %w", closeErr)
	}
	after, err := os.Lstat(path)
	if err != nil {
		return bench.ContentReference{}, fmt.Errorf("reinspect artifact: %w", err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) || size != before.Size() || after.Size() != before.Size() {
		return bench.ContentReference{}, errors.New("publication artifact changed while it was hashed")
	}
	return bench.ContentReference{Locator: locator, Digest: fmt.Sprintf("sha256:%x", hash.Sum(nil)), Size: size}, nil
}

func parseTriple(value string) (string, string, string, error) {
	parts := strings.Split(value, ",")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("must be name,left-path,right-path")
	}
	for _, part := range parts {
		if strings.TrimSpace(part) == "" || strings.ContainsAny(part, "\r\n") {
			return "", "", "", fmt.Errorf("has an empty or control-bearing field")
		}
	}
	return parts[0], parts[1], parts[2], nil
}

func writeOnce(path string, data []byte) error {
	if path == "" {
		return errors.New("output path is required")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("output already exists")
		}
		return err
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Write(data); err != nil {
		_ = os.Remove(path)
		return err
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		if _, err := file.Write([]byte("\n")); err != nil {
			_ = os.Remove(path)
			return err
		}
	}
	if err := file.Sync(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func decodeCatalog(path string) (bench.Catalog, error) { return decode(path, bench.DecodeCatalog) }
func decodeOracle(path string) (bench.Oracle, error)   { return decode(path, bench.DecodeOracle) }
func decodeRatchet(path string) (bench.Ratchet, error) { return decode(path, bench.DecodeRatchet) }
func decodeObservation(path string) (bench.ObservationSet, error) {
	return decode(path, bench.DecodeObservationSet)
}
func decodeCyclePlan(path string) (bench.CyclePlan, error) {
	return decode(path, bench.DecodeCyclePlan)
}
func decodeCycleLedger(path string) (bench.CycleLedger, error) {
	return decode(path, bench.DecodeCycleLedger)
}
func decodeSourceFreeze(path string) (bench.SourceFreeze, error) {
	return decode(path, bench.DecodeSourceFreeze)
}
func decodeOracleCandidate(path string) (bench.OracleCandidate, error) {
	return decode(path, bench.DecodeOracleCandidate)
}

func decodeAutomatedCrossCheck(path string) (bench.AutomatedCrossCheck, error) {
	return decode(path, bench.DecodeAutomatedCrossCheck)
}
func decodeAdjudication(path string) (bench.AdjudicationRecord, error) {
	return decode(path, bench.DecodeAdjudicationRecord)
}
func decodeAccountableReview(path string) (bench.AccountableReview, error) {
	return decode(path, bench.DecodeAccountableReview)
}
func decodeFinalOracleFreeze(path string) (bench.FinalOracleFreeze, error) {
	return decode(path, bench.DecodeFinalOracleFreeze)
}

func decodeSourceCaseEvidence(path string) (bench.SourceCaseEvidenceSet, error) {
	return decode(path, bench.DecodeSourceCaseEvidence)
}

func decodeSourceEvidencePlan(path string) (bench.SourceEvidencePlan, error) {
	return decode(path, bench.DecodeSourceEvidencePlan)
}

func decodeNativeEvidence(path string) (bench.NativeEvidenceSet, error) {
	return decode(path, bench.DecodeNativeEvidenceSet)
}
func decodePublicationControl(path string) (bench.PublicationControl, error) {
	return decode(path, bench.DecodePublicationControl)
}
func decodeFalsifierSpec(path string) (bench.FalsifierSpec, error) {
	return decode(path, bench.DecodeFalsifierSpec)
}
func decodeCaptureManifest(path string) (capture.CaptureManifest, error) {
	return decode(path, capture.DecodeCaptureManifest)
}

func decodeCycleCellCapture(path string) (capture.CycleCellCapture, error) {
	file, err := os.Open(path)
	if err != nil {
		return capture.CycleCellCapture{}, err
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(io.LimitReader(file, 8<<20))
	decoder.DisallowUnknownFields()
	var record capture.CycleCellCapture
	if err := decoder.Decode(&record); err != nil {
		return capture.CycleCellCapture{}, fmt.Errorf("decode captured slot record: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return capture.CycleCellCapture{}, errors.New("captured slot record contains trailing data")
	}
	return record, nil
}

func decode[T any](path string, parse func(io.Reader) (T, error)) (T, error) {
	var zero T
	file, err := os.Open(path)
	if err != nil {
		return zero, err
	}
	defer func() { _ = file.Close() }()
	return parse(file)
}

func productionRunner(limits capture.RuntimeLimits) (ports.ToolRunner, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("hardened sandbox requires Linux")
	}
	delegatedRoot := os.Getenv("SCA_ACCURACY_DELEGATED_CGROUP_ROOT")
	if strings.TrimSpace(delegatedRoot) == "" {
		return nil, errors.New("hardened sandbox requires SCA_ACCURACY_DELEGATED_CGROUP_ROOT captured from the delegated service")
	}
	ready, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	runner, err := sandbox.NewDirectCgroupRunnerReadyAt(ready, time.Duration(limits.TimeoutSeconds)*time.Second, limits.MaxOutputBytes, limits.MemoryBytes, limits.PIDsMax, 250*time.Millisecond, delegatedRoot)
	if err != nil {
		return nil, err
	}
	if runner.ControlSetIdentity() != capture.SandboxIdentityBubblewrapSeccompCgroupV2 {
		return nil, errors.New("required sandbox control set is unavailable")
	}
	return runner, nil
}
