package reachbench

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

type runtimeFacts struct {
	repositoryRoot     string
	checkoutBundleRoot string
	temporaryRoot      string
	rawRoot            string
	outputRoot         string
	output             string
	controllerRoot     string
	runKey             string
	harness            HarnessIdentity
}

func DefaultDependencies() Dependencies {
	return Dependencies{
		Command: func(ctx context.Context, binary string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, binary, args...).Output()
		},
		Environment: os.LookupEnv,
		TempRoot:    os.TempDir,
		RandomSegment: func() (string, error) {
			bytes := make([]byte, 16)
			if _, err := rand.Read(bytes); err != nil {
				return "", err
			}
			return hex.EncodeToString(bytes), nil
		},
	}
}

func (runner *Runner) deriveRuntime(ctx context.Context) (runtimeFacts, error) {
	rootOutput, err := runner.dependencies.Command(ctx, "git", "rev-parse", "--show-toplevel")
	if err != nil {
		return runtimeFacts{}, fmt.Errorf("derive repository root with git argv: %w", err)
	}
	repositoryRoot, err := benchcycle.RealDirectory(strings.TrimSpace(string(rootOutput)))
	if err != nil {
		return runtimeFacts{}, fmt.Errorf("validate derived repository root: %w", err)
	}
	harness, err := runner.deriveHarness(ctx)
	if err != nil {
		return runtimeFacts{}, err
	}
	runKey, _, err := runner.deriveRunKey()
	if err != nil {
		return runtimeFacts{}, err
	}
	temporaryRoot, err := benchcycle.RealDirectory(runner.dependencies.TempRoot())
	if err != nil {
		return runtimeFacts{}, fmt.Errorf("validate trusted temporary root: %w", err)
	}
	rawRoot, outputRoot, err := prepareTemporaryRoots(temporaryRoot)
	if err != nil {
		return runtimeFacts{}, err
	}
	parts := strings.Split(runKey, "/")
	output := filepath.Join(outputRoot, parts[0], parts[1])
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		return runtimeFacts{}, fmt.Errorf("create trusted reachability output parent: %w", err)
	}
	if _, err := benchcycle.RealDirectory(filepath.Dir(output)); err != nil {
		return runtimeFacts{}, fmt.Errorf("validate trusted reachability output parent: %w", err)
	}
	if err := benchcycle.EnsureAbsent(output, "reachability output bundle"); err != nil {
		return runtimeFacts{}, err
	}
	return runtimeFacts{
		repositoryRoot:     repositoryRoot,
		checkoutBundleRoot: filepath.Join(repositoryRoot, filepath.FromSlash(TrustedBundleRelativePath)),
		temporaryRoot:      temporaryRoot,
		rawRoot:            rawRoot,
		outputRoot:         outputRoot,
		output:             output,
		controllerRoot:     filepath.Join(temporaryRoot, filepath.FromSlash(controllerRootDirectory)),
		runKey:             runKey,
		harness:            harness,
	}, nil
}

func (runner *Runner) deriveHarness(ctx context.Context) (HarnessIdentity, error) {
	commit, err := runner.gitSHA(ctx, "HEAD")
	if err != nil {
		return HarnessIdentity{}, fmt.Errorf("derive harness commit: %w", err)
	}
	tree, err := runner.gitSHA(ctx, "HEAD^{tree}")
	if err != nil {
		return HarnessIdentity{}, fmt.Errorf("derive harness tree: %w", err)
	}
	harness := HarnessIdentity{ID: ReviewedHarnessID, Commit: commit, Tree: tree}
	if err := validateHarness(harness); err != nil {
		return HarnessIdentity{}, err
	}
	return harness, nil
}

func (runner *Runner) deriveTrustedBaselineAnalyzer(ctx context.Context) (RevisionIdentity, error) {
	commit, err := runner.gitSHA(ctx, measurement.TrustedBaselineRevision)
	if err != nil {
		return RevisionIdentity{}, fmt.Errorf("derive trusted baseline analyzer commit: %w", err)
	}
	if commit != measurement.TrustedBaselineRevision {
		return RevisionIdentity{}, errors.New("derived trusted baseline analyzer commit does not match fixed revision")
	}
	tree, err := runner.gitSHA(ctx, measurement.TrustedBaselineRevision+"^{tree}")
	if err != nil {
		return RevisionIdentity{}, fmt.Errorf("derive trusted baseline analyzer tree: %w", err)
	}
	analyzer := RevisionIdentity{ID: AnalyzerSubjectID, Commit: commit, Tree: tree}
	if err := validateRevision(analyzer); err != nil {
		return RevisionIdentity{}, err
	}
	return analyzer, nil
}

func (runner *Runner) gitSHA(ctx context.Context, revision string) (string, error) {
	output, err := runner.dependencies.Command(ctx, "git", "rev-parse", revision)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(output))
	if !benchcycle.FullSHA(value) {
		return "", errors.New("git did not return a lowercase full SHA")
	}
	return value, nil
}

func (runner *Runner) deriveRunKey() (string, bool, error) {
	runID, runOK := runner.dependencies.Environment("GITHUB_RUN_ID")
	attempt, attemptOK := runner.dependencies.Environment("GITHUB_RUN_ATTEMPT")
	if runOK != attemptOK {
		return "", false, errors.New("GitHub run identity requires both run ID and attempt")
	}
	if runOK {
		if !decimalSegment(runID) || !decimalSegment(attempt) {
			return "", false, errors.New("GitHub run identity must contain bounded decimal run ID and attempt")
		}
		key := "github-" + runID + "/attempt-" + attempt
		if err := benchcycle.ValidateRunKey(key); err != nil {
			return "", false, err
		}
		return key, false, nil
	}
	segment, err := runner.dependencies.RandomSegment()
	if err != nil {
		return "", false, fmt.Errorf("generate local diagnostic run identity: %w", err)
	}
	key := "local/" + segment
	if err := benchcycle.ValidateRunKey(key); err != nil {
		return "", false, fmt.Errorf("validate local diagnostic run identity: %w", err)
	}
	return key, true, nil
}

func prepareTemporaryRoots(temporaryRoot string) (string, string, error) {
	rawRoot := filepath.Join(temporaryRoot, filepath.FromSlash(privateRunDirectory))
	outputRoot := filepath.Join(temporaryRoot, filepath.FromSlash(publishedRunDirectory))
	for _, path := range []string{rawRoot, outputRoot} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return "", "", fmt.Errorf("create trusted temporary root: %w", err)
		}
		if _, err := benchcycle.RealDirectory(path); err != nil {
			return "", "", fmt.Errorf("validate trusted temporary root: %w", err)
		}
	}
	return rawRoot, outputRoot, nil
}

func decimalSegment(value string) bool {
	if value == "" || len(value) > 80 {
		return false
	}
	for _, item := range value {
		if item < '0' || item > '9' {
			return false
		}
	}
	return true
}

func (runner *Runner) loadBundle(root string) (TrustedBundle, measurement.ArtifactReference, error) {
	path, err := benchcycle.BelowRoot(root, "trusted-bundle.json")
	if err != nil {
		return TrustedBundle{}, measurement.ArtifactReference{}, fmt.Errorf("resolve trusted bundle: %w", err)
	}
	var bundle TrustedBundle
	encoded, err := readCanonicalJSON(path, &bundle)
	if err != nil {
		return TrustedBundle{}, measurement.ArtifactReference{}, fmt.Errorf("read trusted bundle: %w", err)
	}
	if err := bundle.Validate(); err != nil {
		return TrustedBundle{}, measurement.ArtifactReference{}, err
	}
	return bundle, measurement.ArtifactReference{ID: bundle.ID, Digest: benchmark.SHA256Digest(encoded)}, nil
}

func (runner *Runner) loadControllerEnvelope(facts runtimeFacts) (RunEnvelope, error) {
	path, present := runner.dependencies.Environment(ControllerEnvelopeEnvironment)
	if !present || strings.TrimSpace(path) == "" {
		return RunEnvelope{}, errors.New("controller envelope path is absent")
	}
	if _, err := benchcycle.RealDirectory(facts.controllerRoot); err != nil {
		return RunEnvelope{}, fmt.Errorf("validate controller root: %w", err)
	}
	envelopeRoot, err := benchcycle.RealDirectory(filepath.Join(facts.controllerRoot, "envelopes"))
	if err != nil {
		return RunEnvelope{}, fmt.Errorf("validate controller envelope root: %w", err)
	}
	relative, err := filepath.Rel(envelopeRoot, path)
	if err != nil {
		return RunEnvelope{}, fmt.Errorf("resolve controller envelope path: %w", err)
	}
	envelopePath, err := benchcycle.BelowRoot(envelopeRoot, filepath.ToSlash(relative))
	if err != nil {
		return RunEnvelope{}, fmt.Errorf("controller envelope path is not a trusted regular file: %w", err)
	}
	var envelope RunEnvelope
	if _, err := readCanonicalJSON(envelopePath, &envelope); err != nil {
		return RunEnvelope{}, fmt.Errorf("read controller envelope: %w", err)
	}
	if err := envelope.Validate(); err != nil {
		return RunEnvelope{}, err
	}
	return envelope, nil
}

func controllerBundleRoot(facts runtimeFacts) (string, error) {
	root, err := benchcycle.RealDirectory(filepath.Join(facts.controllerRoot, "trusted-bundle"))
	if err != nil {
		return "", fmt.Errorf("validate controller-owned trusted bundle root: %w", err)
	}
	return root, nil
}

func checkoutBundleRoot(facts runtimeFacts) (string, error) {
	root, err := benchcycle.RealDirectory(facts.checkoutBundleRoot)
	if err != nil {
		return "", fmt.Errorf("validate checkout-relative diagnostic bundle root: %w", err)
	}
	return root, nil
}

func localEnvelope(facts runtimeFacts, bundle measurement.ArtifactReference, snapshot measurement.SnapshotIdentity) RunEnvelope {
	return RunEnvelope{
		SchemaVersion: EnvelopeSchemaVersion,
		Route:         RouteLocalDiagnostic,
		Purpose:       measurement.CandidateAcceptance,
		FinalMode:     FinalDiagnostic,
		Harness:       facts.harness,
		Analyzer:      RevisionIdentity{ID: AnalyzerSubjectID, Commit: facts.harness.Commit, Tree: facts.harness.Tree},
		Snapshot:      snapshot,
		Bundle:        bundle,
	}
}
