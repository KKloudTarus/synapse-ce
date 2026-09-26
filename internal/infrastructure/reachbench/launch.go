package reachbench

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/toolrunner"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

var errUnsupportedReachbenchPlatform = errors.New("reachability production capture requires linux/amd64")

type lifecycleRunner interface {
	Run(context.Context, []string) (Result, error)
}

// CurrentGoBinaryScorecardResult identifies one sanitized hosted scorecard.
type CurrentGoBinaryScorecardResult struct {
	Path      string
	Scorecard CurrentGoBinaryScorecard
}

type productionLaunchDependencies struct {
	newFixtureMaterializer func(FixtureMaterializerDependencies) (fixtureMaterializer, error)
	newProductionCapture   func(ProductionCaptureDependencies) (CaptureAdapter, error)
	newRunner              func(Dependencies, CaptureAdapter) (lifecycleRunner, error)
}

// RunFromEnvironment is the single no-argument production entrypoint.
func RunFromEnvironment(ctx context.Context, args []string) (Result, error) {
	if err := requireReachbenchPlatform(runtime.GOOS, runtime.GOARCH); err != nil {
		return Result{}, err
	}
	return runWithProductionDependencies(ctx, args, defaultProductionLaunchDependencies())
}

// RunCurrentGoBinaryScorecardFromEnvironment measures the current production
// Go-binary bindings separately from the historical trusted lifecycle assets.
func RunCurrentGoBinaryScorecardFromEnvironment(ctx context.Context) (CurrentGoBinaryScorecardResult, error) {
	if err := requireReachbenchPlatform(runtime.GOOS, runtime.GOARCH); err != nil {
		return CurrentGoBinaryScorecardResult{}, err
	}
	dependencies := DefaultDependencies()
	runner := &Runner{dependencies: dependencies}
	clean, err := currentGoBinarySourceClean(ctx, runner)
	if err != nil {
		return CurrentGoBinaryScorecardResult{}, err
	}
	if !clean {
		return CurrentGoBinaryScorecardResult{}, errors.New("current Go-binary scorecard requires a clean source checkout")
	}
	harness, err := runner.deriveHarness(ctx)
	if err != nil {
		return CurrentGoBinaryScorecardResult{}, fmt.Errorf("derive current Go-binary scorecard source: %w", err)
	}
	runKey, _, err := runner.deriveRunKey()
	if err != nil {
		return CurrentGoBinaryScorecardResult{}, fmt.Errorf("derive current Go-binary scorecard run key: %w", err)
	}
	parts := filepath.FromSlash(runKey)
	root := filepath.Join(os.TempDir(), "synapse-reachability", "current-go-binary", parts)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return CurrentGoBinaryScorecardResult{}, fmt.Errorf("create current Go-binary scorecard root: %w", err)
	}
	scorecard, err := RunCurrentGoBinaryScorecard(ctx, RevisionIdentity{ID: AnalyzerSubjectID, Commit: harness.Commit, Tree: harness.Tree}, os.Getenv("SYNAPSE_GOBIN_BINDING_REPORT_DIR"))
	if err != nil {
		return CurrentGoBinaryScorecardResult{}, err
	}
	path := filepath.Join(root, "scorecard.json")
	if err := WriteCurrentGoBinaryScorecard(path, scorecard); err != nil {
		return CurrentGoBinaryScorecardResult{}, err
	}
	return CurrentGoBinaryScorecardResult{Path: path, Scorecard: scorecard}, nil
}

func requireReachbenchPlatform(goos, goarch string) error {
	if goos != "linux" || goarch != "amd64" {
		return fmt.Errorf("%w: got %s/%s", errUnsupportedReachbenchPlatform, goos, goarch)
	}
	return nil
}

func defaultProductionLaunchDependencies() productionLaunchDependencies {
	return productionLaunchDependencies{
		newFixtureMaterializer: func(dependencies FixtureMaterializerDependencies) (fixtureMaterializer, error) {
			return NewFixtureMaterializer(dependencies)
		},
		newProductionCapture: func(dependencies ProductionCaptureDependencies) (CaptureAdapter, error) {
			return NewProductionCapture(dependencies)
		},
		newRunner: func(dependencies Dependencies, capture CaptureAdapter) (lifecycleRunner, error) {
			return NewRunner(dependencies, capture)
		},
	}
}

func runWithProductionDependencies(ctx context.Context, args []string, dependencies productionLaunchDependencies) (Result, error) {
	cfg := config.Load()
	execRunner := toolrunner.NewExecRunner(0, 0)
	materializer, err := dependencies.newFixtureMaterializer(DefaultFixtureMaterializerDependencies(execRunner))
	if err != nil {
		return Result{}, fmt.Errorf("create reachability fixture materializer: %w", err)
	}
	capture, err := dependencies.newProductionCapture(ProductionCaptureDependencies{
		Materializer:    materializer,
		Fixtures:        measurement.DefaultFixtureManifest(),
		CallGraphBinary: cfg.TaintCallgraphBin,
		ASTBinary:       cfg.ASTBin,
		JVMPointsTo:     cfg.JVMTier2PointsToEnabled(),
	})
	if err != nil {
		return Result{}, fmt.Errorf("create reachability production capture: %w", err)
	}
	runner, err := dependencies.newRunner(DefaultDependencies(), capture)
	if err != nil {
		return Result{}, fmt.Errorf("create reachability runner: %w", err)
	}
	return runner.Run(ctx, args)
}
