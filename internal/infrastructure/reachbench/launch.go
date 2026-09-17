package reachbench

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/toolrunner"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

var errUnsupportedReachbenchPlatform = errors.New("reachability production capture requires linux/amd64")

type lifecycleRunner interface {
	Run(context.Context, []string) (Result, error)
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
		Materializer:             materializer,
		Fixtures:                 measurement.DefaultFixtureManifest(),
		CallGraphBinary:          cfg.TaintCallgraphBin,
		ASTBinary:                cfg.ASTBin,
		JVMPointsTo:              cfg.JVMTier2PointsToEnabled(),
		EnableJSLexicalNegatives: cfg.JSSymbolReachabilityEnabled,
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
