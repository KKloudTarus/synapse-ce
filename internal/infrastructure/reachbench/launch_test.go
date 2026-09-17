package reachbench

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/toolrunner"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

type launchTestMaterializer struct{}

func (launchTestMaterializer) Materialize(_ context.Context, request FixtureMaterializationRequest) (MaterializedFixture, error) {
	return MaterializedFixture{Root: "/private/reachbench-fixture", Specification: request.Specification}, nil
}

type launchTestCapture struct{}

func (launchTestCapture) Capture(context.Context, CaptureRequest) (CaptureResult, error) {
	return CaptureResult{}, nil
}

type launchRunnerFunc func(context.Context, []string) (Result, error)

func (f launchRunnerFunc) Run(ctx context.Context, args []string) (Result, error) {
	return f(ctx, args)
}

func TestRequireReachbenchPlatformRejectsUnsupportedPlatforms(t *testing.T) {
	tests := []struct {
		name   string
		goos   string
		goarch string
	}{
		{name: "non-linux", goos: "darwin", goarch: "amd64"},
		{name: "non-amd64", goos: "linux", goarch: "arm64"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := requireReachbenchPlatform(test.goos, test.goarch)
			if !errors.Is(err, errUnsupportedReachbenchPlatform) {
				t.Fatalf("requireReachbenchPlatform(%q, %q) error = %v, want unsupported-platform error", test.goos, test.goarch, err)
			}
		})
	}

	if err := requireReachbenchPlatform("linux", "amd64"); err != nil {
		t.Fatalf("requireReachbenchPlatform(linux, amd64) error = %v, want nil", err)
	}
}

func TestRunWithProductionDependenciesPropagatesCaptureConfiguration(t *testing.T) {
	t.Setenv("SYNAPSE_TAINT_CALLGRAPH_BIN", "test-callgraph")
	t.Setenv("SYNAPSE_AST_BIN", "test-ast")
	t.Setenv("SYNAPSE_JVM_REACH_TIER2_POINTS_TO_ENABLED", "true")
	t.Setenv("SYNAPSE_JSREACH_TIER2_ENABLED", "true")

	expectedMaterializer := launchTestMaterializer{}
	expectedCapture := launchTestCapture{}
	var materializerDependencies FixtureMaterializerDependencies
	var captureDependencies ProductionCaptureDependencies
	var runnerDependencies Dependencies
	var runnerCapture CaptureAdapter
	var runnerArgs []string

	dependencies := defaultProductionLaunchDependencies()
	dependencies.newFixtureMaterializer = func(got FixtureMaterializerDependencies) (fixtureMaterializer, error) {
		materializerDependencies = got
		return expectedMaterializer, nil
	}
	dependencies.newProductionCapture = func(got ProductionCaptureDependencies) (CaptureAdapter, error) {
		captureDependencies = got
		return expectedCapture, nil
	}
	dependencies.newRunner = func(got Dependencies, capture CaptureAdapter) (lifecycleRunner, error) {
		runnerDependencies = got
		runnerCapture = capture
		return launchRunnerFunc(func(_ context.Context, args []string) (Result, error) {
			runnerArgs = append([]string(nil), args...)
			return Result{}, nil
		}), nil
	}

	args := []string{"--local-diagnostic"}
	if _, err := runWithProductionDependencies(context.Background(), args, dependencies); err != nil {
		t.Fatalf("runWithProductionDependencies() error = %v", err)
	}

	if _, ok := materializerDependencies.ToolRunner.(*toolrunner.ExecRunner); !ok {
		t.Error("fixture materializer did not receive the production exec runner")
	}
	if materializerDependencies.Platform == nil || materializerDependencies.LocateTool == nil {
		t.Error("fixture materializer did not receive default platform dependencies")
	}
	if captureDependencies.Materializer != expectedMaterializer {
		t.Error("production capture did not receive the fixture materializer")
	}
	expectedManifest := measurement.DefaultFixtureManifest()
	if captureDependencies.Fixtures.ID != expectedManifest.ID {
		t.Errorf("production capture fixture manifest = %q, want %q", captureDependencies.Fixtures.ID, expectedManifest.ID)
	}
	if captureDependencies.CallGraphBinary != "test-callgraph" {
		t.Errorf("production capture call graph binary = %q, want test-callgraph", captureDependencies.CallGraphBinary)
	}
	if captureDependencies.ASTBinary != "test-ast" {
		t.Errorf("production capture AST binary = %q, want test-ast", captureDependencies.ASTBinary)
	}
	if !captureDependencies.JVMPointsTo {
		t.Error("production capture did not enable configured JVM points-to analysis")
	}
	if !captureDependencies.EnableJSLexicalNegatives {
		t.Error("production capture did not enable configured JavaScript symbol reachability")
	}
	if runnerDependencies.Command == nil || runnerDependencies.Environment == nil || runnerDependencies.TempRoot == nil || runnerDependencies.RandomSegment == nil {
		t.Error("runner did not receive default dependencies")
	}
	if runnerCapture != expectedCapture {
		t.Error("runner did not receive the production capture")
	}
	if len(runnerArgs) != len(args) || runnerArgs[0] != args[0] {
		t.Errorf("runner arguments = %q, want %q", runnerArgs, args)
	}
}
