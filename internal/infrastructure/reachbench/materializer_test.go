package reachbench

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	reachcontract "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

type fixtureToolRunner struct {
	mu    sync.Mutex
	calls []ports.ToolSpec
	run   func(context.Context, ports.ToolSpec) (ports.ToolResult, error)
}

func (runner *fixtureToolRunner) Run(ctx context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	runner.mu.Lock()
	runner.calls = append(runner.calls, cloneToolSpec(spec))
	runner.mu.Unlock()
	if runner.run == nil {
		return ports.ToolResult{}, nil
	}
	return runner.run(ctx, spec)
}

func (runner *fixtureToolRunner) Calls() []ports.ToolSpec {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return append([]ports.ToolSpec(nil), runner.calls...)
}

func TestFixtureMaterializerCopiesNonBuildFixtureAtMaterializedPaths(t *testing.T) {
	runner := &fixtureToolRunner{}
	materializer := newFixtureMaterializer(t, runner, "linux/amd64")
	specification := materializerFixture(t, "go-source-tier2-input")
	workRoot := privateMaterializerRoot(t)

	fixture, err := materializer.Materialize(context.Background(), FixtureMaterializationRequest{
		Specification: specification,
		WorkRoot:      workRoot,
		CellKey:       "sha256:" + strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if len(runner.Calls()) != 0 {
		t.Fatalf("non-build fixture invoked tool runner: %+v", runner.Calls())
	}
	if len(fixture.Outputs) != 0 {
		t.Fatalf("non-build outputs = %+v, want none", fixture.Outputs)
	}
	for _, file := range specification.Files {
		path, err := fixture.ResolveInput(file.Path)
		if err != nil {
			t.Fatalf("ResolveInput(%q): %v", file.Path, err)
		}
		relative, err := filepath.Rel(fixture.Root, path)
		if err != nil {
			t.Fatalf("relative input path: %v", err)
		}
		want := file.Path
		if file.MaterializedPath != "" {
			want = file.MaterializedPath
		}
		if got := filepath.ToSlash(relative); got != want {
			t.Errorf("materialized path = %q, want %q", got, want)
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read materialized input: %v", err)
		}
		if got := benchmark.SHA256Digest(contents); got != file.Digest {
			t.Errorf("materialized input digest = %q, want %q", got, file.Digest)
		}
	}
	if _, err := fixture.ResolveInput("fixtures/unknown"); err == nil {
		t.Fatal("ResolveInput accepted an undeclared path")
	}
}

func TestFixtureMaterializerBuildsFrozenGeneratedFixture(t *testing.T) {
	workRoot := privateMaterializerRoot(t)
	specification := materializerFixture(t, "go-binary-input")
	runner := &fixtureToolRunner{}
	materializer := newFixtureMaterializer(t, runner, "linux/amd64")
	runner.run = func(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
		root, args, ok := materializerGoInvocation(spec)
		if !ok {
			return ports.ToolResult{}, fmt.Errorf("unexpected tool specification %+v", spec)
		}
		switch {
		case reflect.DeepEqual(args, []string{"version"}):
			return ports.ToolResult{Stdout: []byte("go version go1.27.0 linux/amd64\n")}, nil
		case reflect.DeepEqual(args, specification.Build.Steps[0].Argv[1:]):
			path := filepath.Join(root, filepath.FromSlash(specification.Build.Outputs[0].Path))
			if err := os.WriteFile(path, []byte("generated binary fixture"), 0o600); err != nil {
				return ports.ToolResult{}, err
			}
			return ports.ToolResult{}, nil
		default:
			return ports.ToolResult{}, fmt.Errorf("unexpected tool specification %+v", spec)
		}
	}

	fixture, err := materializer.Materialize(context.Background(), FixtureMaterializationRequest{
		Specification: specification,
		WorkRoot:      workRoot,
		CellKey:       "sha256:" + strings.Repeat("b", 64),
	})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	calls := runner.Calls()
	if len(calls) != 2 {
		t.Fatalf("tool calls = %d, want probe and build", len(calls))
	}
	for index, call := range calls {
		if call.Workdir != "" {
			t.Errorf("tool call %d workdir = %q, want empty", index+1, call.Workdir)
		}
	}
	root, buildArgs, ok := materializerGoInvocation(calls[1])
	if !ok || calls[1].Name != specification.Build.Steps[0].Argv[0] || !reflect.DeepEqual(buildArgs, specification.Build.Steps[0].Argv[1:]) {
		t.Errorf("build argv = %q %q, want Go -C <root> %q", calls[1].Name, calls[1].Args, specification.Build.Steps[0].Argv[1:])
	}
	if root != fixture.Root {
		t.Errorf("Go build root = %q, want %q", root, fixture.Root)
	}
	environment := toolEnvironment(calls[1].Env)
	for key, want := range map[string]string{
		"CGO_ENABLED": "0",
		"GOOS":        "linux",
		"GOARCH":      "amd64",
		"GOWORK":      "off",
		"GOTOOLCHAIN": "local",
		"GOPROXY":     "off",
		"GOSUMDB":     "off",
		"TZ":          "UTC",
		"LC_ALL":      "C",
	} {
		if got := environment[key]; got != want {
			t.Errorf("environment %s = %q, want %q", key, got, want)
		}
	}
	if environment["HOME"] == "" || !strings.HasPrefix(environment["HOME"], fixture.Root) {
		t.Errorf("HOME = %q, want workspace-local path", environment["HOME"])
	}
	if len(fixture.Outputs) != 1 || fixture.Outputs[0].Path != specification.Build.Outputs[0].Path {
		t.Fatalf("outputs = %+v", fixture.Outputs)
	}
	output, err := fixture.ResolveOutput(specification.Build.Outputs[0].Path)
	if err != nil {
		t.Fatalf("ResolveOutput: %v", err)
	}
	contents, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if got := benchmark.SHA256Digest(contents); got != fixture.Outputs[0].Digest {
		t.Errorf("output digest = %q, want %q", got, fixture.Outputs[0].Digest)
	}
}

func TestFixtureMaterializerBuildsEveryFrozenToolFormWithoutRunnerWorkdir(t *testing.T) {
	for _, fixtureID := range []string{
		"go-binary-input",
		"dotnet-build-aware-import-input",
		"dotnet-symbols-tier2-input",
		"jvm-coarse-input",
		"jvm-tier2-input",
	} {
		t.Run(fixtureID, func(t *testing.T) {
			specification := materializerFixture(t, fixtureID)
			workRoot := privateMaterializerRoot(t)
			cellKey := "sha256:" + strings.Repeat("a", 64)
			expectedRoot, err := prepareMaterializationRoot(workRoot, cellKey)
			if err != nil {
				t.Fatalf("prepare materialization root: %v", err)
			}
			runner := &fixtureToolRunner{}
			materializer := newFixtureMaterializer(t, runner, "linux/amd64")
			runner.run = func(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
				if isFixtureToolchainProbe(specification.Build.Toolchain.Family, spec) {
					return matchingFixtureToolchainProbe(specification.Build.Toolchain.Family), nil
				}
				for _, output := range specification.Build.Outputs {
					path := filepath.Join(expectedRoot, filepath.FromSlash(output.Path))
					if err := os.WriteFile(path, []byte("generated "+fixtureID), 0o600); err != nil {
						return ports.ToolResult{}, err
					}
				}
				return ports.ToolResult{}, nil
			}

			fixture, err := materializer.Materialize(context.Background(), FixtureMaterializationRequest{
				Specification: specification,
				WorkRoot:      workRoot,
				CellKey:       cellKey,
			})
			if err != nil {
				t.Fatalf("Materialize: %v", err)
			}
			calls := runner.Calls()
			if len(calls) != len(specification.Build.Steps)+1 {
				t.Fatalf("tool calls = %d, want %d", len(calls), len(specification.Build.Steps)+1)
			}
			for index, call := range calls {
				if call.Workdir != "" {
					t.Errorf("tool call %d workdir = %q, want empty", index+1, call.Workdir)
				}
			}
			assertFrozenFixtureInvocations(t, fixture.Root, specification.Build, calls)
		})
	}
}

func TestFrozenFixturePathRewritingFailsClosed(t *testing.T) {
	root := privateMaterializerRoot(t)
	unsafe := materializerFixture(t, "dotnet-symbols-tier2-input")
	unsafe.Build.Steps = []reachcontract.FixtureBuildStep{{Argv: []string{"dotnet", "restore", "./../outside"}}}
	if _, _, err := buildToolInvocation(root, unsafe, unsafe.Build.Steps[0]); err == nil {
		t.Fatal("build invocation accepted a path that escapes the materialization root")
	}
	if _, err := resolveFrozenRootRelativePath(root, "fixtures/not-root-relative"); err == nil {
		t.Fatal("root-relative resolver accepted a non-frozen path form")
	}
	if _, err := resolveFrozenRootRelativePath(root, "./../outside"); err == nil {
		t.Fatal("root-relative resolver accepted a path that escapes the materialization root")
	}
	if err := os.Mkdir(filepath.Join(root, "generated"), 0o700); err != nil {
		t.Fatalf("create classpath parent: %v", err)
	}
	if _, err := rewriteFrozenRootRelativeArg(root, "./generated/a:generated/b"); err == nil {
		t.Fatal("JVM classpath rewriting accepted a non-root-relative vector entry")
	}
	jvm := materializerFixture(t, "jvm-coarse-input")
	if _, _, err := buildToolInvocation(root, jvm, reachcontract.FixtureBuildStep{Argv: []string{"dotnet", "restore"}}); err == nil {
		t.Fatal("JVM build invocation accepted a non-frozen tool form")
	}
}

func TestFixtureMaterializerReusesStableCellRootAndClearsPriorContents(t *testing.T) {
	materializer := newFixtureMaterializer(t, &fixtureToolRunner{}, "linux/amd64")
	request := FixtureMaterializationRequest{
		Specification: materializerFixture(t, "go-source-tier2-input"),
		WorkRoot:      privateMaterializerRoot(t),
		CellKey:       "sha256:" + strings.Repeat("c", 64),
	}
	first, err := materializer.Materialize(context.Background(), request)
	if err != nil {
		t.Fatalf("first materialization: %v", err)
	}
	stale := filepath.Join(first.Root, "stale")
	if err := os.WriteFile(stale, []byte("remove me"), 0o600); err != nil {
		t.Fatalf("write stale file: %v", err)
	}
	second, err := materializer.Materialize(context.Background(), request)
	if err != nil {
		t.Fatalf("second materialization: %v", err)
	}
	if first.Root != second.Root {
		t.Errorf("roots differ: %q != %q", first.Root, second.Root)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Errorf("stale path remains or could not be inspected: %v", err)
	}
}

func TestFixtureMaterializerRejectsUnsupportedBuildPlatform(t *testing.T) {
	runner := &fixtureToolRunner{}
	materializer := newFixtureMaterializer(t, runner, "darwin/arm64")
	_, err := materializer.Materialize(context.Background(), FixtureMaterializationRequest{
		Specification: materializerFixture(t, "go-binary-input"),
		WorkRoot:      privateMaterializerRoot(t),
		CellKey:       "sha256:" + strings.Repeat("d", 64),
	})
	if err == nil {
		t.Fatal("Materialize accepted unsupported platform")
	}
	if len(runner.Calls()) != 0 {
		t.Fatalf("platform rejection ran tools: %+v", runner.Calls())
	}
}

func TestFixtureMaterializerRejectsToolchainVersionMismatch(t *testing.T) {
	runner := &fixtureToolRunner{run: func(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
		_, args, ok := materializerGoInvocation(spec)
		if !ok || !reflect.DeepEqual(args, []string{"version"}) {
			return ports.ToolResult{}, fmt.Errorf("unexpected tool %q %q", spec.Name, spec.Args)
		}
		return ports.ToolResult{Stdout: []byte("go version go1.26.0 linux/amd64\n")}, nil
	}}
	materializer := newFixtureMaterializer(t, runner, "linux/amd64")
	_, err := materializer.Materialize(context.Background(), FixtureMaterializationRequest{
		Specification: materializerFixture(t, "go-binary-input"),
		WorkRoot:      privateMaterializerRoot(t),
		CellKey:       "sha256:" + strings.Repeat("e", 64),
	})
	if err == nil {
		t.Fatal("Materialize accepted mismatched toolchain version")
	}
	if calls := runner.Calls(); len(calls) != 1 {
		t.Fatalf("tool calls = %d, want probe only", len(calls))
	}
}

func TestMatchingToolchainVersionRequiresExactProbeOutput(t *testing.T) {
	cases := []struct {
		name    string
		family  string
		version string
		result  ports.ToolResult
		want    bool
	}{
		{
			name:    "go exact standard output",
			family:  "go",
			version: "1.27.0",
			result:  ports.ToolResult{Stdout: []byte("go version go1.27.0 linux/amd64\n")},
			want:    true,
		},
		{
			name:    "go wrong platform output",
			family:  "go",
			version: "1.27.0",
			result:  ports.ToolResult{Stdout: []byte("go version go1.27.0 darwin/arm64\n")},
		},
		{
			name:    "dotnet exact trimmed output",
			family:  "dotnet-sdk",
			version: "8.0.100",
			result:  ports.ToolResult{Stdout: []byte(" 8.0.100\n")},
			want:    true,
		},
		{
			name:    "dotnet noise rejected",
			family:  "dotnet-sdk",
			version: "8.0.100",
			result:  ports.ToolResult{Stdout: []byte("8.0.100\nextra")},
		},
		{
			name:    "javac stdout exact",
			family:  "openjdk",
			version: "21.0.5",
			result:  ports.ToolResult{Stdout: []byte("javac 21.0.5\n")},
			want:    true,
		},
		{
			name:    "javac stderr exact",
			family:  "openjdk",
			version: "21.0.5",
			result:  ports.ToolResult{Stderr: []byte("javac 21.0.5\n")},
			want:    true,
		},
		{
			name:    "javac mixed streams rejected",
			family:  "openjdk",
			version: "21.0.5",
			result:  ports.ToolResult{Stdout: []byte("javac 21.0.5"), Stderr: []byte("warning")},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := matchingToolchainVersion(test.family, test.version, test.result); got != test.want {
				t.Errorf("matchingToolchainVersion = %v, want %v", got, test.want)
			}
		})
	}
}

func TestFixtureMaterializerRejectsBuildExecutionFailures(t *testing.T) {
	cases := []struct {
		name   string
		result ports.ToolResult
		err    error
	}{
		{name: "nonzero", result: ports.ToolResult{ExitCode: 1}},
		{name: "timeout", result: ports.ToolResult{TimedOut: true}},
		{name: "truncated", result: ports.ToolResult{Truncated: true}},
		{name: "runner error", err: errors.New("runner unavailable")},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			runner := &fixtureToolRunner{run: func(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
				_, args, ok := materializerGoInvocation(spec)
				if ok && reflect.DeepEqual(args, []string{"version"}) {
					return ports.ToolResult{Stdout: []byte("go version go1.27.0 linux/amd64\n")}, nil
				}
				return test.result, test.err
			}}
			materializer := newFixtureMaterializer(t, runner, "linux/amd64")
			_, err := materializer.Materialize(context.Background(), FixtureMaterializationRequest{
				Specification: materializerFixture(t, "go-binary-input"),
				WorkRoot:      privateMaterializerRoot(t),
				CellKey:       "sha256:" + strings.Repeat("f", 64),
			})
			if err == nil {
				t.Fatal("Materialize accepted failed build execution")
			}
			if calls := runner.Calls(); len(calls) != 2 {
				t.Fatalf("tool calls = %d, want probe and failed build", len(calls))
			}
		})
	}
}

func TestFixtureMaterializerRejectsMissingAndSymlinkOutputs(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		runner := successfulGoFixtureRunner(t, nil)
		materializer := newFixtureMaterializer(t, runner, "linux/amd64")
		_, err := materializer.Materialize(context.Background(), FixtureMaterializationRequest{
			Specification: materializerFixture(t, "go-binary-input"),
			WorkRoot:      privateMaterializerRoot(t),
			CellKey:       "sha256:" + strings.Repeat("1", 64),
		})
		if err == nil {
			t.Fatal("Materialize accepted missing declared output")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		runner := successfulGoFixtureRunner(t, func(spec ports.ToolSpec, output string) error {
			root, _, ok := materializerGoInvocation(spec)
			if !ok {
				return errors.New("missing Go materialization root")
			}
			outside := filepath.Join(filepath.Dir(root), "outside")
			if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
				return err
			}
			if err := os.Symlink(outside, output); err != nil {
				t.Skipf("create symlink: %v", err)
			}
			return nil
		})
		materializer := newFixtureMaterializer(t, runner, "linux/amd64")
		_, err := materializer.Materialize(context.Background(), FixtureMaterializationRequest{
			Specification: materializerFixture(t, "go-binary-input"),
			WorkRoot:      privateMaterializerRoot(t),
			CellKey:       "sha256:" + strings.Repeat("2", 64),
		})
		if err == nil {
			t.Fatal("Materialize accepted symlink output")
		}
	})
}

func TestFixtureMaterializerRejectsOversizedOutput(t *testing.T) {
	runner := successfulGoFixtureRunner(t, func(_ ports.ToolSpec, output string) error {
		return os.WriteFile(output, make([]byte, maxMaterializedFileBytes+1), 0o600)
	})
	materializer := newFixtureMaterializer(t, runner, "linux/amd64")
	_, err := materializer.Materialize(context.Background(), FixtureMaterializationRequest{
		Specification: materializerFixture(t, "go-binary-input"),
		WorkRoot:      privateMaterializerRoot(t),
		CellKey:       "sha256:" + strings.Repeat("3", 64),
	})
	if err == nil {
		t.Fatal("Materialize accepted oversized output")
	}
}

func TestFixtureMaterializerHonorsCancellation(t *testing.T) {
	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &fixtureToolRunner{}
	materializer := newFixtureMaterializer(t, runner, "linux/amd64")
	_, err := materializer.Materialize(cancelledContext, FixtureMaterializationRequest{
		Specification: materializerFixture(t, "go-source-tier2-input"),
		WorkRoot:      privateMaterializerRoot(t),
		CellKey:       "sha256:" + strings.Repeat("4", 64),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
	if len(runner.Calls()) != 0 {
		t.Fatalf("cancelled materialization ran tools: %+v", runner.Calls())
	}
}

func TestMaterializedFixtureManifestIsCanonicalAndPathIndependent(t *testing.T) {
	runner := successfulGoFixtureRunner(t, func(_ ports.ToolSpec, output string) error {
		return os.WriteFile(output, []byte("stable generated output"), 0o600)
	})
	materializer := newFixtureMaterializer(t, runner, "linux/amd64")
	request := FixtureMaterializationRequest{
		Specification: materializerFixture(t, "go-binary-input"),
		WorkRoot:      privateMaterializerRoot(t),
		CellKey:       "sha256:" + strings.Repeat("5", 64),
	}
	first, err := materializer.Materialize(context.Background(), request)
	if err != nil {
		t.Fatalf("first Materialize: %v", err)
	}
	second, err := materializer.Materialize(context.Background(), request)
	if err != nil {
		t.Fatalf("second Materialize: %v", err)
	}
	firstManifest, err := first.CanonicalManifest()
	if err != nil {
		t.Fatalf("first CanonicalManifest: %v", err)
	}
	secondManifest, err := second.CanonicalManifest()
	if err != nil {
		t.Fatalf("second CanonicalManifest: %v", err)
	}
	if !bytes.Equal(firstManifest, secondManifest) {
		t.Fatalf("canonical manifests differ:\n%s\n%s", firstManifest, secondManifest)
	}
	if bytes.Contains(firstManifest, []byte(first.Root)) {
		t.Fatalf("canonical manifest contains private root %q", first.Root)
	}
	firstDigest, err := first.ManifestDigest()
	if err != nil {
		t.Fatalf("first ManifestDigest: %v", err)
	}
	secondDigest, err := second.ManifestDigest()
	if err != nil {
		t.Fatalf("second ManifestDigest: %v", err)
	}
	if firstDigest != secondDigest {
		t.Errorf("manifest digest differs: %q != %q", firstDigest, secondDigest)
	}
}

func isFixtureToolchainProbe(family string, spec ports.ToolSpec) bool {
	switch family {
	case "go":
		_, args, ok := materializerGoInvocation(spec)
		return ok && reflect.DeepEqual(args, []string{"version"})
	case "dotnet-sdk":
		return spec.Name == "dotnet" && reflect.DeepEqual(spec.Args, []string{"--version"})
	case "openjdk":
		return spec.Name == "javac" && reflect.DeepEqual(spec.Args, []string{"-version"})
	default:
		return false
	}
}

func matchingFixtureToolchainProbe(family string) ports.ToolResult {
	switch family {
	case "go":
		return ports.ToolResult{Stdout: []byte("go version go1.27.0 linux/amd64\n")}
	case "dotnet-sdk":
		return ports.ToolResult{Stdout: []byte("8.0.100\n")}
	case "openjdk":
		return ports.ToolResult{Stdout: []byte("javac 21.0.5\n")}
	default:
		return ports.ToolResult{}
	}
}

func assertFrozenFixtureInvocations(t *testing.T, root string, build *reachcontract.FixtureBuild, calls []ports.ToolSpec) {
	t.Helper()
	if build == nil || len(calls) != len(build.Steps)+1 {
		t.Fatalf("fixture build invocation shape is invalid")
	}
	probeName, probeArgs := toolchainProbe(build.Toolchain.Family)
	if build.Kind == reachcontract.FixtureBuildGoBinary {
		probeRoot, args, ok := materializerGoInvocation(calls[0])
		if !ok || probeRoot != root || calls[0].Name != probeName || !reflect.DeepEqual(args, probeArgs) {
			t.Fatalf("Go probe = %q %q, want Go -C %q %q", calls[0].Name, calls[0].Args, root, probeArgs)
		}
	} else if calls[0].Name != probeName || !reflect.DeepEqual(calls[0].Args, probeArgs) {
		t.Fatalf("toolchain probe = %q %q, want %q %q", calls[0].Name, calls[0].Args, probeName, probeArgs)
	}
	for index, step := range build.Steps {
		call := calls[index+1]
		if call.Name != step.Argv[0] {
			t.Errorf("build step %d tool = %q, want %q", index+1, call.Name, step.Argv[0])
			continue
		}
		if build.Kind == reachcontract.FixtureBuildGoBinary {
			gotRoot, args, ok := materializerGoInvocation(call)
			if !ok || gotRoot != root || !reflect.DeepEqual(args, step.Argv[1:]) {
				t.Errorf("Go build step %d argv = %q, want Go -C %q %q", index+1, call.Args, root, step.Argv[1:])
			}
			continue
		}
		assertRootRelativeArgs(t, root, step.Argv[1:], call.Args)
	}
}

func assertRootRelativeArgs(t *testing.T, root string, want, got []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("rewritten argv length = %d, want %d", len(got), len(want))
	}
	for index, original := range want {
		if !strings.HasPrefix(original, "./") {
			if got[index] != original {
				t.Errorf("argv %d = %q, want unchanged %q", index, got[index], original)
			}
			continue
		}
		if strings.Contains(original, ":") {
			parts := strings.Split(original, ":")
			for partIndex, part := range parts {
				parts[partIndex] = filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(part, "./")))
			}
			wantClasspath := strings.Join(parts, ":")
			if got[index] != wantClasspath {
				t.Errorf("classpath argv %d = %q, want %q", index, got[index], wantClasspath)
			}
			continue
		}
		wantPath := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(original, "./")))
		if got[index] != wantPath {
			t.Errorf("argv %d = %q, want %q", index, got[index], wantPath)
		}
	}
}

func newFixtureMaterializer(t *testing.T, runner ports.ToolRunner, platform string) *FixtureMaterializer {
	t.Helper()
	toolDirectory := filepath.Join(t.TempDir(), "tools")
	materializer, err := NewFixtureMaterializer(FixtureMaterializerDependencies{
		ToolRunner: runner,
		Platform:   func() string { return platform },
		LocateTool: func(name string) (string, error) { return filepath.Join(toolDirectory, name), nil },
	})
	if err != nil {
		t.Fatalf("NewFixtureMaterializer: %v", err)
	}
	return materializer
}

func materializerFixture(t *testing.T, id string) reachcontract.FixtureSpecification {
	t.Helper()
	for _, specification := range reachcontract.DefaultReachabilityBenchmark().Fixtures.Fixtures {
		if specification.ID == id {
			return cloneMaterializedSpecification(specification)
		}
	}
	t.Fatalf("fixture %q not found", id)
	return reachcontract.FixtureSpecification{}
}

func privateMaterializerRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "private-work")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("create work root: %v", err)
	}
	return root
}

func successfulGoFixtureRunner(t *testing.T, build func(ports.ToolSpec, string) error) *fixtureToolRunner {
	t.Helper()
	return &fixtureToolRunner{run: func(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
		root, args, ok := materializerGoInvocation(spec)
		if !ok {
			return ports.ToolResult{}, fmt.Errorf("unexpected tool %q %q", spec.Name, spec.Args)
		}
		if reflect.DeepEqual(args, []string{"version"}) {
			return ports.ToolResult{Stdout: []byte("go version go1.27.0 linux/amd64\n")}, nil
		}
		output := filepath.Join(root, "generated", "go-binary-pclntab")
		if build == nil {
			return ports.ToolResult{}, nil
		}
		return ports.ToolResult{}, build(spec, output)
	}}
}

func materializerGoInvocation(spec ports.ToolSpec) (string, []string, bool) {
	if spec.Name != "go" || len(spec.Args) < 3 || spec.Args[0] != "-C" || !filepath.IsAbs(spec.Args[1]) {
		return "", nil, false
	}
	return spec.Args[1], spec.Args[2:], true
}

func cloneToolSpec(spec ports.ToolSpec) ports.ToolSpec {
	clone := spec
	clone.Args = append([]string(nil), spec.Args...)
	clone.Env = append([]string(nil), spec.Env...)
	return clone
}

func toolEnvironment(values []string) map[string]string {
	environment := make(map[string]string, len(values))
	for _, value := range values {
		key, value, found := strings.Cut(value, "=")
		if !found {
			continue
		}
		environment[key] = value
	}
	return environment
}
