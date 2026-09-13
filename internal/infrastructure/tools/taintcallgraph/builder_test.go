package taintcallgraph

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeRunner struct {
	gotSpec ports.ToolSpec
	result  ports.ToolResult
	err     error
}

func (f *fakeRunner) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	f.gotSpec = spec
	return f.result, f.err
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestBuildSandboxedSpecAndParse(t *testing.T) {
	wire := `{"protocol_version":"v1.1.0","entrypoints":["m.main"],"edges":[{"caller":"m.main","callees":["m.run"]}]}`
	fr := &fakeRunner{result: ports.ToolResult{Stdout: []byte(wire)}}
	g, err := New("synapse-callgraph").WithRunner(fr).Build(context.Background(), "/work/target")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(g.Edges) != 1 || g.Edges[0].Caller != "m.main" || len(g.Entrypoints) != 1 || g.Entrypoints[0] != "m.main" {
		t.Fatalf("parsed graph wrong: %+v", g)
	}
	// The ToolSpec must CONFINE the run: the build-callgraph argv, the target bound READ-ONLY, cgo disabled.
	s := fr.gotSpec
	if s.Name != "synapse-callgraph" || !reflect.DeepEqual(s.Args, []string{"build-callgraph", "/work/target"}) {
		t.Errorf("spec name/args wrong: %+v", s)
	}
	if !reflect.DeepEqual(s.ReadOnlyPaths, []string{"/work/target"}) {
		t.Errorf("the target must be bound read-only: %+v", s.ReadOnlyPaths)
	}
	if !contains(s.Env, "CGO_ENABLED=0") {
		t.Errorf("cgo must be disabled in the sandboxed run (no untrusted-C compile): %+v", s.Env)
	}
}

func TestBuildExitCodeFailsClosed(t *testing.T) {
	// A non-zero exit (e.g. the target failed to load/typecheck) must surface as an error, never a partial graph.
	fr := &fakeRunner{result: ports.ToolResult{ExitCode: 1, Stderr: []byte("load error: undefined foo")}}
	if _, err := New("").WithRunner(fr).Build(context.Background(), "/work/target"); err == nil {
		t.Error("a non-zero exit must fail closed")
	}
}

func TestBuildRunnerErrorFailsClosed(t *testing.T) {
	fr := &fakeRunner{err: errors.New("sandbox boom")}
	if _, err := New("").WithRunner(fr).Build(context.Background(), "/work/target"); err == nil {
		t.Error("a runner error must propagate (fail closed)")
	}
}

func TestNewDefaultsBinaryName(t *testing.T) {
	// New("") must default the binary to "synapse-callgraph" (the in-repo cmd), reflected in the ToolSpec.
	fr := &fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"protocol_version":"v1.1.0"}`)}}
	if _, err := New("").WithRunner(fr).Build(context.Background(), "/t"); err != nil {
		t.Fatalf("build: %v", err)
	}
	if fr.gotSpec.Name != "synapse-callgraph" {
		t.Errorf(`New("") must default the binary to "synapse-callgraph", got %q`, fr.gotSpec.Name)
	}
}

func TestBuildRejectsDriftedOutput(t *testing.T) {
	fr := &fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"protocol_version":"v2.0.0"}`)}}
	if _, err := New("").WithRunner(fr).Build(context.Background(), "/work/target"); err == nil {
		t.Error("an unrecognized protocol version in the binary output must fail closed")
	}
}
