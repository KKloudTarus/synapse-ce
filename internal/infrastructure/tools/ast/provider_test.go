package ast

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// A missing sidecar binary must degrade to available=false with no error (the provider is optional
// enrichment), so a caller falls back to its own counting rather than failing.
func TestProviderUnavailableWhenBinaryMissing(t *testing.T) {
	p := New("/nonexistent/synapse-ast-does-not-exist")
	counts, available, err := p.FunctionCounts(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("missing binary must not error, got %v", err)
	}
	if available {
		t.Errorf("missing binary must report available=false")
	}
	if counts != nil {
		t.Errorf("missing binary must return nil counts, got %v", counts)
	}
}

func TestProviderEmptyRoot(t *testing.T) {
	_, available, err := New("").FunctionCounts(context.Background(), "")
	if err != nil || available {
		t.Errorf("empty root: want (unavailable, no error), got available=%v err=%v", available, err)
	}
}

func TestBugsUnavailableWhenBinaryMissing(t *testing.T) {
	p := New("/nonexistent/synapse-ast-does-not-exist")
	bugs, available, err := p.Bugs(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("missing binary must not error, got %v", err)
	}
	if available || len(bugs) != 0 {
		t.Errorf("missing binary must report unavailable + no bugs, got available=%v bugs=%d", available, len(bugs))
	}
}

func TestComplexityUnavailableWhenBinaryMissing(t *testing.T) {
	p := New("/nonexistent/synapse-ast-does-not-exist")
	report, available, err := p.Complexity(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("missing binary must not error, got %v", err)
	}
	if available {
		t.Errorf("missing binary must report available=false")
	}
	if len(report.Functions) != 0 {
		t.Errorf("missing binary must return an empty report, got %+v", report)
	}
}

func TestAnalyzeUnavailableWhenBinaryMissing(t *testing.T) {
	findings, err := New("/nonexistent/synapse-ast-does-not-exist").Analyze(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("missing binary must not error, got %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("missing binary must return no findings, got %+v", findings)
	}
}

func TestAnalyzeMalformedJSON(t *testing.T) {
	p := New("synapse-ast").WithRunner(fakeRunner{stdout: []byte("not json")})
	if _, err := p.Analyze(context.Background(), t.TempDir()); err == nil {
		t.Fatal("malformed quality JSON must error")
	}
}

func TestAnalyzeCanceledRunner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := New("synapse-ast").WithRunner(fakeRunner{err: context.Canceled})
	if _, err := p.Analyze(ctx, t.TempDir()); err != context.Canceled {
		t.Fatalf("canceled analysis error = %v, want context.Canceled", err)
	}
}

func TestAnalyzeTimedOutRunner(t *testing.T) {
	want := context.DeadlineExceeded
	p := New("synapse-ast").WithRunner(fakeRunner{result: ports.ToolResult{TimedOut: true}, err: want})
	if _, err := p.Analyze(context.Background(), t.TempDir()); err != want {
		t.Fatalf("timed-out analysis error = %v, want %v", err, want)
	}
}

type fakeRunner struct {
	stdout []byte
	result ports.ToolResult
	err    error
}

func (r fakeRunner) Run(context.Context, ports.ToolSpec) (ports.ToolResult, error) {
	r.result.Stdout = r.stdout
	return r.result, r.err
}
