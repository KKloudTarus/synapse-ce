package ast

import (
	"context"
	"testing"
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
