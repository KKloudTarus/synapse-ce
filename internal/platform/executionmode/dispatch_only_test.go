package executionmode

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// A dispatch-only composition root must not be able to execute anything locally:
// every execution port fails closed so a routing bug surfaces as an error rather
// than an unsandboxed host exec.
func TestDispatchOnlyFailsClosed(t *testing.T) {
	d := DispatchOnly{}
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{"acquire", func() error { _, err := d.Acquire(ctx, ports.AcquireRequest{}); return err }},
		{"generate sbom", func() error { _, err := d.Generate(ctx, "target"); return err }},
		{"detection scan", func() error { _, err := d.Scan(ctx, &sbom.SBOM{}); return err }},
		{"run tool", func() error { _, err := d.Run(ctx, ports.ToolSpec{Name: "syft"}); return err }},
		{"submit task", func() error { return d.Submit(func(context.Context) {}) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, ErrDispatchOnly) {
				t.Fatalf("%s: got %v, want ErrDispatchOnly", tt.name, err)
			}
		})
	}
}

// Submit must not run the task it refuses: a silently-executed task would run
// untrusted tooling in the API process.
func TestDispatchOnlySubmitDoesNotRunTask(t *testing.T) {
	ran := false
	if err := (DispatchOnly{}).Submit(func(context.Context) { ran = true }); err == nil {
		t.Fatal("Submit() returned nil error")
	}
	if ran {
		t.Fatal("Submit() executed the task")
	}
}
