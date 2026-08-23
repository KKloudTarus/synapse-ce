// Package executionmode provides fail-closed adapters for process roles that may
// compose execution-capable use cases but are not authorized to execute locally.
package executionmode

import (
	"context"
	"errors"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var ErrDispatchOnly = errors.New("local tool execution is disabled in dispatch-only mode")

// DispatchOnly satisfies execution ports required by API-side service composition.
// Queue-backed paths must return before any of these methods are reached.
type DispatchOnly struct{}

func (DispatchOnly) Acquire(context.Context, ports.AcquireRequest) (*ports.Workspace, error) {
	return nil, ErrDispatchOnly
}

func (DispatchOnly) Generate(context.Context, string) (*sbom.SBOM, error) {
	return nil, ErrDispatchOnly
}

func (DispatchOnly) Name() string { return "dispatch-only" }

func (DispatchOnly) Scan(context.Context, *sbom.SBOM) ([]vulnerability.RawFinding, error) {
	return nil, ErrDispatchOnly
}

func (DispatchOnly) Run(context.Context, ports.ToolSpec) (ports.ToolResult, error) {
	return ports.ToolResult{}, ErrDispatchOnly
}

func (DispatchOnly) Submit(func(context.Context)) error { return ErrDispatchOnly }

var (
	_ ports.Acquirer        = DispatchOnly{}
	_ ports.SBOMGenerator   = DispatchOnly{}
	_ ports.DetectionSource = DispatchOnly{}
	_ ports.ToolRunner      = DispatchOnly{}
)
