//go:build !linux

package scabench

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// DigestPinnedOCITargetRunner is unavailable outside Linux because production
// target-native comparison must execute in the pinned target OCI boundary.
type DigestPinnedOCITargetRunner struct{}

var _ ports.ToolRunner = (*DigestPinnedOCITargetRunner)(nil)

func NewDigestPinnedOCITargetRunner(_ ports.ToolRunner, _, _ string) (*DigestPinnedOCITargetRunner, error) {
	return nil, fmt.Errorf("%w: Linux digest-pinned OCI execution is required", ErrTargetNativeComparisonUnavailable)
}

func (*DigestPinnedOCITargetRunner) Run(context.Context, ports.ToolSpec) (ports.ToolResult, error) {
	return ports.ToolResult{}, fmt.Errorf("%w: Linux digest-pinned OCI execution is required", ErrTargetNativeComparisonUnavailable)
}
