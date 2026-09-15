//go:build !linux

package scabench

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TargetNativeVersionComparator is intentionally unavailable outside Linux.
type TargetNativeVersionComparator struct{}

var _ ports.NativeVersionComparator = (*TargetNativeVersionComparator)(nil)

func NewTargetNativeVersionComparator(_ ports.ToolRunner, _ string) (*TargetNativeVersionComparator, error) {
	return nil, fmt.Errorf("%w: Linux target execution is required", ErrTargetNativeComparisonUnavailable)
}

func (*TargetNativeVersionComparator) CompareNativeVersion(context.Context, ports.NativeVersionComparisonRequest) (ports.NativeVersionComparisonResult, error) {
	return ports.NativeVersionComparisonResult{}, fmt.Errorf("%w: Linux target execution is required", ErrTargetNativeComparisonUnavailable)
}
