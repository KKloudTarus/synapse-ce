//go:build !linux

package responseactuator

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type Registry struct{}

func NewRegistry() (*Registry, error) {
	return nil, fmt.Errorf("%w: live process response is supported only on Linux", shared.ErrForbidden)
}

func (*Registry) ObserveProcess(shared.ID, shared.ID, detection.ProcessEvent) {}

func (*Registry) StopProcess(context.Context, shared.ID) (bool, error) {
	return false, fmt.Errorf("%w: live process response is supported only on Linux", shared.ErrForbidden)
}

func (*Registry) RestartProcess(context.Context, shared.ID) (bool, error) {
	return false, fmt.Errorf("%w: live process response is supported only on Linux", shared.ErrForbidden)
}

func (*Registry) Close() error { return nil }
