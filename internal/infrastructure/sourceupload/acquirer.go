package sourceupload

import (
	"context"
	"errors"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Acquirer struct {
	next    ports.Acquirer
	sources ports.EngagementSourceStore
}

func NewAcquirer(next ports.Acquirer, sources ports.EngagementSourceStore) *Acquirer {
	return &Acquirer{next: next, sources: sources}
}

var _ ports.Acquirer = (*Acquirer)(nil)

func (a *Acquirer) Acquire(ctx context.Context, request ports.AcquireRequest) (*ports.Workspace, error) {
	if request.Kind != ports.TargetUpload {
		return a.next.Acquire(ctx, request)
	}
	if a.next == nil || a.sources == nil || request.Locator == "" {
		return nil, fmt.Errorf("%w: uploaded source acquisition is not configured", shared.ErrValidation)
	}
	path, item, cleanupSource, err := a.sources.Materialize(ctx, request.Locator)
	if err != nil {
		return nil, err
	}
	if item.Target() != request.Value {
		_ = cleanupSource()
		return nil, fmt.Errorf("%w: uploaded source identity does not match stored content", shared.ErrValidation)
	}
	workspace, err := a.next.Acquire(ctx, ports.AcquireRequest{Kind: ports.TargetArchive, Value: path})
	if err != nil {
		_ = cleanupSource()
		return nil, err
	}
	cleanupWorkspace := workspace.Cleanup
	workspace.Cleanup = func() error {
		var workspaceErr error
		if cleanupWorkspace != nil {
			workspaceErr = cleanupWorkspace()
		}
		return errors.Join(workspaceErr, cleanupSource())
	}
	return workspace, nil
}
