package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
)

// CloudSandboxExecutor runs one connector inside the hardened helper boundary.
type CloudSandboxExecutor interface {
	EnumerateCloud(context.Context, CloudScope) (cloudposture.Inventory, []cloudposture.CoverageIssue, error)
}
