package ports

import (
	"context"
	"errors"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var ErrOwnershipNonManifest = errors.New("path is not an application manifest")

// OwnershipFile is bounded capture evidence, never authority to activate a policy.
// Base and head files retain their own immutable revisions.
type OwnershipFile struct {
	Path     string
	Content  string
	Revision string
	Base     bool
}

type OwnershipCapture struct {
	Revision     string
	BaseRevision string
	Files        []OwnershipFile
	Reason       string
}

type OwnershipSourceReader interface {
	ReadOwnershipSource(context.Context, AcquireRequest, *Workspace) (OwnershipCapture, error)
	OwnershipPath(root, path string, manifest bool) (string, error)
}

type OwnershipSourceRecord struct {
	ID           shared.ID            `json:"id"`
	EngagementID shared.ID            `json:"engagement_id"`
	Repository   string               `json:"repository"`
	Revision     string               `json:"source_revision"`
	BaseRevision string               `json:"base_revision,omitempty"`
	BaseRequired bool                 `json:"base_required"`
	Reason       string               `json:"reason,omitempty"`
	CreatedBy    string               `json:"created_by"`
	CreatedAt    time.Time            `json:"created_at"`
	Snapshots    []ownership.Snapshot `json:"-"`
}

type OwnershipSourceStore interface {
	SaveOwnershipSource(context.Context, OwnershipSourceRecord) error
	MarkOwnershipSourceReady(context.Context, shared.ID, shared.ID) error
}

type OwnershipFindingSource struct {
	Paths   []string `json:"paths"`
	Invalid bool     `json:"invalid"`
}

// OwnershipSourceBatch is attached only by server-side scan producers. The
// PostgreSQL finding upsert persists each canonical binding in its transaction,
// after dedup has resolved the authoritative finding ID.
type OwnershipSourceBatch struct {
	Source   OwnershipSourceRecord
	Findings map[string]OwnershipFindingSource // finding.Identity -> source evidence
}

type ownershipSourceContextKey struct{}

func WithOwnershipSource(ctx context.Context, batch OwnershipSourceBatch) context.Context {
	return context.WithValue(ctx, ownershipSourceContextKey{}, batch)
}

func OwnershipSourceFrom(ctx context.Context) (OwnershipSourceBatch, bool) {
	batch, ok := ctx.Value(ownershipSourceContextKey{}).(OwnershipSourceBatch)
	return batch, ok
}
