package ports

import (
	"context"
	"errors"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ErrIdentityCutover rejects a transition whose durable evidence or optimistic version is stale.
var ErrIdentityCutover = errors.New("identity cutover transition rejected")

// IdentityCutoverPhase is the operator-visible, durable authority state.
type IdentityCutoverPhase string

const (
	IdentityCutoverLegacy     IdentityCutoverPhase = "legacy"
	IdentityCutoverShadow     IdentityCutoverPhase = "shadow"
	IdentityCutoverDeclared   IdentityCutoverPhase = "declared"
	IdentityCutoverContracted IdentityCutoverPhase = "contracted"
)

// IdentityCutoverState is derived from the tenant policy and append-only cutover ledger.
type IdentityCutoverState struct {
	TenantID      shared.ID
	Phase         IdentityCutoverPhase
	PolicyVersion int
	Declared      bool
	Contracted    bool
}

// IdentityCutoverEvidence binds a declaration to a fresh clean shadow report and an observed
// old-writer drain. A caller cannot acknowledge these conditions without durable evidence.
type IdentityCutoverEvidence struct {
	ShadowReportID      shared.ID
	OldWriterGeneration string
	OldWriterCount      int
	MigrationVersion    int
}

// IdentityCutoverStore owns durable, fenced cutover transitions and their audit ledger.
type IdentityCutoverStore interface {
	// RecordCutoverWriterHeartbeat is called by each current writer instance. Declaration uses
	// these database-owned liveness records instead of an operator-supplied writer count.
	RecordCutoverWriterHeartbeat(ctx context.Context, tenantID shared.ID, generation, instanceID string, at time.Time) error
	CutoverState(ctx context.Context, tenantID shared.ID) (IdentityCutoverState, error)
	PrepareCutover(ctx context.Context, tenantID shared.ID, expectedVersion int, actor string, at time.Time) (IdentityCutoverState, error)
	CanaryCutover(ctx context.Context, tenantID shared.ID) (IdentityShadowReport, error)
	DeclareCutover(ctx context.Context, tenantID shared.ID, expectedVersion int, evidence IdentityCutoverEvidence, actor string, at time.Time) (IdentityCutoverState, error)
	ContractCutover(ctx context.Context, tenantID shared.ID, expectedVersion int, actor string, at time.Time) (IdentityCutoverState, error)
	AbortCutover(ctx context.Context, tenantID shared.ID, expectedVersion int, actor string, at time.Time) (IdentityCutoverState, error)
}
