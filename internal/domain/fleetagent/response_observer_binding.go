package fleetagent

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ResponseObserverBinding is the server-owned authorization for a secondary agent to observe one
// canonical asset without becoming that asset's primary inventory owner.
type ResponseObserverBinding struct {
	TenantID   shared.ID
	AgentID    shared.ID
	AssetID    shared.ID
	AssignedBy string
	AssignedAt time.Time
	ExpiresAt  time.Time
	Version    int
}

func (b ResponseObserverBinding) Validate() error {
	if b.TenantID.IsZero() || b.AgentID.IsZero() || b.AssetID.IsZero() || strings.TrimSpace(b.AssignedBy) == "" ||
		b.AssignedAt.IsZero() || b.ExpiresAt.IsZero() || !b.AssignedAt.Before(b.ExpiresAt) || b.Version <= 0 {
		return fmt.Errorf("%w: response-observer binding is incomplete", shared.ErrValidation)
	}
	return nil
}

func (b ResponseObserverBinding) ActiveAt(now time.Time) bool {
	return b.Validate() == nil && !now.UTC().Before(b.AssignedAt.UTC()) && now.UTC().Before(b.ExpiresAt.UTC())
}
