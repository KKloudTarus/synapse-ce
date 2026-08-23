package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ExecutionRequest describes one external-tool execution that must be checked
// against current engagement state and recorded on the append-only audit log.
type ExecutionRequest struct {
	Actor        string
	EngagementID shared.ID
	Action       string
	Target       engagement.Target
	Metadata     map[string]string
}

// ExecutionAuthorizer is the current-state authorization chokepoint used before
// external execution or issuance of an execution-bound capability.
type ExecutionAuthorizer interface {
	Authorize(context.Context, ExecutionRequest) (time.Time, error)
}
