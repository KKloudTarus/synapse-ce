package ports

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// FleetAuditIntent is an exact immutable audit payload committed with the
// authoritative fleet mutation that requires it.
type FleetAuditIntent struct {
	ID    string
	Entry AuditEntry
}

// Normalize returns the canonical form of the intention and validates it. Every
// adapter must persist and return THIS form: the payload's hash in the audit chain
// depends on it, so a backend that normalized differently would make an immediate
// delivery and a restart-time delivery of one intention hash differently.
// Microsecond truncation matches PostgreSQL timestamptz, the coarsest resolution
// any backend can store.
func (i FleetAuditIntent) Normalize() (FleetAuditIntent, error) {
	i.ID = strings.TrimSpace(i.ID)
	i.Entry.Actor = strings.TrimSpace(i.Entry.Actor)
	i.Entry.Action = strings.TrimSpace(i.Entry.Action)
	i.Entry.Target = strings.TrimSpace(i.Entry.Target)
	i.Entry.At = i.Entry.At.UTC().Truncate(time.Microsecond)
	if i.ID == "" || i.Entry.Actor == "" || i.Entry.Action == "" ||
		i.Entry.Target == "" || i.Entry.At.IsZero() {
		return FleetAuditIntent{}, fmt.Errorf("%w: fleet audit intention is incomplete", shared.ErrValidation)
	}
	// The chain assigns linkage on append; a caller-supplied hash would let state
	// outside the chain dictate the chain's own shape.
	if i.Entry.Hash != "" || i.Entry.PreviousHash != "" {
		return FleetAuditIntent{}, fmt.Errorf("%w: fleet audit intention cannot precompute chain hashes", shared.ErrValidation)
	}
	if strings.TrimSpace(i.Entry.Metadata["idempotency_key"]) == "" {
		return FleetAuditIntent{}, fmt.Errorf("%w: fleet audit intention idempotency key is required", shared.ErrValidation)
	}
	// The idempotency key IS the obligation's identity. If they could differ, the audit
	// chain would dedupe on one value while the outbox tracked another.
	if i.Entry.Metadata["idempotency_key"] != i.ID {
		return FleetAuditIntent{}, fmt.Errorf("%w: fleet audit intention id must match its idempotency key", shared.ErrValidation)
	}
	i.Entry.Metadata = maps.Clone(i.Entry.Metadata)
	return i, nil
}

// SameFleetAuditIntent reports whether two intentions carry identical immutable
// content, and therefore whether one is an exact retry of the other.
func SameFleetAuditIntent(left, right FleetAuditIntent) bool {
	return left.ID == right.ID && left.Entry.Actor == right.Entry.Actor &&
		left.Entry.Action == right.Entry.Action && left.Entry.Target == right.Entry.Target &&
		left.Entry.At.Equal(right.Entry.At) && left.Entry.Hash == right.Entry.Hash &&
		left.Entry.PreviousHash == right.Entry.PreviousHash &&
		maps.Equal(left.Entry.Metadata, right.Entry.Metadata)
}

// FleetAuditIntentStore exposes pending delivery and monotonic completion for
// state-local fleet audit intentions.
type FleetAuditIntentStore interface {
	ListPendingFleetAudits(ctx context.Context) ([]FleetAuditIntent, error)
	AcknowledgeFleetAudit(ctx context.Context, id string) error
}

// PrivacyPolicyAuditStore commits an activation and its exact audit intention
// in one local transaction or memory critical section. It returns the committed
// intention, not just the activation: the caller must audit the payload that
// actually became durable, never one it re-derives itself.
type PrivacyPolicyAuditStore interface {
	PrivacyPolicyStore
	FleetAuditIntentStore
	ActivatePrivacyPolicyWithAudit(
		ctx context.Context,
		activation privacy.Activation,
		intent FleetAuditIntent,
	) (privacy.Activation, FleetAuditIntent, error)
}

// TelemetryAuditStore commits immutable batch identity or one signed gap
// revision together with the exact audit intention in one local transaction or
// memory critical section.
type TelemetryAuditStore interface {
	TelemetryTransportStore
	FleetAuditIntentStore
	CommitBatchWithAudit(
		ctx context.Context,
		batch TelemetryEventBatch,
		intent FleetAuditIntent,
	) (FleetAuditIntent, error)
	AcceptAgentGapRevisionWithAudit(
		ctx context.Context,
		revision TelemetryAgentGapRevision,
		intent FleetAuditIntent,
	) (FleetAuditIntent, error)
}

// SensorStateAuditStore commits one signed observation and its exact audit
// intention in one local transaction or memory critical section.
type SensorStateAuditStore interface {
	SensorStateStore
	FleetAuditIntentStore
	AppendSensorStateWithAudit(
		ctx context.Context,
		observation sensorstate.Observation,
		intent FleetAuditIntent,
	) (FleetAuditIntent, error)
}
