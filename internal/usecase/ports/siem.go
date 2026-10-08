package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
)

// SIEMStore persists sink configuration, leases, batches, and checkpoints.
// Implementations scope every call to the tenant bound on ctx.
type SIEMStore interface {
	CreateSink(ctx context.Context, sink siem.Sink, sealedSecret string) error
	UpdateSink(ctx context.Context, sink siem.Sink, expectedVersion int64) error
	GetSink(ctx context.Context, id shared.ID) (siem.Sink, error)
	ListSinks(ctx context.Context) ([]siem.Sink, error)
	PutSecret(ctx context.Context, sinkID shared.ID, version int64, sealed string) error
	LatestSecret(ctx context.Context, sinkID shared.ID) (version int64, sealed string, err error)
	GetSecret(ctx context.Context, sinkID shared.ID, version int64) (sealed string, err error)

	Claim(ctx context.Context, owner string, sink siem.Sink, source siem.Source, now time.Time, ttl time.Duration) (siem.Lease, error)
	Release(ctx context.Context, lease siem.Lease) error
	SaveBatch(ctx context.Context, batch siem.Batch, sealed []string) error
	OpenBatch(ctx context.Context, sinkID shared.ID, source siem.Source) (siem.Batch, []string, bool, error)
	Checkpoint(ctx context.Context, sinkID shared.ID, source siem.Source) (siem.Checkpoint, bool, error)
	Commit(ctx context.Context, lease siem.Lease, batch siem.Batch, checkpoint siem.Checkpoint, now time.Time) error
	ResetPartition(ctx context.Context, sink siem.Sink, source siem.Source, checkpoint siem.Checkpoint) error
	Prune(ctx context.Context, before time.Time) error
	AggregateBacklog(ctx context.Context) (map[siem.Source]siem.BacklogAggregate, error)
}

// SIEMSources reads committed audit and incident rows. Audit metadata is
// returned only so the chain can be recomputed; exporters must not serialize it.
type SIEMSources interface {
	ReadAudit(ctx context.Context, afterID int64, limit int) ([]siem.AuditFact, []map[string]string, siem.AuditAnchor, error)
	CountAudit(ctx context.Context, afterID int64) (count int, oldestUnixMicro int64, err error)
	ReadIncident(ctx context.Context, phase siem.Phase, afterSeq int64, limit int) ([]siem.IncidentFact, error)
	HeadIncident(ctx context.Context, phase siem.Phase) (siem.IncidentFact, bool, error)
	CountIncident(ctx context.Context, phase siem.Phase, afterSeq int64) (count int, oldestUnixMicro int64, err error)
	BackfillIncidents(ctx context.Context, limit int) (int, error)
}

// SIEMDirectory lists tenants a worker may visit. It does not carry secrets.
type SIEMDirectory interface {
	TenantIDs(ctx context.Context) ([]shared.ID, error)
}

// SIEMSealer seals a prepared payload to the sink generation. AAD mismatch
// must fail closed.
type SIEMSealer interface {
	Seal(ctx context.Context, plaintext, aad []byte) (string, error)
	Open(ctx context.Context, ciphertext string, aad []byte) ([]byte, error)
}

// SIEMDriver sends one batch to a single destination.
type SIEMDriver interface {
	Deliver(ctx context.Context, req siem.Delivery) (siem.DeliveryResult, error)
}

// SIEMAckDriver polls a durable receipt without resubmitting the POST.
type SIEMAckDriver interface {
	PollAck(ctx context.Context, req siem.Delivery, ackID int64) (bool, time.Duration, error)
}

// SIEMSecretValidator lets a provider reject malformed write-only credentials
// before they are sealed and stored. Errors must not include credential values.
type SIEMSecretValidator interface {
	ValidateSecret(secret string) error
}

// SIEMEngagementPolicy is the shared engagement ceiling. Unknown policy is
// reported as Known=false; callers fail closed to signal.
type SIEMEngagementPolicy interface {
	Ceiling(ctx context.Context, engagementID string) (siem.EngagementCeiling, error)
}

// SIEMMetrics records bounded operational series. Label values are enums
// chosen by the caller from fixed sets, never event ids or URLs.
type SIEMMetrics interface {
	Batch(provider, result string)
	Items(provider, disposition string, n int)
	Retry(provider string)
	Gap(source string)
	Backlog(source string, ageSeconds float64, records int)
	Blocked(reason string)
}

// SIEMOCSFValidator validates complete documents against the pinned offline schemas.
// Errors must not expose record values.
type SIEMOCSFValidator interface {
	Validate(body []byte) error
}
