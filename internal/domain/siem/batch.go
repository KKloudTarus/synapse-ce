package siem

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// BatchState is the durable lifecycle of one prepared export.
type BatchState string

const (
	BatchPrepared    BatchState = "prepared"
	BatchSending     BatchState = "sending"
	BatchPartial     BatchState = "partial"
	BatchAwaitingAck BatchState = "awaiting_ack"
	BatchAcked       BatchState = "acked"
	BatchBlocked     BatchState = "blocked"
	BatchInvalid     BatchState = "invalidated"
)

// Open reports whether another batch must not be prepared for the partition.
func (s BatchState) Open() bool {
	switch s {
	case BatchPrepared, BatchSending, BatchPartial, BatchAwaitingAck, BatchBlocked:
		return true
	default:
		return false
	}
}

// ItemDisposition is the durable result of one record. Quarantine and
// suppression are handled outcomes. Failure stops the prefix.
type ItemDisposition string

const (
	ItemPending     ItemDisposition = "pending"
	ItemAcked       ItemDisposition = "acked"
	ItemFailed      ItemDisposition = "failed"
	ItemQuarantined ItemDisposition = "quarantined"
	ItemSuppressed  ItemDisposition = "suppressed"
)

// Handled reports whether the cursor may move past the item.
func (d ItemDisposition) Handled() bool {
	return d == ItemAcked || d == ItemQuarantined || d == ItemSuppressed
}

// BatchItem is one record inside a batch, in send order.
type BatchItem struct {
	Ordinal       int
	RecordID      string
	Position      Position
	Disposition   ItemDisposition
	PayloadDigest string
	Mapping       string
	DataClass     DataClass
	EngagementID  string
	SafeReason    string
}

// Batch is the persisted unit of work between a cursor and a sink generation.
type Batch struct {
	ID             shared.ID
	TenantID       shared.ID
	SinkID         shared.ID
	Source         Source
	Generation     int64
	LeaseToken     int64
	State          BatchState
	PolicyVersion  string
	MappingVersion string
	Items          []BatchItem
	ChainHead      string
	Diagnostic     string
	Attempt        int
	NextAttemptAt  time.Time
	IndexerAckID   *int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// HandledPrefix is the number of leading items the cursor may cross.
// A later success does not jump over a failed or pending item.
func HandledPrefix(items []BatchItem) int {
	n := 0
	for _, item := range items {
		if !item.Disposition.Handled() {
			return n
		}
		n++
	}
	return n
}

// AdvancePosition returns the cursor after the handled prefix. The second
// result is false when nothing new was handled.
func AdvancePosition(items []BatchItem) (Position, bool) {
	n := HandledPrefix(items)
	if n == 0 {
		return Position{}, false
	}
	return items[n-1].Position, true
}

// NextState derives the batch state from its items and an operator block.
func NextState(items []BatchItem, blocked bool) BatchState {
	if len(items) == 0 {
		return BatchInvalid
	}
	if blocked {
		return BatchBlocked
	}
	handled := HandledPrefix(items)
	if handled == len(items) {
		return BatchAcked
	}
	if handled > 0 {
		return BatchPartial
	}
	pending := true
	for _, item := range items {
		if item.Disposition == ItemFailed {
			pending = false
			break
		}
		if item.Disposition != ItemPending {
			pending = false
		}
	}
	if pending {
		return BatchPrepared
	}
	return BatchBlocked
}

// Validate checks structural batch rules before a write.
func (b Batch) Validate() error {
	if b.ID.IsZero() || b.TenantID.IsZero() || b.SinkID.IsZero() || !b.Source.Valid() {
		return fmt.Errorf("%w: batch identity is incomplete", shared.ErrValidation)
	}
	if b.Generation < 1 || b.LeaseToken < 1 || b.PolicyVersion == "" || b.MappingVersion == "" {
		return fmt.Errorf("%w: batch generation, lease, and versions are required", shared.ErrValidation)
	}
	if len(b.Items) == 0 || len(b.Items) > MaxBatchRecords {
		return fmt.Errorf("%w: batch item count is outside 1..%d", shared.ErrValidation, MaxBatchRecords)
	}
	if len(b.Diagnostic) > MaxDiagnosticLen {
		return fmt.Errorf("%w: batch diagnostic is too long", shared.ErrValidation)
	}
	var bytes int
	for i, item := range b.Items {
		if item.Ordinal != i {
			return fmt.Errorf("%w: batch items must be ordered from zero", shared.ErrValidation)
		}
		if item.RecordID == "" || item.PayloadDigest == "" {
			return fmt.Errorf("%w: batch item %d needs an id and digest", shared.ErrValidation, i)
		}
		if err := item.Position.Validate(); err != nil {
			return err
		}
		if item.Position.Source != b.Source {
			return fmt.Errorf("%w: batch item source does not match the batch", shared.ErrValidation)
		}
		bytes += len(item.RecordID) + len(item.PayloadDigest)
	}
	if bytes > MaxBatchBytes {
		return fmt.Errorf("%w: batch identity bytes exceed the cap", shared.ErrValidation)
	}
	return nil
}
