package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// NotificationOutbox is the in-memory twin of the Postgres outbox. It joins the memory
// TenantTransactionRunner, so a rolled-back transaction leaves no record, and applies the same
// idempotency and activation rules.
type NotificationOutbox struct {
	mu                 sync.Mutex
	records            map[sourceRecordKey]outboxEntry
	approvalRecipients map[sourceRecordKey][]shared.ID
	activated          map[shared.ID]time.Time
	deferred           map[*tenantTransaction]map[sourceRecordKey]pendingOutboxEntry
}

type outboxEntry struct {
	record    notification.SourceRecord
	processed bool
}

// pendingOutboxEntry belongs only to its owning tenant transaction. Polling and
// recipient reads intentionally cannot see it: publishing it before the
// producer's audit commits would let a worker create durable events for a
// transaction that subsequently rolls back.
type pendingOutboxEntry struct {
	record     notification.SourceRecord
	recipients []shared.ID
	approval   bool
}

type sourceRecordKey struct {
	tenant   shared.ID
	kind, id string
}

var _ ports.NotificationOutbox = (*NotificationOutbox)(nil)
var _ ports.ApprovalNotificationOutbox = (*NotificationOutbox)(nil)
var _ ports.ApprovalNotificationRecipientReader = (*NotificationOutbox)(nil)

func NewNotificationOutbox() *NotificationOutbox {
	return &NotificationOutbox{
		records:            map[sourceRecordKey]outboxEntry{},
		approvalRecipients: map[sourceRecordKey][]shared.ID{},
		activated:          map[shared.ID]time.Time{},
		deferred:           map[*tenantTransaction]map[sourceRecordKey]pendingOutboxEntry{},
	}
}

// AppendApprovalSource mirrors the PostgreSQL first-source-wins behavior: the
// immutable recipient snapshot is committed or rolled back with the outbox
// record, and a replay never unions later reviewers into the first roster.
func (o *NotificationOutbox) AppendApprovalSource(ctx context.Context, record notification.SourceRecord, recipients []shared.ID) error {
	if err := record.Normalize(); err != nil {
		return err
	}
	transaction, ok := ctx.Value(tenantTransactionKey{}).(*tenantTransaction)
	if !ok {
		return fmt.Errorf("%w: approval notification append requires a tenant transaction", shared.ErrValidation)
	}
	if transaction.tenantID != record.TenantID {
		return fmt.Errorf("%w: approval notification record belongs to another tenant", shared.ErrValidation)
	}
	return o.appendDeferred(ctx, transaction, record, memoryApprovalRecipientIDs(recipients), true)
}

func (o *NotificationOutbox) ApprovalNotificationRecipients(ctx context.Context, tenant shared.ID, sourceKind, sourceID string) ([]shared.ID, error) {
	if current, ok := shared.TenantFrom(ctx); ok && current != tenant {
		return nil, fmt.Errorf("%w: approval recipient tenant mismatch", shared.ErrValidation)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]shared.ID(nil), o.approvalRecipients[sourceRecordKey{tenant: tenant, kind: sourceKind, id: sourceID}]...), nil
}

func memoryApprovalRecipientIDs(ids []shared.ID) []shared.ID {
	seen := map[shared.ID]struct{}{}
	for _, id := range ids {
		if !id.IsZero() {
			seen[id] = struct{}{}
		}
	}
	out := make([]shared.ID, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Activate records when the tenant turned notifications on; records dated earlier are dropped.
// It stands in for the framework activation row of notification_source_state.
func (o *NotificationOutbox) Activate(tenant shared.ID, at time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.activated[tenant] = at.UTC()
}

func (o *NotificationOutbox) Append(ctx context.Context, record notification.SourceRecord) error {
	if err := record.Normalize(); err != nil {
		return err
	}
	transaction, ok := ctx.Value(tenantTransactionKey{}).(*tenantTransaction)
	if !ok {
		return fmt.Errorf("%w: notification outbox append requires a tenant transaction", shared.ErrValidation)
	}
	if transaction.tenantID != record.TenantID {
		return fmt.Errorf("%w: notification outbox record belongs to another tenant", shared.ErrValidation)
	}
	return o.appendDeferred(ctx, transaction, record, nil, false)
}

// appendDeferred reserves the source key inside the producer transaction and
// makes it visible only after that transaction commits. The transaction-local
// reservation preserves first-source-wins when the same source is appended
// twice before commit without exposing it to a concurrent poll.
func (o *NotificationOutbox) appendDeferred(ctx context.Context, transaction *tenantTransaction, record notification.SourceRecord, recipients []shared.ID, approval bool) error {
	key := sourceRecordKey{tenant: record.TenantID, kind: record.SourceKind, id: record.SourceID}
	o.mu.Lock()
	activatedAt, active := o.activated[record.TenantID]
	if _, exists := o.records[key]; exists || !active || record.OccurredAt.Before(activatedAt) {
		o.mu.Unlock()
		return nil
	}
	pending := o.deferred[transaction]
	if pending == nil {
		pending = map[sourceRecordKey]pendingOutboxEntry{}
		o.deferred[transaction] = pending
	}
	if _, exists := pending[key]; exists {
		o.mu.Unlock()
		return nil
	}
	pending[key] = pendingOutboxEntry{record: cloneSourceRecord(record), recipients: append([]shared.ID(nil), recipients...), approval: approval}
	o.mu.Unlock()

	registerTenantCommit(ctx, func() { o.publishDeferred(transaction, key) })
	registerTenantRollback(ctx, func() { o.discardDeferred(transaction, key) })
	return nil
}

func (o *NotificationOutbox) publishDeferred(transaction *tenantTransaction, key sourceRecordKey) {
	o.mu.Lock()
	defer o.mu.Unlock()
	pending := o.deferred[transaction]
	entry, ok := pending[key]
	if !ok {
		return
	}
	delete(pending, key)
	if len(pending) == 0 {
		delete(o.deferred, transaction)
	}
	if _, exists := o.records[key]; exists {
		return
	}
	o.records[key] = outboxEntry{record: cloneSourceRecord(entry.record)}
	if entry.approval {
		o.approvalRecipients[key] = append([]shared.ID(nil), entry.recipients...)
	}
}

func (o *NotificationOutbox) discardDeferred(transaction *tenantTransaction, key sourceRecordKey) {
	o.mu.Lock()
	defer o.mu.Unlock()
	pending := o.deferred[transaction]
	if pending == nil {
		return
	}
	delete(pending, key)
	if len(pending) == 0 {
		delete(o.deferred, transaction)
	}
}

// Records returns the tenant's committed records, processed or not, in drain order.
func (o *NotificationOutbox) Records(tenant shared.ID) []notification.SourceRecord {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.collect(tenant, 0, func(outboxEntry) bool { return true })
}

// pending returns up to limit unprocessed records of the tenant in drain order: occurrence time,
// then source key, as the Postgres poller orders them.
func (o *NotificationOutbox) pending(tenant shared.ID, limit int) []notification.SourceRecord {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.collect(tenant, limit, func(entry outboxEntry) bool { return !entry.processed })
}

func (o *NotificationOutbox) markProcessed(record notification.SourceRecord) {
	o.mu.Lock()
	defer o.mu.Unlock()
	key := sourceRecordKey{tenant: record.TenantID, kind: record.SourceKind, id: record.SourceID}
	if entry, ok := o.records[key]; ok {
		entry.processed = true
		o.records[key] = entry
	}
}

// isActivated reports whether the tenant's notification framework has been activated.
func (o *NotificationOutbox) isActivated(tenant shared.ID) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, ok := o.activated[tenant]
	return ok
}

func (o *NotificationOutbox) tenants() []shared.ID {
	o.mu.Lock()
	defer o.mu.Unlock()
	seen := map[shared.ID]bool{}
	for key := range o.records {
		seen[key.tenant] = true
	}
	for tenant := range o.activated {
		seen[tenant] = true
	}
	return sortedTenants(seen)
}

func (o *NotificationOutbox) collect(tenant shared.ID, limit int, keep func(outboxEntry) bool) []notification.SourceRecord {
	var out []notification.SourceRecord
	for key, entry := range o.records {
		if key.tenant == tenant && keep(entry) {
			out = append(out, cloneSourceRecord(entry.record))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].OccurredAt.Before(out[j].OccurredAt)
		}
		if out[i].SourceKind != out[j].SourceKind {
			return out[i].SourceKind < out[j].SourceKind
		}
		return out[i].SourceID < out[j].SourceID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func sortedTenants(set map[shared.ID]bool) []shared.ID {
	out := make([]shared.ID, 0, len(set))
	for tenant := range set {
		out = append(out, tenant)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func cloneSourceRecord(record notification.SourceRecord) notification.SourceRecord {
	record.Data = append([]byte(nil), record.Data...)
	record.Context = append([]byte(nil), record.Context...)
	return record
}
