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
	mu        sync.Mutex
	records   map[sourceRecordKey]outboxEntry
	activated map[shared.ID]time.Time
}

type outboxEntry struct {
	record    notification.SourceRecord
	processed bool
}

type sourceRecordKey struct {
	tenant   shared.ID
	kind, id string
}

var _ ports.NotificationOutbox = (*NotificationOutbox)(nil)

func NewNotificationOutbox() *NotificationOutbox {
	return &NotificationOutbox{records: map[sourceRecordKey]outboxEntry{}, activated: map[shared.ID]time.Time{}}
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
	o.mu.Lock()
	defer o.mu.Unlock()
	activatedAt, active := o.activated[record.TenantID]
	key := sourceRecordKey{tenant: record.TenantID, kind: record.SourceKind, id: record.SourceID}
	if _, exists := o.records[key]; exists || !active || record.OccurredAt.Before(activatedAt) {
		return nil
	}
	o.records[key] = outboxEntry{record: cloneSourceRecord(record)}
	registerTenantRollback(ctx, func() {
		o.mu.Lock()
		defer o.mu.Unlock()
		delete(o.records, key)
	})
	return nil
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
