package file

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/audit"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AuditLog is an append-only, file-backed audit sink (one JSON object per line).
// Append-only by construction (O_APPEND); replaced by the Postgres adapter. Each
// record is chained to the previous one (audit.ComputeHash) so the log is
// tamper-evident – editing or dropping a line breaks Verify.
type AuditLog struct {
	path string
	mu   sync.Mutex

	// Loaded lazily under mu because construction must not fail if the audit path
	// has not been created yet.
	heads  map[string]string
	loaded bool
}

// auditFileEntry keeps RecordOnce's tenant-scoped identity outside caller metadata.
// Existing tenantless records decode with an empty TenantID for compatibility.
type auditFileEntry struct {
	ports.AuditEntry
	TenantID string `json:"tenant_id,omitempty"`
}

// NewAuditLog returns an append-only audit log writing JSONL to path.
func NewAuditLog(path string) *AuditLog { return &AuditLog{path: path, heads: map[string]string{}} }

var (
	_ ports.AuditLogger           = (*AuditLog)(nil)
	_ ports.AuditReader           = (*AuditLog)(nil)
	_ ports.IdempotentAuditLogger = (*AuditLog)(nil)
)

// readAll returns every entry oldest-first (file order). Caller holds the mutex.
// Every record must be a complete non-blank JSON line; accepting a valid suffix
// after corruption would let Verify report an incomplete chain as intact.
func (a *AuditLog) readAll() ([]auditFileEntry, error) {
	data, err := os.ReadFile(a.path) // #nosec G304 -- operator config path
	if err != nil {
		if os.IsNotExist(err) {
			return []auditFileEntry{}, nil
		}
		return nil, fmt.Errorf("audit read: %w", err)
	}
	if len(data) == 0 {
		return []auditFileEntry{}, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("audit record %d: incomplete final record", strings.Count(string(data), "\n")+1)
	}

	lines := strings.Split(string(data[:len(data)-1]), "\n")
	out := make([]auditFileEntry, 0, len(lines))
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			return nil, fmt.Errorf("audit record %d: blank record", i+1)
		}
		var e auditFileEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("audit decode record %d: %w", i+1, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// List returns the most recent audit entries (newest first), capped at limit, by
// reading the JSONL sink. Dev-scale only (the file is small); Postgres is used in
// any real deployment.
func (a *AuditLog) List(ctx context.Context, limit int) ([]ports.AuditEntry, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return nil, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	all, err := a.readAll()
	if err != nil {
		return nil, err
	}
	out := make([]ports.AuditEntry, 0, limit)
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		if all[i].TenantID == tenantID.String() {
			out = append(out, all[i].AuditEntry)
		}
	}
	return out, nil
}

// Verify re-derives the hash chain over the whole log (oldest-first) and reports
// whether it is intact.
func (a *AuditLog) Verify(ctx context.Context) (audit.Report, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return audit.Report{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	all, err := a.readAll()
	if err != nil {
		return audit.Report{}, err
	}
	entries := make([]auditFileEntry, 0)
	for _, entry := range all {
		if entry.TenantID == tenantID.String() {
			entries = append(entries, entry)
		}
	}
	return audit.Verify(toRecords(entries)), nil
}

// loadHead recovers the chain head from the file tail once per process. Caller
// holds the mutex.
func (a *AuditLog) loadHead() error {
	if a.loaded {
		return nil
	}
	all, err := a.readAll()
	if err != nil {
		return err
	}
	for _, entry := range all {
		if entry.TenantID != "" {
			a.heads[entry.TenantID] = entry.Hash
		}
	}
	a.loaded = true
	return nil
}

// RecordOnce appends an idempotent audit entry, chaining it to the previous record.
// It persists the context tenant with the key, while tenantless records remain global.
func (a *AuditLog) RecordOnce(ctx context.Context, e ports.AuditEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if key := e.Metadata["idempotency_key"]; key != "" {
		all, err := a.readAll()
		if err != nil {
			return err
		}
		tenantID := ""
		if tenant, ok := shared.TenantFrom(ctx); ok {
			tenantID = tenant.String()
		}
		for _, existing := range all {
			if existing.Action == e.Action && existing.Metadata["idempotency_key"] == key && existing.TenantID == tenantID {
				return nil
			}
		}
		return a.recordLocked(auditFileEntry{AuditEntry: e, TenantID: tenantID})
	}
	tenantID := ""
	if tenant, ok := shared.TenantFrom(ctx); ok {
		tenantID = tenant.String()
	}
	return a.recordLocked(auditFileEntry{AuditEntry: e, TenantID: tenantID})
}

func (a *AuditLog) Record(ctx context.Context, e ports.AuditEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	tenantID := ""
	if tenant, ok := shared.TenantFrom(ctx); ok {
		tenantID = tenant.String()
	}
	return a.recordLocked(auditFileEntry{AuditEntry: e, TenantID: tenantID})
}

func (a *AuditLog) recordLocked(entry auditFileEntry) error {
	if dir := filepath.Dir(a.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("audit mkdir: %w", err)
		}
	}
	if err := a.loadHead(); err != nil {
		return err
	}
	e := entry.AuditEntry
	previous := a.heads[entry.TenantID]
	e.PreviousHash = previous
	e.Hash = audit.ComputeHash(previous, e.Actor, e.Action, e.Target, e.Metadata, e.At)
	entry.AuditEntry = e

	b, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit encode: %w", err)
	}
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- operator config path
	if err != nil {
		return fmt.Errorf("audit open: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("audit write: %w", err)
	}
	a.heads[entry.TenantID] = e.Hash
	return nil
}

// toRecords maps oldest-first audit entries to chain records for verification.
func toRecords(entries []auditFileEntry) []audit.Record {
	recs := make([]audit.Record, len(entries))
	for i, entry := range entries {
		e := entry.AuditEntry
		recs[i] = audit.Record{
			Actor: e.Actor, Action: e.Action, Target: e.Target,
			Metadata: e.Metadata, At: e.At, Hash: e.Hash, PreviousHash: e.PreviousHash,
		}
	}
	return recs
}
