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
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AuditLog is an append-only, file-backed audit sink (one JSON object per line).
// Append-only by construction (O_APPEND); replaced by the Postgres adapter. Each
// record is chained to the previous one (audit.ComputeHash) so the log is
// tamper-evident – editing or dropping a line breaks Verify.
type AuditLog struct {
	path string
	mu   sync.Mutex
	// head is the hash of the last appended record; "" before the first append.
	// loaded becomes true once head has been recovered from the file tail so the
	// chain survives a process restart.
	head   string
	loaded bool
}

// NewAuditLog returns an append-only audit log writing JSONL to path.
func NewAuditLog(path string) *AuditLog { return &AuditLog{path: path} }

var (
	_ ports.AuditLogger = (*AuditLog)(nil)
	_ ports.AuditReader = (*AuditLog)(nil)
)

// readAll returns every entry oldest-first (file order), tolerating blank/partial
// lines. Caller holds the mutex.
func (a *AuditLog) readAll() ([]ports.AuditEntry, error) {
	data, err := os.ReadFile(a.path) // #nosec G304 -- operator config path
	if err != nil {
		if os.IsNotExist(err) {
			return []ports.AuditEntry{}, nil
		}
		return nil, fmt.Errorf("audit read: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	out := make([]ports.AuditEntry, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e ports.AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue // tolerate a malformed/partial line
		}
		out = append(out, e)
	}
	return out, nil
}

// List returns the most recent audit entries (newest first), capped at limit, by
// reading the JSONL sink. Dev-scale only (the file is small); Postgres is used in
// any real deployment.
func (a *AuditLog) List(_ context.Context, limit int) ([]ports.AuditEntry, error) {
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
		out = append(out, all[i])
	}
	return out, nil
}

// Verify re-derives the hash chain over the whole log (oldest-first) and reports
// whether it is intact.
func (a *AuditLog) Verify(_ context.Context) (audit.Report, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	all, err := a.readAll()
	if err != nil {
		return audit.Report{}, err
	}
	return audit.Verify(toRecords(all)), nil
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
	if len(all) > 0 {
		a.head = all[len(all)-1].Hash
	}
	a.loaded = true
	return nil
}

// Record appends one audit entry, chaining it to the previous record. The file is
// opened O_APPEND so existing records can never be overwritten in-process.
func (a *AuditLog) Record(ctx context.Context, e ports.AuditEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if dir := filepath.Dir(a.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("audit mkdir: %w", err)
		}
	}
	if err := a.loadHead(); err != nil {
		return err
	}
	e.PreviousHash = a.head
	e.Hash = audit.ComputeHash(a.head, e.Actor, e.Action, e.Target, e.Metadata, e.At)

	b, err := json.Marshal(e)
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
	a.head = e.Hash
	return nil
}

// toRecords maps oldest-first audit entries to chain records for verification.
func toRecords(entries []ports.AuditEntry) []audit.Record {
	recs := make([]audit.Record, len(entries))
	for i, e := range entries {
		recs[i] = audit.Record{
			Actor: e.Actor, Action: e.Action, Target: e.Target,
			Metadata: e.Metadata, At: e.At, Hash: e.Hash, PreviousHash: e.PreviousHash,
		}
	}
	return recs
}
