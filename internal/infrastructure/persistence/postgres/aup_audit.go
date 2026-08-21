package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/audit"
	"github.com/KKloudTarus/synapse-ce/internal/domain/aup"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AUPStore persists Acceptable-Use-Policy acceptances to PostgreSQL.
type AUPStore struct{ pool *pgxpool.Pool }

// NewAUPStore returns an AUP store backed by the given pool.
func NewAUPStore(pool *pgxpool.Pool) *AUPStore { return &AUPStore{pool: pool} }

var _ ports.AUPStore = (*AUPStore)(nil)

// Accepted reports whether the given policy version has been accepted.
func (s *AUPStore) Accepted(ctx context.Context, version string) (bool, error) {
	var ok bool
	if err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM aup_acceptances WHERE policy_version=$1)`, version).Scan(&ok); err != nil {
		return false, fmt.Errorf("aup accepted: %w", err)
	}
	return ok, nil
}

// Save records an acceptance, idempotent per (actor, version) – this keeps
// per-actor history (the file dev sink keeps one record per version; both gate
// identically via Accepted's EXISTS-by-version).
// RBAC is enforced at the API edge. Should actor identifiers ever become attacker-
// influenced (e.g. a future external OIDC subject), key idempotency on a
// UNIQUE(actor, policy_version) constraint instead of a concatenated id.
func (s *AUPStore) Save(ctx context.Context, a aup.Acceptance) error {
	id := a.Actor + ":" + a.Version
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO aup_acceptances (id, actor, policy_version, accepted_at) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (id) DO NOTHING`,
		id, a.Actor, a.Version, a.AcceptedAt); err != nil {
		return fmt.Errorf("save aup: %w", err)
	}
	return nil
}

// AuditLog is an append-only, attributable audit log on PostgreSQL.
type AuditLog struct{ pool *pgxpool.Pool }

// NewAuditLog returns an audit log backed by the given pool.
func NewAuditLog(pool *pgxpool.Pool) *AuditLog { return &AuditLog{pool: pool} }

var (
	_ ports.AuditLogger           = (*AuditLog)(nil)
	_ ports.AuditReader           = (*AuditLog)(nil)
	_ ports.IdempotentAuditLogger = (*AuditLog)(nil)
)

// auditChainLock is a fixed key for the transaction-scoped advisory lock that
// serializes audit appends, so the read-head/insert-next step is race-free even
// across connections (the chain head must be read and extended atomically).
const auditChainLock = 0x5359_4E41 // "SYNA"

// scanEntries reads audit rows in result order into entries.
func scanEntries(rows pgx.Rows) ([]ports.AuditEntry, error) {
	defer rows.Close()
	out := []ports.AuditEntry{}
	for rows.Next() {
		var (
			e        ports.AuditEntry
			meta     []byte
			hash     *string
			prevHash *string
		)
		if err := rows.Scan(&e.Actor, &e.Action, &e.Target, &meta, &e.At, &hash, &prevHash); err != nil {
			return nil, fmt.Errorf("scan audit: %w", err)
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &e.Metadata)
		}
		if hash != nil {
			e.Hash = *hash
		}
		if prevHash != nil {
			e.PreviousHash = *prevHash
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// List returns the calling tenant's most recent audit entries (newest first), capped at limit.
func (l *AuditLog) List(ctx context.Context, limit int) (out []ports.AuditEntry, err error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	err = WithContextTenant(ctx, l.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT actor, action, target, metadata, created_at, hash, previous_hash
			   FROM audit_log ORDER BY id DESC LIMIT $1`, limit)
		if err != nil {
			return fmt.Errorf("list audit: %w", err)
		}
		out, err = scanEntries(rows)
		return err
	})
	return out, err
}

// Verify examines only the calling tenant's rows. The historical audit chain is
// global, so omitted links make a tenant-only result unavailable rather than falsely
// claiming a complete integrity check. Server maintenance code may use VerifyGlobal.
func (l *AuditLog) Verify(ctx context.Context) (audit.Report, error) {
	entries, err := l.tenantEntries(ctx)
	if err != nil {
		return audit.Report{}, err
	}
	report := audit.Verify(toRecords(entries))
	firstHashedPrevious := ""
	for _, entry := range entries {
		if entry.Hash != "" {
			firstHashedPrevious = entry.PreviousHash
			break
		}
	}
	if firstHashedPrevious != "" || !report.Intact {
		return audit.Report{
			Unchained: report.Unchained,
			Error:     "tenant-scoped audit verification is unavailable for the global hash chain; use server-only VerifyGlobal",
		}, nil
	}
	return report, nil
}

// VerifyGlobal re-derives the complete, globally linked audit chain. It deliberately
// bypasses tenant visibility and must only be called by server-side maintenance code,
// never by a tenant HTTP endpoint.
func (l *AuditLog) VerifyGlobal(ctx context.Context) (audit.Report, error) {
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return audit.Report{}, fmt.Errorf("global audit verify: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT set_config('app.audit_global_read', 'on', true)"); err != nil {
		return audit.Report{}, fmt.Errorf("global audit verify: enable read: %w", err)
	}
	rows, err := tx.Query(ctx,
		`SELECT actor, action, target, metadata, created_at, hash, previous_hash
		   FROM audit_log ORDER BY id ASC`)
	if err != nil {
		return audit.Report{}, fmt.Errorf("global audit verify: query: %w", err)
	}
	entries, err := scanEntries(rows)
	if err != nil {
		return audit.Report{}, err
	}
	return audit.Verify(toRecords(entries)), nil
}

// MigrationMetadata returns each migration's latest recorded state in version order.
// It makes no schema changes and is intended for offline restore verification.
func (l *AuditLog) MigrationMetadata(ctx context.Context) ([]ports.MigrationMetadata, error) {
	rows, err := l.pool.Query(ctx, `SELECT version_id, is_applied
		FROM (
			SELECT DISTINCT ON (version_id) version_id, is_applied
			FROM goose_db_version
			WHERE version_id > 0
			ORDER BY version_id, id DESC
		) AS latest
		ORDER BY version_id ASC`)
	if err != nil {
		return nil, fmt.Errorf("read migration metadata: %w", err)
	}
	defer rows.Close()
	out := []ports.MigrationMetadata{}
	for rows.Next() {
		var state ports.MigrationMetadata
		if err := rows.Scan(&state.Version, &state.Applied); err != nil {
			return nil, fmt.Errorf("scan migration metadata: %w", err)
		}
		out = append(out, state)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read migration metadata rows: %w", err)
	}
	return out, nil
}

var _ ports.RestoreAuditReader = (*AuditLog)(nil)
var _ ports.RestoreMigrationReader = (*AuditLog)(nil)

func (l *AuditLog) tenantEntries(ctx context.Context) (out []ports.AuditEntry, err error) {
	err = WithContextTenant(ctx, l.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT actor, action, target, metadata, created_at, hash, previous_hash
			   FROM audit_log ORDER BY id ASC`)
		if err != nil {
			return fmt.Errorf("verify audit: %w", err)
		}
		out, err = scanEntries(rows)
		return err
	})
	return out, err
}

// Record appends an immutable audit entry (INSERT only – never update or delete), chaining it
// to the previous row. A transaction-scoped advisory lock serializes the read-head/insert so
// concurrent writers cannot fork the chain. The fork-guard unique index
// (migration 0033) is defense-in-depth on top of the lock: if the lock is ever bypassed, a
// concurrent append yields a 23505 unique violation – Record then re-reads the advanced head
// and re-chains (bounded), parity with the evidence store, rather than surfacing an opaque
// error. On the normal locked path the conflict is unreachable and the loop runs once.
// RecordOnce implements ports.IdempotentAuditLogger. Entries with a deterministic
// metadata idempotency_key are recovered without adding a second chain link.
func (l *AuditLog) RecordOnce(ctx context.Context, e ports.AuditEntry) error {
	if e.Metadata["idempotency_key"] == "" {
		return l.Record(ctx, e)
	}
	const maxAttempts = 8
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err := l.recordOnce(ctx, e)
		if err == nil {
			return nil
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			continue
		}
		return err
	}
	return fmt.Errorf("append idempotent audit entry: %w after %d attempts", shared.ErrConflict, maxAttempts)
}

func (l *AuditLog) Record(ctx context.Context, e ports.AuditEntry) error {
	const maxAttempts = 8
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err := l.recordOnce(ctx, e)
		if err == nil {
			return nil
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			continue // fork race (lock bypassed) – re-read the advanced head + re-chain
		}
		return err
	}
	return fmt.Errorf("append audit entry: %w after %d attempts", shared.ErrConflict, maxAttempts)
}

// recordOnce performs one locked read-head → chain → insert attempt. A 23505 unique violation
// propagates (wrapped) so Record can retry.
func (l *AuditLog) recordOnce(ctx context.Context, e ports.AuditEntry) error {
	tenantID, tenantBound := shared.TenantFrom(ctx)
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("audit tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if tenantBound {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.current_tenant', $1, true)", tenantID.String()); err != nil {
			return fmt.Errorf("audit tx: set tenant: %w", err)
		}
	}
	var rlsEnforced bool
	if err := tx.QueryRow(ctx, "SELECT row_security_active('audit_log'::regclass)").Scan(&rlsEnforced); err != nil {
		return fmt.Errorf("audit tx: inspect RLS: %w", err)
	}
	if tenantBound && rlsEnforced {
		if err := appendTenantAudit(ctx, tx, tenantID.String(), e); err != nil {
			return err
		}
	} else if err := appendAudit(ctx, tx, e); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("audit commit: %w", err)
	}
	return nil
}

// appendAudit extends the audit chain within an existing transaction.
func appendAudit(ctx context.Context, tx pgx.Tx, e ports.AuditEntry) error {
	meta, err := json.Marshal(e.Metadata)
	if err != nil {
		return fmt.Errorf("marshal audit metadata: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(auditChainLock)); err != nil {
		return fmt.Errorf("audit lock: %w", err)
	}
	var prev *string
	if err := tx.QueryRow(ctx,
		`SELECT hash FROM audit_log WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1`).Scan(&prev); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("audit head: %w", err)
	}
	prevHash := ""
	if prev != nil {
		prevHash = *prev
	}
	hash := audit.ComputeHash(prevHash, e.Actor, e.Action, e.Target, e.Metadata, e.At)
	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_log (tenant_id, actor, action, target, metadata, created_at, hash, previous_hash)
		 VALUES ('', $1, $2, $3, $4, $5, $6, $7)`,
		e.Actor, e.Action, e.Target, string(meta), e.At, hash, prevHash); err != nil {
		return fmt.Errorf("insert audit: %w", err)
	}
	return nil
}

func appendTenantAudit(ctx context.Context, tx pgx.Tx, tenantID string, e ports.AuditEntry) error {
	meta, err := json.Marshal(e.Metadata)
	if err != nil {
		return fmt.Errorf("marshal audit metadata: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(auditChainLock)); err != nil {
		return fmt.Errorf("audit lock: %w", err)
	}
	if key := e.Metadata["idempotency_key"]; key != "" {
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM audit_log WHERE tenant_id = $1 AND action = $2 AND idempotency_key = $3)`, tenantID, e.Action, key).Scan(&exists); err != nil {
			return fmt.Errorf("check idempotent audit record: %w", err)
		}
		if exists {
			return nil
		}
	}
	var prev *string
	if err := tx.QueryRow(ctx,
		`SELECT hash FROM audit_log WHERE tenant_id = $1 AND hash_version = 2 AND hash IS NOT NULL ORDER BY id DESC LIMIT 1`, tenantID).Scan(&prev); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("audit head: %w", err)
	}
	prevHash := ""
	if prev != nil {
		prevHash = *prev
	}
	hash := audit.ComputeHash(prevHash, e.Actor, e.Action, e.Target, e.Metadata, e.At)
	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_log (tenant_id, actor, action, target, metadata, idempotency_key, hash_version, created_at, hash, previous_hash)
		 VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), 2, $7, $8, $9)`,
		tenantID, e.Actor, e.Action, e.Target, string(meta), e.Metadata["idempotency_key"], e.At, hash, prevHash); err != nil {
		return fmt.Errorf("insert audit: %w", err) // 23505 propagates for Record's retry
	}
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
