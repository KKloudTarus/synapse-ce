package vault

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// PostgresVault persists encrypted credentials on PostgreSQL. The column holds only the
// AES-256-GCM ciphertext (base64) – the master key lives in process memory, never in
// the DB – so a database compromise alone does not yield the secrets.
type PostgresVault struct {
	pool   *pgxpool.Pool
	cipher *Cipher
}

var _ ports.CredentialVault = (*PostgresVault)(nil)

// NewPostgresVault returns a Postgres-backed vault over the cipher.
func NewPostgresVault(pool *pgxpool.Pool, cipher *Cipher) *PostgresVault {
	return &PostgresVault{pool: pool, cipher: cipher}
}

func (v *PostgresVault) Put(ctx context.Context, engagementID shared.ID, name string, secret []byte) error {
	if err := validateName(name); err != nil {
		return err
	}
	ct, err := v.cipher.Seal(secret, aad(engagementID, name))
	if err != nil {
		return err
	}
	if _, err := v.pool.Exec(ctx,
		`INSERT INTO credentials (engagement_id, name, ciphertext, created_at, updated_at)
		 VALUES ($1, $2, $3, now(), now())
		 ON CONFLICT (engagement_id, name) DO UPDATE SET ciphertext = EXCLUDED.ciphertext, updated_at = now()`,
		engagementID.String(), name, ct); err != nil {
		return fmt.Errorf("put credential: %w", err)
	}
	return nil
}

func (v *PostgresVault) Resolve(ctx context.Context, engagementID shared.ID, name string) ([]byte, error) {
	var ct string
	err := v.pool.QueryRow(ctx,
		`SELECT ciphertext FROM credentials WHERE engagement_id=$1 AND name=$2`,
		engagementID.String(), name).Scan(&ct)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("credential %q: %w", name, shared.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("resolve credential: %w", err)
	}
	return v.cipher.Open(ct, aad(engagementID, name))
}

func (v *PostgresVault) List(ctx context.Context, engagementID shared.ID) ([]ports.CredentialMeta, error) {
	rows, err := v.pool.Query(ctx,
		`SELECT name, created_at, updated_at FROM credentials WHERE engagement_id=$1 ORDER BY name`,
		engagementID.String())
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	defer rows.Close()
	var out []ports.CredentialMeta
	for rows.Next() {
		var m ports.CredentialMeta
		if err := rows.Scan(&m.Name, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan credential: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (v *PostgresVault) Delete(ctx context.Context, engagementID shared.ID, name string) error {
	tag, err := v.pool.Exec(ctx,
		`DELETE FROM credentials WHERE engagement_id=$1 AND name=$2`, engagementID.String(), name)
	if err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("credential %q: %w", name, shared.ErrNotFound)
	}
	return nil
}
