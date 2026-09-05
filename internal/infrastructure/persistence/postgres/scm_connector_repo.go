package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scmconnector"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// SCMConnectorRepository persists tenant-scoped source-control connectors on PostgreSQL. The
// token is sealed with the vault cipher (AES-256-GCM, AAD-bound to tenant+id) so the column
// holds only ciphertext; the plaintext is returned ONLY by ResolveGitCredential at clone time.
// scm_connectors is RLS-protected (migration 0133): every statement runs inside a WithTenant
// transaction and carries an explicit tenant_id predicate as defense in depth.
type SCMConnectorRepository struct {
	pool   *pgxpool.Pool
	cipher *vault.Cipher
}

// NewSCMConnectorRepository returns a repository over the pool and the vault cipher. The cipher
// is required: without it a token could only be stored in the clear, which the contract forbids.
func NewSCMConnectorRepository(pool *pgxpool.Pool, cipher *vault.Cipher) (*SCMConnectorRepository, error) {
	if pool == nil || cipher == nil {
		return nil, fmt.Errorf("%w: scm connector repository requires a pool and a cipher", shared.ErrValidation)
	}
	return &SCMConnectorRepository{pool: pool, cipher: cipher}, nil
}

var _ ports.SCMConnectorStore = (*SCMConnectorRepository)(nil)

// scmAAD binds a sealed token to its (tenant, connector, host, username) identity. Binding the ROUTING
// fields (host, username) in addition to the ids means a database-write attacker cannot repoint a
// connector at their own host (UPDATE ... SET host='evil') and have the tenant's real token decrypt for
// it: any change to host or username fails the GCM tag check on Open, so the token stays inert.
func scmAAD(tenantID, id shared.ID, host, username string) []byte {
	return []byte("scm:" + tenantID.String() + ":" + id.String() + ":" + host + ":" + username)
}

func ctxTenant(ctx context.Context) (shared.ID, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return "", fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	return tenantID, nil
}

// Put upserts a connector under the caller's tenant, sealing the token bound to the connector's
// (tenant, id, host, username) identity. A token is always required. The UNIQUE(tenant_id, host)
// constraint makes a second connector for the same host a conflict.
func (r *SCMConnectorRepository) Put(ctx context.Context, c scmconnector.Connector, token []byte) error {
	tenantID, err := ctxTenant(ctx)
	if err != nil {
		return err
	}
	if c.ID.IsZero() {
		return fmt.Errorf("%w: connector id is required", shared.ErrValidation)
	}
	if len(token) == 0 {
		return fmt.Errorf("%w: a connector requires a token", shared.ErrValidation)
	}
	c.TenantID = tenantID
	return requireTenant(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		ciphertext, serr := r.cipher.Seal(token, scmAAD(tenantID, c.ID, c.Host, c.Username))
		if serr != nil {
			return fmt.Errorf("seal connector token: %w", serr)
		}
		tag, err := tx.Exec(ctx,
			`INSERT INTO scm_connectors (tenant_id, id, name, provider, host, username, auth_kind, token_ciphertext, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), now())
			 ON CONFLICT (tenant_id, id) DO UPDATE SET
			     name = EXCLUDED.name, provider = EXCLUDED.provider, host = EXCLUDED.host,
			     username = EXCLUDED.username, auth_kind = EXCLUDED.auth_kind,
			     token_ciphertext = EXCLUDED.token_ciphertext, updated_at = now()
			 WHERE scm_connectors.tenant_id = $1`,
			tenantID.String(), c.ID.String(), c.Name, string(c.Provider), c.Host, c.Username, string(c.AuthKind), ciphertext)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" { // UNIQUE(tenant_id, host)
				return fmt.Errorf("%w: a connector already exists for host %s", shared.ErrConflict, c.Host)
			}
			return fmt.Errorf("save connector: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("connector %s belongs to another tenant: %w", c.ID, shared.ErrConflict)
		}
		return nil
	})
}

// List returns the tenant's connectors as metadata (never the token), ordered by host then name.
func (r *SCMConnectorRepository) List(ctx context.Context) ([]ports.SCMConnectorMeta, error) {
	tenantID, err := ctxTenant(ctx)
	if err != nil {
		return nil, err
	}
	var out []ports.SCMConnectorMeta
	err = requireTenant(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, name, provider, host, username, auth_kind, created_at, updated_at
			   FROM scm_connectors WHERE tenant_id = $1 ORDER BY host, name`, tenantID.String())
		if err != nil {
			return fmt.Errorf("list connectors: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			m, serr := scanConnectorMeta(rows)
			if serr != nil {
				return serr
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// Get returns one connector's metadata; ErrNotFound when absent under the tenant.
func (r *SCMConnectorRepository) Get(ctx context.Context, id shared.ID) (ports.SCMConnectorMeta, error) {
	tenantID, err := ctxTenant(ctx)
	if err != nil {
		return ports.SCMConnectorMeta{}, err
	}
	var m ports.SCMConnectorMeta
	err = requireTenant(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT id, name, provider, host, username, auth_kind, created_at, updated_at
			   FROM scm_connectors WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String())
		var serr error
		m, serr = scanConnectorMeta(row)
		if errors.Is(serr, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		return serr
	})
	return m, err
}

// Delete removes one connector; ErrNotFound when absent under the tenant.
func (r *SCMConnectorRepository) Delete(ctx context.Context, id shared.ID) error {
	tenantID, err := ctxTenant(ctx)
	if err != nil {
		return err
	}
	return requireTenant(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM scm_connectors WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String())
		if err != nil {
			return fmt.Errorf("delete connector: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return shared.ErrNotFound
		}
		return nil
	})
}

// ResolveGitCredential returns the credential for a normalized clone-URL host under the caller's
// tenant, opening the sealed token. ok=false when the tenant has no connector for that host.
func (r *SCMConnectorRepository) ResolveGitCredential(ctx context.Context, host string) (ports.GitCredential, bool, error) {
	tenantID, err := ctxTenant(ctx)
	if err != nil {
		return ports.GitCredential{}, false, err
	}
	var cred ports.GitCredential
	found := false
	err = requireTenant(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		var id, username, ciphertext string
		qerr := tx.QueryRow(ctx,
			`SELECT id, username, token_ciphertext FROM scm_connectors WHERE tenant_id = $1 AND host = $2`,
			tenantID.String(), host).Scan(&id, &username, &ciphertext)
		if errors.Is(qerr, pgx.ErrNoRows) {
			return nil
		}
		if qerr != nil {
			return fmt.Errorf("resolve connector for host: %w", qerr)
		}
		token, oerr := r.cipher.Open(ciphertext, scmAAD(tenantID, shared.ID(id), host, username))
		if oerr != nil {
			return fmt.Errorf("open connector token: %w", oerr)
		}
		cred = ports.GitCredential{Username: username, Token: token}
		found = true
		return nil
	})
	return cred, found, err
}

func scanConnectorMeta(row pgx.Row) (ports.SCMConnectorMeta, error) {
	var m ports.SCMConnectorMeta
	var provider, authKind string
	if err := row.Scan(&m.ID, &m.Name, &provider, &m.Host, &m.Username, &authKind, &m.CreatedAt, &m.UpdatedAt); err != nil {
		return ports.SCMConnectorMeta{}, err
	}
	m.Provider = scmconnector.Provider(provider)
	m.AuthKind = scmconnector.AuthKind(authKind)
	return m, nil
}
