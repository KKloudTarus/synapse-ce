package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/orgidentity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// CredentialLocator is intentionally the only adapter that reads enterprise human credentials
// before tenant binding. Its SELECT is an exact primary-key equality and its result contains only
// organization, closed credential kind and target id.
type CredentialLocator struct{ pool *pgxpool.Pool }

func NewCredentialLocator(pool *pgxpool.Pool) (*CredentialLocator, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: credential locator requires pool", shared.ErrValidation)
	}
	return &CredentialLocator{pool: pool}, nil
}

var _ ports.CredentialLocatorResolver = (*CredentialLocator)(nil)
var _ ports.CredentialLocatorWriter = (*CredentialLocator)(nil)

func (s *CredentialLocator) ResolveExactHash(ctx context.Context, digest string) (orgidentity.CredentialLocator, error) {
	var organizationID, kind, credentialID string
	err := s.pool.QueryRow(ctx, `SELECT organization_id,credential_kind,credential_id FROM credential_index WHERE digest=$1`, digest).
		Scan(&organizationID, &kind, &credentialID)
	if errors.Is(err, pgx.ErrNoRows) {
		return orgidentity.CredentialLocator{}, shared.ErrNotFound
	}
	if err != nil {
		return orgidentity.CredentialLocator{}, fmt.Errorf("resolve exact credential hash: %w", err)
	}
	locator, err := orgidentity.NewCredentialLocator(digest, shared.ID(organizationID), orgidentity.CredentialKind(kind), shared.ID(credentialID))
	if err != nil {
		// Persisted locator corruption is a dependency/data-integrity failure, never an invalid
		// credential. Preserve the cause for internal logs while public D2 mapping stays generic.
		return orgidentity.CredentialLocator{}, fmt.Errorf("decode credential locator: %w", err)
	}
	return locator, nil
}

func (s *CredentialLocator) PutExactHash(ctx context.Context, locator orgidentity.CredentialLocator) error {
	validated, err := orgidentity.NewCredentialLocator(locator.Digest, locator.OrganizationID, locator.Kind, locator.CredentialID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO credential_index(digest,organization_id,credential_kind,credential_id) VALUES($1,$2,$3,$4)`,
		validated.Digest, validated.OrganizationID.String(), string(validated.Kind), validated.CredentialID.String())
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return fmt.Errorf("credential digest or target already exists: %w", shared.ErrConflict)
	}
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return fmt.Errorf("credential organization does not exist: %w", shared.ErrForbidden)
	}
	return fmt.Errorf("put exact credential hash: %w", err)
}

func (s *CredentialLocator) DeleteExactHash(ctx context.Context, digest string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM credential_index WHERE digest=$1`, digest)
	if err != nil {
		return fmt.Errorf("delete exact credential hash: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return shared.ErrNotFound
	}
	return nil
}
