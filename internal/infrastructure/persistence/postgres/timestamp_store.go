package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TimestampStore persists external RFC-3161 tokens for chain heads on PostgreSQL,
// out-of-band from the report. One token per (chain, engagement, head).
type TimestampStore struct{ pool *pgxpool.Pool }

// NewTimestampStore returns a timestamp store backed by the given pool.
func NewTimestampStore(pool *pgxpool.Pool) *TimestampStore { return &TimestampStore{pool: pool} }

var _ ports.TimestampStore = (*TimestampStore)(nil)

// Get returns the stored token for a head, or nil if it is not yet anchored.
func (s *TimestampStore) Get(ctx context.Context, chain string, eng shared.ID, head string) (*ports.TimestampToken, error) {
	var tok ports.TimestampToken
	err := s.pool.QueryRow(ctx,
		`SELECT authority, token FROM timestamp_tokens WHERE chain=$1 AND engagement_id=$2 AND head=$3`,
		chain, eng.String(), head).Scan(&tok.Authority, &tok.Token)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get timestamp token: %w", err)
	}
	return &tok, nil
}

// LatestHead returns the most-recently-anchored head for a chain (ok=false if none) – the
// retained head for out-of-band tail-truncation detection.
func (s *TimestampStore) LatestHead(ctx context.Context, chain string, eng shared.ID) (string, bool, error) {
	var head string
	err := s.pool.QueryRow(ctx,
		`SELECT head FROM timestamp_tokens WHERE chain=$1 AND engagement_id=$2 ORDER BY seq DESC LIMIT 1`,
		chain, eng.String()).Scan(&head)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("latest anchored head: %w", err)
	}
	return head, true, nil
}

// Put stores a token for a head, idempotent per (chain, engagement, head).
func (s *TimestampStore) Put(ctx context.Context, chain string, eng shared.ID, head string, token ports.TimestampToken) error {
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO timestamp_tokens (chain, engagement_id, head, authority, token)
		 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (chain, engagement_id, head) DO NOTHING`,
		chain, eng.String(), head, token.Authority, token.Token); err != nil {
		return fmt.Errorf("put timestamp token: %w", err)
	}
	return nil
}
