package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// InboundWebhookRepository accesses the global routing registry ONLY through
// one narrow migration-owner lookup plus tenant-scoped RLS reads/admission. The
// runtime role has no unscoped row visibility and no direct write privilege.
type InboundWebhookRepository struct{ pool *pgxpool.Pool }

func NewInboundWebhookRepository(pool *pgxpool.Pool) *InboundWebhookRepository {
	return &InboundWebhookRepository{pool: pool}
}

var _ ports.InboundWebhookStore = (*InboundWebhookRepository)(nil)
var _ ports.InboundWebhookAdminStore = (*InboundWebhookRepository)(nil)
var _ ports.InboundWebhookEventDeduper = (*InboundWebhookRepository)(nil)

// LookupInboundWebhook first asks the single privileged lookup for ONLY a
// tenant ID. The sealed keys, owner and status are then read under FORCE RLS
// in that tenant's transaction. Unknown IDs execute a dummy tenant-scoped
// read too, reducing the known-vs-unknown timing difference.
func (s *InboundWebhookRepository) LookupInboundWebhook(ctx context.Context, publicID string) (ports.InboundWebhookEndpoint, bool, error) {
	if s == nil || s.pool == nil || len(publicID) < 32 || len(publicID) > 64 {
		return ports.InboundWebhookEndpoint{}, false, nil
	}
	var tenantID shared.ID
	err := s.pool.QueryRow(ctx,
		"SELECT tenant_id FROM synapse_lookup_inbound_webhook($1)", publicID).Scan(&tenantID)
	known := err == nil && !tenantID.IsZero()
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ports.InboundWebhookEndpoint{}, false, err
	}
	if !known {
		tenantID = "synapse-webhook-unmapped-dummy"
	}

	var e ports.InboundWebhookEndpoint
	e.PublicID = publicID
	var previousExpiresAt *time.Time
	err = requireTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
            SELECT e.owner_kind, e.owner_id, i.provider,
                e.enabled AND i.enabled AND NOT i.archived,
                e.current_version, e.current_sealed, e.previous_sealed,
                e.previous_expires_at, e.revoked_at, e.rate_per_minute
            FROM inbound_webhook_endpoints e
            JOIN integrations i ON i.tenant_id=e.tenant_id AND i.id=e.owner_id
            WHERE e.public_id=$1 AND e.tenant_id=$2
        `, publicID, tenantID).Scan(
			&e.OwnerKind, &e.OwnerID, &e.Provider, &e.Enabled, &e.CurrentVersion,
			&e.CurrentSealed, &e.PreviousSealed, &previousExpiresAt,
			&e.RevokedAt, &e.RatePerMinute,
		)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ports.InboundWebhookEndpoint{}, false, nil
	}
	if err != nil {
		return ports.InboundWebhookEndpoint{}, false, err
	}
	if !known {
		return ports.InboundWebhookEndpoint{}, false, nil
	}
	e.TenantID = tenantID
	if previousExpiresAt != nil {
		e.PreviousExpiresAt = *previousExpiresAt
	}
	return e, true, nil
}

func (s *InboundWebhookRepository) AdmitInboundWebhook(ctx context.Context, identity ports.InboundWebhookIdentity, version int, usedPrevious bool) (int, error) {
	if s == nil || s.pool == nil || identity.PublicID == "" || identity.TenantID.IsZero() ||
		identity.OwnerKind != "integration" || identity.OwnerID == "" || version < 1 {
		return -1, nil
	}
	decision := -1
	err := requireTenant(ctx, s.pool, identity.TenantID, func(tx pgx.Tx) error {
		// A FOR SHARE lock prevents disable/archive racing with the request's
		// admission. A missing, archived or other-tenant owner always denies.
		var active bool
		err := tx.QueryRow(ctx, `
            SELECT enabled AND NOT archived FROM integrations
            WHERE tenant_id=$1 AND id=$2 FOR SHARE
        `, identity.TenantID, identity.OwnerID).Scan(&active)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if !active {
			return nil
		}
		return tx.QueryRow(ctx,
			"SELECT synapse_admit_inbound_webhook($1,$2,$3,$4,$5,$6)",
			identity.PublicID, identity.TenantID.String(),
			identity.OwnerKind, identity.OwnerID, version, usedPrevious,
		).Scan(&decision)
	})
	return decision, err
}

func (s *InboundWebhookRepository) ProcessInboundWebhookEvent(ctx context.Context, identity ports.InboundWebhookIdentity, event ports.InboundWebhookEvent, receive func(context.Context) error) (bool, error) {
	if s == nil || s.pool == nil || identity.PublicID == "" || identity.TenantID.IsZero() ||
		identity.OwnerKind != "integration" || identity.OwnerID == "" || event.Provider == "" ||
		event.EventID == "" || len(event.Provider) > 64 || len(event.EventID) > 128 || receive == nil {
		return false, fmt.Errorf("%w: invalid inbound event identity", shared.ErrValidation)
	}
	digest, err := hex.DecodeString(event.PayloadSHA256)
	if err != nil || len(digest) != 32 || event.PayloadSHA256 != strings.ToLower(event.PayloadSHA256) {
		return false, fmt.Errorf("%w: invalid inbound event digest", shared.ErrValidation)
	}
	claimed := false
	err = requireTenant(ctx, s.pool, identity.TenantID, func(tx pgx.Tx) error {
		// Hold the authenticated owner and endpoint active until enqueue commits.
		// This also prevents a forged same-tenant owner from claiming another hook.
		var active bool
		if err := tx.QueryRow(ctx,
			`SELECT synapse_lock_inbound_webhook_event($1,$2,$3,$4,$5)`,
			identity.TenantID.String(), identity.PublicID, identity.OwnerKind, identity.OwnerID, event.Provider).Scan(&active); err != nil {
			return err
		}
		if !active {
			return fmt.Errorf("%w: inbound webhook changed before enqueue", shared.ErrConflict)
		}
		tag, err := tx.Exec(ctx, `
			INSERT INTO inbound_webhook_events(tenant_id,public_id,provider,event_id,received_at,payload_sha256)
			VALUES($1,$2,$3,$4,now(),$5) ON CONFLICT DO NOTHING
		`, identity.TenantID, identity.PublicID, event.Provider, event.EventID, event.PayloadSHA256)
		if err != nil {
			return err
		}
		claimed = tag.RowsAffected() == 1
		if !claimed {
			return nil
		}
		// The callback's scan status, audit, and job queue writes share this tx.
		// A failed enqueue, canceled request or process crash cannot leave a claim
		// committed independently of its durable work.
		return receive(bindTenantTransaction(ctx, identity.TenantID, tx))
	})
	if err != nil {
		return false, err
	}
	return claimed, nil
}

func (s *InboundWebhookRepository) ClaimInboundWebhookEvent(ctx context.Context, identity ports.InboundWebhookIdentity, provider, eventID string, at time.Time) (bool, error) {
	if s == nil || s.pool == nil || identity.PublicID == "" || identity.TenantID.IsZero() ||
		identity.OwnerKind != "integration" || identity.OwnerID == "" || provider == "" ||
		eventID == "" || len(provider) > 64 || len(eventID) > 128 {
		return false, nil
	}
	claimed := false
	err := requireTenant(ctx, s.pool, identity.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			INSERT INTO inbound_webhook_events(tenant_id,public_id,provider,event_id,received_at)
			VALUES($1,$2,$3,$4,$5)
			ON CONFLICT (tenant_id,public_id,provider,event_id) DO NOTHING
		`, identity.TenantID, identity.PublicID, provider, eventID, at.UTC())
		if err != nil {
			return err
		}
		claimed = tag.RowsAffected() == 1
		return nil
	})
	return claimed, err
}

func (s *InboundWebhookRepository) ReleaseInboundWebhookEvent(ctx context.Context, identity ports.InboundWebhookIdentity, provider, eventID string) error {
	if s == nil || s.pool == nil || identity.PublicID == "" || identity.TenantID.IsZero() ||
		identity.OwnerKind != "integration" || identity.OwnerID == "" || provider == "" || eventID == "" {
		return nil
	}
	return requireTenant(ctx, s.pool, identity.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			DELETE FROM inbound_webhook_events
			WHERE tenant_id=$1 AND public_id=$2 AND provider=$3 AND event_id=$4
		`, identity.TenantID, identity.PublicID, provider, eventID)
		return err
	})
}

func (s *InboundWebhookRepository) GetInboundWebhookForOwner(ctx context.Context, tenantID shared.ID, ownerKind, ownerID string) (ports.InboundWebhookEndpoint, bool, error) {
	if s == nil || s.pool == nil || tenantID.IsZero() || ownerKind != "integration" || ownerID == "" {
		return ports.InboundWebhookEndpoint{}, false, nil
	}
	var e ports.InboundWebhookEndpoint
	var previousExpiresAt *time.Time
	err := requireTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT e.public_id, e.owner_kind, e.owner_id, i.provider,
			       e.enabled, e.current_version, e.current_sealed, e.previous_sealed,
			       e.previous_expires_at, e.revoked_at, e.rate_per_minute
			  FROM inbound_webhook_endpoints e
			  JOIN integrations i ON i.tenant_id=e.tenant_id AND i.id=e.owner_id
			 WHERE e.tenant_id=$1 AND e.owner_kind=$2 AND e.owner_id=$3
		`, tenantID, ownerKind, ownerID).Scan(
			&e.PublicID, &e.OwnerKind, &e.OwnerID, &e.Provider,
			&e.Enabled, &e.CurrentVersion, &e.CurrentSealed, &e.PreviousSealed,
			&previousExpiresAt, &e.RevokedAt, &e.RatePerMinute,
		)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ports.InboundWebhookEndpoint{}, false, nil
	}
	if err != nil {
		return ports.InboundWebhookEndpoint{}, false, err
	}
	e.TenantID = tenantID
	if previousExpiresAt != nil {
		e.PreviousExpiresAt = *previousExpiresAt
	}
	return e, true, nil
}

func (s *InboundWebhookRepository) ProvisionInboundWebhook(ctx context.Context, endpoint ports.InboundWebhookEndpoint) (bool, error) {
	if s == nil || s.pool == nil || endpoint.TenantID.IsZero() || endpoint.PublicID == "" ||
		endpoint.OwnerKind != "integration" || endpoint.OwnerID == "" || endpoint.CurrentVersion != 1 ||
		endpoint.CurrentSealed == "" || endpoint.RatePerMinute < 1 || endpoint.RatePerMinute > 600 {
		return false, nil
	}
	function := "synapse_provision_github_inbound_webhook"
	switch endpoint.Provider {
	case "", "github":
	case "bitbucket":
		function = "synapse_provision_bitbucket_inbound_webhook"
	default:
		return false, nil
	}
	provisioned := false
	err := requireTenant(ctx, s.pool, endpoint.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			"SELECT "+function+"($1,$2,$3,$4,$5)",
			endpoint.TenantID.String(), endpoint.PublicID, endpoint.OwnerID,
			endpoint.CurrentSealed, endpoint.RatePerMinute,
		).Scan(&provisioned)
	})
	return provisioned, err
}

func (s *InboundWebhookRepository) RotateInboundWebhook(ctx context.Context, identity ports.InboundWebhookIdentity, expectedVersion int, currentSealed string, previousExpiresAt time.Time) (bool, error) {
	if s == nil || s.pool == nil || identity.TenantID.IsZero() || identity.PublicID == "" ||
		identity.OwnerKind != "integration" || identity.OwnerID == "" || expectedVersion < 1 ||
		currentSealed == "" || previousExpiresAt.IsZero() {
		return false, nil
	}
	endpoint, found, err := s.GetInboundWebhookForOwner(ctx, identity.TenantID, identity.OwnerKind, identity.OwnerID)
	if err != nil || !found {
		return false, err
	}
	function := "synapse_rotate_github_inbound_webhook"
	switch endpoint.Provider {
	case "github":
	case "bitbucket":
		function = "synapse_rotate_bitbucket_inbound_webhook"
	default:
		return false, nil
	}
	rotated := false
	err = requireTenant(ctx, s.pool, identity.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			"SELECT "+function+"($1,$2,$3,$4,$5,$6)",
			identity.TenantID.String(), identity.PublicID, identity.OwnerID,
			expectedVersion, currentSealed, previousExpiresAt.UTC(),
		).Scan(&rotated)
	})
	return rotated, err
}
