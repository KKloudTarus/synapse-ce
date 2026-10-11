package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

var _ ports.BitbucketWebhookDeduper = (*InboundWebhookRepository)(nil)
var errBitbucketReplay = errors.New("bitbucket replay")

func (s *InboundWebhookRepository) AcceptBitbucketWebhook(ctx context.Context, id ports.InboundWebhookIdentity, requestID, digest string, receive func(context.Context) error) (bool, error) {
	raw, err := hex.DecodeString(digest)
	if s == nil || s.pool == nil || id.TenantID.IsZero() || id.PublicID == "" || id.OwnerKind != "integration" || id.OwnerID == "" ||
		requestID == "" || len(requestID) > 123 || err != nil || len(raw) != 32 || digest != strings.ToLower(digest) || receive == nil {
		return false, fmt.Errorf("%w: invalid Bitbucket delivery identity", shared.ErrValidation)
	}
	err = requireTenant(ctx, s.pool, id.TenantID, func(tx pgx.Tx) error {
		var active bool
		if err := tx.QueryRow(ctx, `SELECT synapse_lock_bitbucket_inbound_webhook($1,$2,$3)`, id.TenantID.String(), id.PublicID, id.OwnerID).Scan(&active); err != nil {
			return err
		}
		if !active {
			return fmt.Errorf("%w: Bitbucket endpoint changed before enqueue", shared.ErrConflict)
		}
		// Separate namespaces share the existing RLS-protected receipt table.
		// The body receipt prevents replay with a changed unsigned request UUID.
		for _, receipt := range []string{"uuid:" + requestID, "body:" + digest} {
			tag, err := tx.Exec(ctx, `INSERT INTO inbound_webhook_events(tenant_id,public_id,provider,event_id,received_at)
				VALUES($1,$2,'bitbucket',$3,now()) ON CONFLICT DO NOTHING`, id.TenantID, id.PublicID, receipt)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return errBitbucketReplay
			}
		}
		return receive(bindTenantTransaction(ctx, id.TenantID, tx))
	})
	if errors.Is(err, errBitbucketReplay) {
		return false, nil
	}
	return err == nil, err
}
