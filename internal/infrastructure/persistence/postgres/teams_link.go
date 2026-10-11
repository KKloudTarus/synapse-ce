package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Microsoft Teams linking (#1420, migration 0229).

// teamsLinkQuota is how many link attempts one person may make per hour, counted in the table email
// and Slack verification requests use.
const teamsLinkQuota = 5

// TeamsLinkOffers reaches the global, owner-only link codes through the two SECURITY DEFINER
// functions of migration 0229. It never opens a tenant session.
type TeamsLinkOffers struct{ pool *pgxpool.Pool }

// NewTeamsLinkOffers returns the offer store.
func NewTeamsLinkOffers(pool *pgxpool.Pool) *TeamsLinkOffers { return &TeamsLinkOffers{pool: pool} }

var _ ports.TeamsLinkOffers = (*TeamsLinkOffers)(nil)

// OfferTeamsLink implements ports.TeamsLinkOffers.
func (s *TeamsLinkOffers) OfferTeamsLink(ctx context.Context, codeDigest, conversationKey, sealed string, expiresAt time.Time) (bool, error) {
	var accepted bool
	err := s.pool.QueryRow(ctx, `SELECT synapse_offer_teams_link($1,$2,$3,$4)`, codeDigest, conversationKey, sealed, expiresAt).Scan(&accepted)
	if err != nil {
		return false, fmt.Errorf("offer Teams link: %w", err)
	}
	return accepted, nil
}

var _ ports.TeamsContactStore = (*UserContactStore)(nil)

// CountTeamsLinkAttempt implements ports.TeamsContactStore.
func (s *UserContactStore) CountTeamsLinkAttempt(ctx context.Context, tenant, user, requestID shared.ID, at time.Time) error {
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := lockEnabledUser(ctx, tx, tenant, user); err != nil {
			return err
		}
		var recent int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM user_contact_verification_requests WHERE tenant_id=$1 AND user_id=$2 AND created_at>$3`, tenant, user, at.Add(-time.Hour)).Scan(&recent); err != nil {
			return err
		}
		if recent >= teamsLinkQuota {
			return fmt.Errorf("%w: link attempts rate limited", shared.ErrConflict)
		}
		_, err := tx.Exec(ctx, `INSERT INTO user_contact_verification_requests(tenant_id,id,user_id,created_at) VALUES($1,$2,$3,$4)`, tenant, requestID, user, at)
		return err
	})
	if err != nil {
		return contactError("count Teams link attempt", err)
	}
	return nil
}

// LinkTeamsContact implements ports.TeamsContactStore. The code is claimed with
// synapse_claim_teams_link inside the tenant transaction, so its deletion commits or rolls back
// with the contact.
func (s *UserContactStore) LinkTeamsContact(ctx context.Context, tenant, user shared.ID, codeDigest string, link ports.TeamsLinker) (ports.UserContact, bool, error) {
	var out ports.UserContact
	found := false
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := lockEnabledUser(ctx, tx, tenant, user); err != nil {
			return err
		}
		var offer string
		err := tx.QueryRow(ctx, `SELECT sealed_reference FROM synapse_claim_teams_link($1)`, codeDigest).Scan(&offer)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		c, sealed, err := link(offer)
		if err != nil {
			return err
		}
		if c.TenantID != tenant || c.UserID != user {
			return fmt.Errorf("%w: Teams contact for another user", shared.ErrValidation)
		}
		found = true
		// Linking the same Teams account again replaces it, and with it the stored conversation.
		if _, err := tx.Exec(ctx, `DELETE FROM user_contacts WHERE tenant_id=$1 AND user_id=$2 AND kind='teams' AND value=$3`, c.TenantID, c.UserID, c.Value); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM user_contacts WHERE tenant_id=$1 AND user_id=$2`, c.TenantID, c.UserID).Scan(&count); err != nil {
			return err
		}
		if count >= 20 {
			return fmt.Errorf("%w: contact limit reached", shared.ErrConflict)
		}
		out, err = scanContact(tx.QueryRow(ctx, `INSERT INTO user_contacts (`+contactColumns+`) VALUES ($1,$2,$3,'teams','manual',$4,$5,1,$5,$5) RETURNING `+contactColumns, c.TenantID, c.ID, c.UserID, c.Value, c.CreatedAt))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO user_teams_conversations(tenant_id,contact_id,user_id,sealed_reference,created_at) VALUES($1,$2,$3,$4,$5)`, c.TenantID, c.ID, c.UserID, sealed, c.CreatedAt); err != nil {
			return err
		}
		return appendTenantAudit(ctx, tx, c.TenantID.String(), ports.AuditEntry{Actor: c.UserID.String(), Action: "user_contact.teams_linked", Target: c.ID.String(), At: c.CreatedAt, Metadata: map[string]string{"kind": "teams"}})
	})
	if err != nil {
		return ports.UserContact{}, false, contactError("link Teams contact", err)
	}
	return out, found, nil
}

// TeamsConversation implements ports.TeamsContactStore.
func (s *UserContactStore) TeamsConversation(ctx context.Context, tenant, contact shared.ID) (string, bool, error) {
	var sealed string
	found := false
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT t.sealed_reference FROM user_teams_conversations t
			JOIN user_contacts c ON c.tenant_id=t.tenant_id AND c.id=t.contact_id AND c.user_id=t.user_id AND c.kind='teams' AND c.verified_at IS NOT NULL
			WHERE t.tenant_id=$1 AND t.contact_id=$2`, tenant, contact).Scan(&sealed)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return nil
	})
	return sealed, found, err
}

// lockEnabledUser locks the principal so disabling it cannot race a contact change.
func lockEnabledUser(ctx context.Context, tx pgx.Tx, tenant, user shared.ID) error {
	var enabled bool
	if err := tx.QueryRow(ctx, `SELECT NOT disabled FROM users WHERE ownership_tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, user).Scan(&enabled); errors.Is(err, pgx.ErrNoRows) {
		return shared.ErrNotFound
	} else if err != nil {
		return err
	}
	if !enabled {
		return shared.ErrForbidden
	}
	return nil
}
