package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type UserContactStore struct{ pool *pgxpool.Pool }

func NewUserContactStore(pool *pgxpool.Pool) *UserContactStore { return &UserContactStore{pool: pool} }

var _ ports.UserContactStore = (*UserContactStore)(nil)

const contactColumns = `tenant_id,id,user_id,kind,source,value,verified_at,version,created_at,updated_at`

func scanContact(row pgx.Row) (ports.UserContact, error) {
	var c ports.UserContact
	err := row.Scan(&c.TenantID, &c.ID, &c.UserID, &c.Kind, &c.Source, &c.Value, &c.VerifiedAt, &c.Version, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

func (s *UserContactStore) List(ctx context.Context, tenantID, userID shared.ID) ([]ports.UserContact, error) {
	result := make([]ports.UserContact, 0)
	err := WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+contactColumns+` FROM user_contacts WHERE tenant_id=$1 AND user_id=$2 ORDER BY created_at,id LIMIT 100`, tenantID, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c ports.UserContact
			if err := rows.Scan(&c.TenantID, &c.ID, &c.UserID, &c.Kind, &c.Source, &c.Value, &c.VerifiedAt, &c.Version, &c.CreatedAt, &c.UpdatedAt); err != nil {
				return err
			}
			result = append(result, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list user contacts: %w", err)
	}
	return result, nil
}

func (s *UserContactStore) Create(ctx context.Context, c ports.UserContact) (ports.UserContact, error) {
	var out ports.UserContact
	err := WithTenant(ctx, s.pool, c.TenantID.String(), func(tx pgx.Tx) error {
		// Lock the principal so disable/move cannot race contact creation.
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT NOT disabled FROM users WHERE ownership_tenant_id=$1 AND id=$2 FOR UPDATE`, c.TenantID, c.UserID).Scan(&enabled); errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if err != nil {
			return err
		}
		if !enabled {
			return shared.ErrForbidden
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM user_contacts WHERE tenant_id=$1 AND user_id=$2`, c.TenantID, c.UserID).Scan(&count); err != nil {
			return err
		}
		if count >= 20 {
			return fmt.Errorf("%w: contact limit reached", shared.ErrConflict)
		}
		var err error
		out, err = scanContact(tx.QueryRow(ctx, `INSERT INTO user_contacts (`+contactColumns+`) VALUES ($1,$2,$3,$4,'manual',$5,NULL,1,$6,$6) RETURNING `+contactColumns, c.TenantID, c.ID, c.UserID, c.Kind, c.Value, c.CreatedAt))
		if err != nil {
			return err
		}
		return appendTenantAudit(ctx, tx, c.TenantID.String(), ports.AuditEntry{Actor: c.UserID.String(), Action: "user_contact.added", Target: c.ID.String(), At: c.CreatedAt, Metadata: map[string]string{"kind": c.Kind}})
	})
	if err != nil {
		return ports.UserContact{}, contactError("create user contact", err)
	}
	return out, nil
}

func (s *UserContactStore) Delete(ctx context.Context, tenantID, userID, contactID shared.ID) error {
	err := WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM user_contacts WHERE tenant_id=$1 AND user_id=$2 AND id=$3 AND source='manual'`, tenantID, userID, contactID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return shared.ErrNotFound
		}
		return appendTenantAudit(ctx, tx, tenantID.String(), ports.AuditEntry{Actor: userID.String(), Action: "user_contact.removed", Target: contactID.String(), At: time.Now().UTC()})
	})
	if err != nil {
		return fmt.Errorf("delete user contact: %w", err)
	}
	return nil
}

func (s *UserContactStore) RequestVerification(ctx context.Context, c ports.UserContactChallenge, jobID shared.ID) error {
	err := WithTenant(ctx, s.pool, c.TenantID.String(), func(tx pgx.Tx) error {
		// All challenges for one user serialize on the principal row, including the
		// hourly quota and resend interval. No in-memory rate limiter is trusted.
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT NOT disabled FROM users WHERE ownership_tenant_id=$1 AND id=$2 FOR UPDATE`, c.TenantID, c.UserID).Scan(&enabled); errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if err != nil {
			return err
		}
		if !enabled {
			return shared.ErrForbidden
		}
		var version int
		var verified *time.Time
		var kind string
		if err := tx.QueryRow(ctx, `SELECT version,verified_at,kind FROM user_contacts WHERE tenant_id=$1 AND user_id=$2 AND id=$3 FOR UPDATE`, c.TenantID, c.UserID, c.ContactID).Scan(&version, &verified, &kind); errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if err != nil {
			return err
		}
		if version != c.ContactVersion || verified != nil || kind != "email" {
			return shared.ErrConflict
		}
		var recent int
		var last *time.Time
		if err := tx.QueryRow(ctx, `SELECT count(*),max(created_at) FROM user_contact_verification_requests WHERE tenant_id=$1 AND user_id=$2 AND created_at>$3`, c.TenantID, c.UserID, c.CreatedAt.Add(-time.Hour)).Scan(&recent, &last); err != nil {
			return err
		}
		if recent >= 5 || last != nil && c.CreatedAt.Sub(*last) < time.Minute {
			return fmt.Errorf("%w: verification request rate limited", shared.ErrConflict)
		}
		if _, err := tx.Exec(ctx, `UPDATE user_contact_challenges SET consumed_at=$4 WHERE tenant_id=$1 AND user_id=$2 AND contact_id=$3 AND consumed_at IS NULL`, c.TenantID, c.UserID, c.ContactID, c.CreatedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO user_contact_verification_requests(tenant_id,id,user_id,created_at) VALUES($1,$2,$3,$4)`, c.TenantID, c.ID, c.UserID, c.CreatedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO user_contact_challenges(tenant_id,id,user_id,contact_id,contact_version,code_digest,sealed_code,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, c.TenantID, c.ID, c.UserID, c.ContactID, c.ContactVersion, c.Digest, c.SealedCode, c.ExpiresAt, c.CreatedAt); err != nil {
			return err
		}
		payload, err := json.Marshal(struct {
			ChallengeID shared.ID `json:"challenge_id"`
		}{ChallengeID: c.ID})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO jobs(id,tenant_id,kind,payload,status,available_at) VALUES($1,$2,$3,$4,'queued',now())`, jobID, c.TenantID, "user_contact_verification", payload); err != nil {
			return err
		}
		return appendTenantAudit(ctx, tx, c.TenantID.String(), ports.AuditEntry{Actor: c.UserID.String(), Action: "user_contact.verification_requested", Target: c.ContactID.String(), At: c.CreatedAt})
	})
	if err != nil {
		return contactError("request user contact verification", err)
	}
	return nil
}

func (s *UserContactStore) Verify(ctx context.Context, tenantID, userID, contactID shared.ID, digest func(shared.ID) string, now time.Time) (ports.UserContact, error) {
	var out ports.UserContact
	var verdict error
	err := WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT NOT disabled FROM users WHERE ownership_tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, userID).Scan(&enabled); errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if err != nil {
			return err
		}
		if !enabled {
			return shared.ErrForbidden
		}
		var id shared.ID
		var version, attempts int
		var stored string
		var expiry time.Time
		err := tx.QueryRow(ctx, `SELECT id,contact_version,code_digest,attempts,expires_at FROM user_contact_challenges WHERE tenant_id=$1 AND user_id=$2 AND contact_id=$3 AND consumed_at IS NULL ORDER BY created_at DESC,id DESC LIMIT 1 FOR UPDATE`, tenantID, userID, contactID).Scan(&id, &version, &stored, &attempts, &expiry)
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return err
		}
		out, err = scanContact(tx.QueryRow(ctx, `SELECT `+contactColumns+` FROM user_contacts WHERE tenant_id=$1 AND user_id=$2 AND id=$3 FOR UPDATE`, tenantID, userID, contactID))
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return err
		}
		if version != out.Version || out.VerifiedAt != nil || !now.Before(expiry) || attempts >= 5 {
			verdict = shared.ErrConflict
			return nil
		}
		candidate := digest(id)
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(stored)) != 1 {
			_, err = tx.Exec(ctx, `UPDATE user_contact_challenges SET attempts=attempts+1 WHERE tenant_id=$1 AND id=$2`, tenantID, id)
			if err != nil {
				return err
			}
			verdict = shared.ErrForbidden
			return nil
		}
		if _, err = tx.Exec(ctx, `UPDATE user_contact_challenges SET consumed_at=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, id, now); err != nil {
			return err
		}
		out, err = scanContact(tx.QueryRow(ctx, `UPDATE user_contacts SET verified_at=$4,updated_at=$4 WHERE tenant_id=$1 AND user_id=$2 AND id=$3 AND version=$5 RETURNING `+contactColumns, tenantID, userID, contactID, now, version))
		if err != nil {
			return err
		}
		return appendTenantAudit(ctx, tx, tenantID.String(), ports.AuditEntry{Actor: userID.String(), Action: "user_contact.verified", Target: contactID.String(), At: now})
	})
	if err != nil {
		return ports.UserContact{}, fmt.Errorf("verify user contact: %w", err)
	}
	if verdict != nil {
		return ports.UserContact{}, verdict
	}
	return out, nil
}

func (s *UserContactStore) LoadDelivery(ctx context.Context, tenantID, challengeID shared.ID) (ports.UserContactDelivery, bool, error) {
	var out ports.UserContactDelivery
	var found bool
	err := WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT c.contact_id,c.contact_version,u.value,c.sealed_code FROM user_contact_challenges c JOIN user_contacts u ON u.tenant_id=c.tenant_id AND u.id=c.contact_id AND u.user_id=c.user_id JOIN users p ON p.ownership_tenant_id=c.tenant_id AND p.id=c.user_id WHERE c.tenant_id=$1 AND c.id=$2 AND c.consumed_at IS NULL AND c.sent_at IS NULL AND c.expires_at>now() AND c.attempts<5 AND c.contact_version=u.version AND u.verified_at IS NULL AND NOT p.disabled AND u.kind='email'`, tenantID, challengeID).Scan(&out.ContactID, &out.ContactVersion, &out.Recipient, &out.SealedCode)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out.ChallengeID = challengeID
		found = true
		return nil
	})
	if err != nil {
		return ports.UserContactDelivery{}, false, fmt.Errorf("load contact verification delivery: %w", err)
	}
	return out, found, nil
}

func (s *UserContactStore) MarkSent(ctx context.Context, tenantID, challengeID shared.ID, at time.Time) error {
	return WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		var userID, contactID shared.ID
		err := tx.QueryRow(ctx, `UPDATE user_contact_challenges SET sent_at=$3 WHERE tenant_id=$1 AND id=$2 AND sent_at IS NULL AND consumed_at IS NULL RETURNING user_id,contact_id`, tenantID, challengeID, at).Scan(&userID, &contactID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return appendTenantAudit(ctx, tx, tenantID.String(), ports.AuditEntry{Actor: "system:worker", Action: "user_contact.verification_sent", Target: contactID.String(), At: at, Metadata: map[string]string{"user_id": userID.String()}})
	})
}

func (s *UserContactStore) MarkDeliveryFailed(ctx context.Context, tenantID, challengeID shared.ID, at time.Time) error {
	return WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		var userID, contactID shared.ID
		err := tx.QueryRow(ctx, `UPDATE user_contact_challenges SET consumed_at=$3 WHERE tenant_id=$1 AND id=$2 AND consumed_at IS NULL AND sent_at IS NULL RETURNING user_id,contact_id`, tenantID, challengeID, at).Scan(&userID, &contactID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return appendTenantAudit(ctx, tx, tenantID.String(), ports.AuditEntry{Actor: "system:worker", Action: "user_contact.verification_dead_letter", Target: contactID.String(), At: at, Metadata: map[string]string{"user_id": userID.String()}})
	})
}

func (s *UserContactStore) ImportOIDCEmail(ctx context.Context, tenantID, userID, id shared.ID, issuer, email string, at time.Time) error {
	key := sha256.Sum256([]byte(issuer))
	sourceKey := hex.EncodeToString(key[:])
	err := WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT NOT disabled FROM users WHERE ownership_tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, userID).Scan(&enabled); errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if err != nil {
			return err
		}
		if !enabled {
			return shared.ErrForbidden
		}
		var changedID shared.ID
		err := tx.QueryRow(ctx, `INSERT INTO user_contacts(tenant_id,id,user_id,kind,source,source_key,value,verified_at,version,created_at,updated_at) VALUES($1,$2,$3,'email','oidc',$4,$5,$6,1,$6,$6) ON CONFLICT (tenant_id,user_id,source_key) WHERE source='oidc' DO UPDATE SET value=EXCLUDED.value,verified_at=EXCLUDED.verified_at,version=CASE WHEN user_contacts.value=EXCLUDED.value THEN user_contacts.version ELSE user_contacts.version+1 END,updated_at=EXCLUDED.updated_at WHERE user_contacts.value IS DISTINCT FROM EXCLUDED.value OR user_contacts.verified_at IS NULL RETURNING id`, tenantID, id, userID, sourceKey, email, at).Scan(&changedID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return appendTenantAudit(ctx, tx, tenantID.String(), ports.AuditEntry{Actor: userID.String(), Action: "user_contact.oidc_verified", Target: changedID.String(), At: at})
	})
	if err != nil {
		return contactError("import OIDC contact", err)
	}
	return nil
}

func (s *UserContactStore) RevokeOIDCEmail(ctx context.Context, tenantID, userID shared.ID, issuer string, at time.Time) error {
	key := sha256.Sum256([]byte(issuer))
	err := WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		var changedID shared.ID
		err := tx.QueryRow(ctx, `UPDATE user_contacts SET verified_at=NULL,version=version+1,updated_at=$4 WHERE tenant_id=$1 AND user_id=$2 AND source='oidc' AND source_key=$3 AND verified_at IS NOT NULL RETURNING id`, tenantID, userID, hex.EncodeToString(key[:]), at).Scan(&changedID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return appendTenantAudit(ctx, tx, tenantID.String(), ports.AuditEntry{Actor: userID.String(), Action: "user_contact.oidc_revoked", Target: changedID.String(), At: at})
	})
	if err != nil {
		return fmt.Errorf("revoke OIDC contact: %w", err)
	}
	return nil
}

func contactError(operation string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		err = shared.ErrConflict
	}
	return fmt.Errorf("%s: %w", operation, err)
}
