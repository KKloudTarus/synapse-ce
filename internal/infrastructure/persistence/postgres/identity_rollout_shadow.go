package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.IdentityShadowImporter = (*IdentityRolloutRepository)(nil)

// ImportLegacyOIDCShadow imports the existing fixed-cell OIDC trust tuple and approved subject
// links without changing serving authority. The connection is disabled and has no active revision;
// no secret value is copied into PostgreSQL. D6+ may explicitly test/activate a later revision.
func (repository *IdentityRolloutRepository) ImportLegacyOIDCShadow(ctx context.Context, config ports.LegacyOIDCShadowConfig) (result ports.IdentityShadowImportResult, err error) {
	config.TenantID = shared.TenantOrDefault(config.TenantID)
	config.Issuer = strings.TrimSpace(config.Issuer)
	config.ClientID = strings.TrimSpace(config.ClientID)
	config.RedirectURL = strings.TrimSpace(config.RedirectURL)
	config.Actor = strings.TrimSpace(config.Actor)
	if config.TenantID.IsZero() || config.Issuer == "" || len(config.Issuer) > 2048 || config.ClientID == "" || len(config.ClientID) > 1024 || config.RedirectURL == "" || len(config.RedirectURL) > 2048 || config.Actor == "" || len(config.Actor) > 256 {
		return result, fmt.Errorf("%w: legacy OIDC shadow config is invalid", shared.ErrValidation)
	}

	connectionID := legacyOIDCConnectionID(config.TenantID, config.Issuer, config.ClientID)
	trustIdentifier := legacyOIDCTrustIdentifier(config.Issuer, config.ClientID)
	configuration, err := json.Marshal(map[string]string{
		"issuer":       config.Issuer,
		"client_id":    config.ClientID,
		"redirect_url": config.RedirectURL,
		"source":       "legacy_fixed_oidc_shadow",
	})
	if err != nil {
		return result, fmt.Errorf("encode legacy OIDC shadow config: %w", err)
	}
	if len(configuration) > 32768 {
		return result, fmt.Errorf("%w: legacy OIDC shadow config is too large", shared.ErrValidation)
	}

	err = WithTenant(ctx, repository.pool, config.TenantID.String(), func(tx pgx.Tx) error {
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&now); err != nil {
			return fmt.Errorf("read identity shadow database time: %w", err)
		}
		now = now.UTC()
		var existingProtocol, existingTrust string
		var enabled bool
		var activeRevision pgtype.Int8
		lookupErr := tx.QueryRow(ctx, `SELECT protocol,trust_identifier,enabled,active_revision FROM sso_connections WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, config.TenantID.String(), connectionID.String()).Scan(&existingProtocol, &existingTrust, &enabled, &activeRevision)
		switch {
		case errors.Is(lookupErr, pgx.ErrNoRows):
			if _, err := tx.Exec(ctx, `INSERT INTO sso_connections(tenant_id,id,protocol,trust_identifier,enabled,active_revision,connection_epoch,version,created_at,updated_at)
				VALUES($1,$2,'oidc',$3,false,NULL,1,1,$4,$4)`, config.TenantID.String(), connectionID.String(), trustIdentifier, now); err != nil {
				return fmt.Errorf("create legacy OIDC shadow connection: %w", err)
			}
		case lookupErr != nil:
			return fmt.Errorf("read legacy OIDC shadow connection: %w", lookupErr)
		default:
			if existingProtocol != "oidc" || existingTrust != trustIdentifier || enabled || activeRevision.Valid {
				return fmt.Errorf("%w: existing OIDC shadow connection differs from fixed legacy trust tuple", shared.ErrConflict)
			}
		}

		var revisionConfig string
		revisionErr := tx.QueryRow(ctx, `SELECT configuration::text FROM sso_connection_revisions WHERE tenant_id=$1 AND connection_id=$2 AND revision=1`, config.TenantID.String(), connectionID.String()).Scan(&revisionConfig)
		switch {
		case errors.Is(revisionErr, pgx.ErrNoRows):
			if _, err := tx.Exec(ctx, `INSERT INTO sso_connection_revisions
				(tenant_id,connection_id,revision,protocol,configuration,encrypted_secret_ref,test_status,test_result,created_by,created_at,tested_at)
				VALUES($1,$2,1,'oidc',$3::jsonb,'env:SYNAPSE_OIDC_CLIENT_SECRET','untested','{}'::jsonb,$4,$5,NULL)`,
				config.TenantID.String(), connectionID.String(), string(configuration), config.Actor, now); err != nil {
				return fmt.Errorf("create legacy OIDC shadow revision: %w", err)
			}
		case revisionErr != nil:
			return fmt.Errorf("read legacy OIDC shadow revision: %w", revisionErr)
		default:
			var existing map[string]string
			if err := json.Unmarshal([]byte(revisionConfig), &existing); err != nil {
				return fmt.Errorf("decode existing OIDC shadow revision: %w", err)
			}
			if existing["issuer"] != config.Issuer || existing["client_id"] != config.ClientID || existing["redirect_url"] != config.RedirectURL || existing["source"] != "legacy_fixed_oidc_shadow" {
				return fmt.Errorf("%w: existing OIDC shadow revision differs from fixed legacy configuration", shared.ErrConflict)
			}
		}

		rows, err := tx.Query(ctx, `SELECT user_id,subject FROM oidc_external_identities WHERE tenant_id=$1 AND issuer=$2 ORDER BY id COLLATE "C"`, config.TenantID.String(), config.Issuer)
		if err != nil {
			return fmt.Errorf("list legacy OIDC approved links: %w", err)
		}
		type legacyOIDCLink struct {
			userID  shared.ID
			subject string
		}
		links := make([]legacyOIDCLink, 0)
		for rows.Next() {
			var userID shared.ID
			var subject string
			if err := rows.Scan(&userID, &subject); err != nil {
				return fmt.Errorf("scan legacy OIDC approved link: %w", err)
			}
			links = append(links, legacyOIDCLink{userID: userID, subject: subject})
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate legacy OIDC approved links: %w", err)
		}
		rows.Close()
		for _, link := range links {
			userID, subject := link.userID, link.subject
			if userID.String() == "operator" {
				result.DriftedLinks++
				continue
			}

			// Shadow import never manufactures access. Only an already-projected exact legacy
			// person+membership may receive the subject link.
			var personID shared.ID
			if err := tx.QueryRow(ctx, `SELECT person_id FROM memberships WHERE tenant_id=$1 AND id=$2 AND person_id=$2 AND status IN ('active','suspended')`, config.TenantID.String(), userID.String()).Scan(&personID); errors.Is(err, pgx.ErrNoRows) {
				result.DriftedLinks++
				continue
			} else if err != nil {
				return fmt.Errorf("verify legacy OIDC membership projection: %w", err)
			}

			identityID := legacyOIDCIdentityID(config.TenantID, connectionID, subject)
			var existingMembership, existingPerson shared.ID
			existingErr := tx.QueryRow(ctx, `SELECT membership_id,person_id FROM authentication_identities WHERE tenant_id=$1 AND connection_id=$2 AND protocol_subject=$3`, config.TenantID.String(), connectionID.String(), subject).Scan(&existingMembership, &existingPerson)
			switch {
			case errors.Is(existingErr, pgx.ErrNoRows):
				if _, err := tx.Exec(ctx, `INSERT INTO authentication_identities
					(tenant_id,id,membership_id,person_id,connection_id,protocol_subject,creation_revision,created_at)
					VALUES($1,$2,$3,$3,$4,$5,1,$6)`, config.TenantID.String(), identityID.String(), userID.String(), connectionID.String(), subject, now); err != nil {
					return fmt.Errorf("project legacy OIDC approved link: %w", err)
				}
				result.ProjectedLinks++
			case existingErr != nil:
				return fmt.Errorf("read OIDC shadow identity: %w", existingErr)
			case existingMembership == userID && existingPerson == userID:
				result.UnchangedLinks++
			default:
				// Subject reassignment is explicitly out of scope. Keep the existing evidence and
				// surface drift for the offline gate/operator instead of stealing the subject.
				result.DriftedLinks++
			}
		}
		result.ConnectionID = connectionID
		result.Revision = 1
		return nil
	})
	return result, err
}

func legacyOIDCConnectionID(tenantID shared.ID, issuer, clientID string) shared.ID {
	sum := sha256.Sum256([]byte(tenantID.String() + "\x00" + issuer + "\x00" + clientID))
	return shared.ID("legacy-oidc-" + hex.EncodeToString(sum[:16]))
}

func legacyOIDCIdentityID(tenantID, connectionID shared.ID, subject string) shared.ID {
	sum := sha256.Sum256([]byte(tenantID.String() + "\x00" + connectionID.String() + "\x00" + subject))
	return shared.ID("legacy-oidc-link-" + hex.EncodeToString(sum[:16]))
}

func legacyOIDCTrustIdentifier(issuer, clientID string) string {
	return issuer + "#client_id=" + clientID
}
