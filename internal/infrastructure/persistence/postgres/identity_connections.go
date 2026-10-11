package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.IdentityConnectionStore = (*IdentityFoundationStore)(nil)

const connectionProjection = `c.tenant_id,c.id,c.display_name,c.trust_namespace,c.enabled,c.revision,
 (SELECT max(r.revision) FROM identity_connection_revisions r WHERE r.tenant_id=c.tenant_id AND r.connection_id=c.id),
 c.version,c.epoch,COALESCE((SELECT t.state='passed' FROM identity_connection_tests t
 WHERE t.tenant_id=c.tenant_id AND t.connection_id=c.id AND t.revision=c.revision
 ORDER BY t.tested_at DESC,t.id DESC LIMIT 1),false),r.settings,r.revision`

func scanConnection(row pgx.Row) (ports.IdentityConnection, error) {
	var c ports.IdentityConnection
	var settings []byte
	err := row.Scan(&c.TenantID, &c.ID, &c.DisplayName, &c.Issuer, &c.Enabled, &c.Revision, &c.DraftRevision, &c.Version, &c.Epoch, &c.TestPassed, &settings, &c.SettingsRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, shared.ErrNotFound
	}
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(settings, &c.Settings); err != nil {
		return c, fmt.Errorf("decode OIDC connection settings: %w", err)
	}
	return c, nil
}

func connectionByRevision(ctx context.Context, tx pgx.Tx, tenant, id shared.ID, revision int) (ports.IdentityConnection, error) {
	return scanConnection(tx.QueryRow(ctx, `SELECT `+connectionProjection+` FROM identity_connections c
 JOIN identity_connection_revisions r ON r.tenant_id=c.tenant_id AND r.connection_id=c.id AND r.revision=CASE WHEN $3=0 THEN c.revision ELSE $3 END
 WHERE c.tenant_id=$1 AND c.id=$2 AND c.protocol='oidc'`, tenant.String(), id.String(), revision))
}

func (s *IdentityFoundationStore) GetIdentityConnection(ctx context.Context, tenant, id shared.ID, revision int) (ports.IdentityConnection, error) {
	var out ports.IdentityConnection
	err := s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		out, err = connectionByRevision(ctx, tx, tenant, id, revision)
		return err
	})
	return out, err
}

func (s *IdentityFoundationStore) ListIdentityConnections(ctx context.Context, tenant shared.ID, eligibleOnly bool) ([]ports.IdentityConnection, error) {
	out := []ports.IdentityConnection{}
	err := s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+connectionProjection+` FROM identity_connections c JOIN identity_connection_revisions r
 ON r.tenant_id=c.tenant_id AND r.connection_id=c.id AND r.revision=c.revision WHERE c.tenant_id=$1 AND c.protocol='oidc'
 AND (NOT $2 OR c.enabled AND COALESCE((SELECT t.state='passed' FROM identity_connection_tests t
 WHERE t.tenant_id=c.tenant_id AND t.connection_id=c.id AND t.revision=c.revision ORDER BY t.tested_at DESC,t.id DESC LIMIT 1),false))
 ORDER BY c.display_name,c.id LIMIT 101`, tenant.String(), eligibleOnly)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanConnection(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		if len(out) > 100 {
			return fmt.Errorf("%w: organization connection limit exceeded", shared.ErrSaturated)
		}
		return rows.Err()
	})
	return out, err
}

// identityAdmin fences authenticated administration against membership/person/session changes.
// Bootstrap eligibility is explicit, short lived, and bound to the authenticated deployment actor.
func identityAdmin(ctx context.Context, tx pgx.Tx, tenant shared.ID, proof ports.IdentityAdminProof) error {
	if proof.Recovery {
		return shared.ErrForbidden
	}
	p := proof.Principal
	if p.TenantID != tenant.String() || proof.At.IsZero() {
		return shared.ErrForbidden
	}
	if p.IsBootstrap() {
		if proof.Bootstrap == nil || !proof.Bootstrap.Active(proof.At) || proof.Bootstrap.Principal.Credential.ID != p.Credential.ID {
			return shared.ErrForbidden
		}
		return nil
	}
	if p.Credential.Kind != authz.KindBrowserSession || p.PersonID == "" || p.MembershipID == "" || p.Role != user.RoleAdmin || !authz.RecentlyAuthenticated(p, proof.At) {
		return shared.ErrForbidden
	}
	var digest string
	var epoch int64
	err := tx.QueryRow(ctx, `SELECT c.digest,s.person_epoch FROM identity_sessions s
 JOIN identity_credentials c ON c.tenant_id=s.tenant_id AND c.id=s.credential_id AND c.state='active'
 JOIN identity_memberships m ON m.tenant_id=s.tenant_id AND m.id=s.membership_id AND m.person_id=s.person_id
 JOIN identity_connections x ON x.tenant_id=s.tenant_id AND x.id=s.connection_id AND x.enabled
 WHERE s.tenant_id=$1 AND s.id=$2 AND s.person_id=$3 AND s.membership_id=$4 AND s.revoked_at IS NULL AND s.expires_at>$5
 AND s.origin_at+$6::interval>$5 AND s.authenticated_at=$7 AND m.state='active' AND m.role='admin'
 AND m.epoch=s.membership_epoch AND x.epoch=s.connection_epoch
	 FOR UPDATE OF s,c,m,x`, tenant.String(), p.Credential.ID, p.PersonID, p.MembershipID, proof.At, "12 hours", p.AuthenticatedAt).Scan(&digest, &epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return shared.ErrForbidden
	}
	if err != nil {
		return err
	}
	var currentEpoch *int64
	if err := tx.QueryRow(ctx, `SELECT synapse_identity_lock_person_epoch($1,$2)`, digest, p.PersonID).Scan(&currentEpoch); err != nil {
		return err
	}
	if currentEpoch == nil || *currentEpoch != epoch {
		return shared.ErrForbidden
	}
	return nil
}

// identityRepairAdmin is deliberately called only by the closed identity repair commands.
// The session and its authority are locked in the same transaction as the mutation.
func identityRepairAdmin(ctx context.Context, tx pgx.Tx, tenant shared.ID, proof ports.IdentityAdminProof, at time.Time) error {
	if !proof.Recovery {
		return identityAdmin(ctx, tx, tenant, proof)
	}
	p := proof.Principal
	if p.Credential.Kind != authz.KindBreakGlass || p.TenantID != tenant.String() || p.Role != user.RoleAdmin || p.PersonID == "" || p.MembershipID == "" {
		return shared.ErrForbidden
	}
	var digest string
	var epoch int64
	err := tx.QueryRow(ctx, `SELECT c.digest,s.person_epoch FROM identity_sessions s
 JOIN identity_credentials c ON c.tenant_id=s.tenant_id AND c.id=s.credential_id AND c.state='active' AND c.kind='break_glass'
 JOIN identity_memberships m ON m.tenant_id=s.tenant_id AND m.id=s.membership_id AND m.person_id=s.person_id
 WHERE s.tenant_id=$1 AND s.id=$2 AND s.person_id=$3 AND s.membership_id=$4 AND s.kind='break_glass'
 AND s.revoked_at IS NULL AND s.expires_at>$5 AND s.origin_at+interval '15 minutes'>$5
 AND m.state='active' AND m.role='admin' AND m.epoch=s.membership_epoch
 FOR UPDATE OF s,c,m`, tenant.String(), p.Credential.ID, p.PersonID, p.MembershipID, at).Scan(&digest, &epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return shared.ErrForbidden
	}
	if err != nil {
		return err
	}
	var current *int64
	if err := tx.QueryRow(ctx, `SELECT synapse_identity_lock_person_epoch($1,$2)`, digest, p.PersonID).Scan(&current); err != nil {
		return err
	}
	if current == nil || *current != epoch {
		return shared.ErrForbidden
	}
	return nil
}

func lockIdentityAdministration(ctx context.Context, tx pgx.Tx, tenant shared.ID) error {
	if _, err := tx.Exec(ctx, `SELECT 1 FROM identity_policies WHERE tenant_id=$1 FOR UPDATE`, tenant.String()); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('identity-administration:'||$1,0))`, tenant.String())
	return err
}

func (s *IdentityFoundationStore) SaveIdentityConnectionDraft(ctx context.Context, d ports.IdentityConnectionDraft, proof ports.IdentityAdminProof) (ports.IdentityConnection, error) {
	if d.ID.IsZero() || strings.TrimSpace(d.DisplayName) == "" || len(d.DisplayName) > 200 || d.Issuer == "" || d.Settings.ClientID == "" || d.Settings.SealedClientSecret == "" {
		return ports.IdentityConnection{}, shared.ErrValidation
	}
	var out ports.IdentityConnection
	err := s.withIdentityTenant(ctx, d.TenantID, func(tx pgx.Tx) error {
		if err := lockIdentityAdministration(ctx, tx, d.TenantID); err != nil {
			return err
		}
		if err := identityRepairAdmin(ctx, tx, d.TenantID, proof, proof.At); err != nil {
			return err
		}
		current, err := connectionByRevision(ctx, tx, d.TenantID, d.ID, 0)
		revision := 1
		if errors.Is(err, shared.ErrNotFound) {
			if d.ExpectedVersion != 0 {
				return shared.ErrConflict
			}
			var count int
			if err = tx.QueryRow(ctx, `SELECT count(*) FROM identity_connections WHERE tenant_id=$1`, d.TenantID.String()).Scan(&count); err != nil {
				return err
			}
			if count >= 100 {
				return shared.ErrSaturated
			}
			if _, err = tx.Exec(ctx, `INSERT INTO identity_connections(tenant_id,id,protocol,trust_namespace,display_name,created_at,updated_at)
 VALUES($1,$2,'oidc',$3,$4,$5,$5)`, d.TenantID.String(), d.ID.String(), d.Issuer, d.DisplayName, proof.At); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			if d.ExpectedVersion != current.Version {
				return shared.ErrConflict
			}
			if current.Issuer != d.Issuer || current.Settings.ClientID != d.Settings.ClientID || current.Settings.RedirectURL != d.Settings.RedirectURL {
				return fmt.Errorf("%w: trust changes require a new connection", shared.ErrConflict)
			}
			revision = current.DraftRevision + 1
			if _, err = tx.Exec(ctx, `UPDATE identity_connections SET display_name=$3,version=version+1,updated_at=$4 WHERE tenant_id=$1 AND id=$2`, d.TenantID.String(), d.ID.String(), d.DisplayName, proof.At); err != nil {
				return err
			}
		}
		settings, err := json.Marshal(d.Settings)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO identity_connection_revisions(tenant_id,connection_id,revision,settings,actor,created_at) VALUES($1,$2,$3,$4,$5,$6)`, d.TenantID.String(), d.ID.String(), revision, settings, proof.Principal.ActorID, proof.At); err != nil {
			return err
		}
		if err = appendTenantAudit(ctx, tx, d.TenantID.String(), ports.AuditEntry{Actor: proof.Principal.ActorID, Action: "identity.connection_draft_saved", Target: d.ID.String(), At: proof.At, Metadata: map[string]string{"issuer": d.Issuer, "client_id": d.Settings.ClientID}}); err != nil {
			return err
		}
		out, err = connectionByRevision(ctx, tx, d.TenantID, d.ID, revision)
		return err
	})
	return out, err
}

func (s *IdentityFoundationStore) RecordIdentityConnectionTest(ctx context.Context, test ports.IdentityConnectionTest, proof ports.IdentityAdminProof) error {
	if test.ID.IsZero() || !test.ExpiresAt.After(test.At) || test.ExpiresAt.After(test.At.Add(24*time.Hour)) {
		return shared.ErrValidation
	}
	return s.withIdentityTenant(ctx, test.TenantID, func(tx pgx.Tx) error {
		if err := lockIdentityAdministration(ctx, tx, test.TenantID); err != nil {
			return err
		}
		if err := identityRepairAdmin(ctx, tx, test.TenantID, proof, proof.At); err != nil {
			return err
		}
		c, err := connectionByRevision(ctx, tx, test.TenantID, test.ConnectionID, test.Revision)
		if err != nil {
			return err
		}
		if c.DraftRevision != test.Revision {
			return shared.ErrConflict
		}
		state := "failed"
		if test.Passed {
			state = "passed"
		}
		if _, err = tx.Exec(ctx, `INSERT INTO identity_connection_tests(tenant_id,id,connection_id,revision,state,tested_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, test.TenantID.String(), test.ID.String(), test.ConnectionID.String(), test.Revision, state, test.At, test.ExpiresAt); err != nil {
			return err
		}
		return appendTenantAudit(ctx, tx, test.TenantID.String(), ports.AuditEntry{Actor: proof.Principal.ActorID, Action: "identity.connection_tested", Target: test.ConnectionID.String(), At: proof.At, Metadata: map[string]string{"result": state}})
	})
}

func (s *IdentityFoundationStore) ActivateIdentityConnection(ctx context.Context, tenant, id shared.ID, revision, version int, proof ports.IdentityAdminProof) (ports.IdentityConnection, error) {
	var out ports.IdentityConnection
	err := s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		if err := lockIdentityAdministration(ctx, tx, tenant); err != nil {
			return err
		}
		if err := identityRepairAdmin(ctx, tx, tenant, proof, proof.At); err != nil {
			return err
		}
		c, err := connectionByRevision(ctx, tx, tenant, id, revision)
		if err != nil {
			return err
		}
		if c.Version != version || c.DraftRevision != revision {
			return shared.ErrConflict
		}
		var passed bool
		if err = tx.QueryRow(ctx, `SELECT COALESCE((SELECT state='passed' AND expires_at>$4 FROM identity_connection_tests
 WHERE tenant_id=$1 AND connection_id=$2 AND revision=$3 ORDER BY tested_at DESC,id DESC LIMIT 1),false)`, tenant.String(), id.String(), revision, proof.At).Scan(&passed); err != nil {
			return err
		}
		if !passed {
			return fmt.Errorf("%w: current revision requires a successful connection test", shared.ErrConflict)
		}
		if _, err = tx.Exec(ctx, `UPDATE identity_connections SET enabled=true,revision=$3,version=version+1,updated_at=$4 WHERE tenant_id=$1 AND id=$2`, tenant.String(), id.String(), revision, proof.At); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE identity_transactions SET consumed_at=$3 WHERE tenant_id=$1 AND connection_id=$2 AND connection_revision<>$4 AND consumed_at IS NULL`, tenant.String(), id.String(), proof.At, revision); err != nil {
			return err
		}
		if err = appendTenantAudit(ctx, tx, tenant.String(), ports.AuditEntry{Actor: proof.Principal.ActorID, Action: "identity.connection_activated", Target: id.String(), At: proof.At}); err != nil {
			return err
		}
		out, err = connectionByRevision(ctx, tx, tenant, id, 0)
		return err
	})
	return out, err
}

func (s *IdentityFoundationStore) DisableIdentityConnection(ctx context.Context, tenant, id shared.ID, version int, proof ports.IdentityAdminProof) (ports.IdentityConnection, error) {
	var out ports.IdentityConnection
	err := s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		if err := lockIdentityAdministration(ctx, tx, tenant); err != nil {
			return err
		}
		if err := identityRepairAdmin(ctx, tx, tenant, proof, proof.At); err != nil {
			return err
		}
		c, err := connectionByRevision(ctx, tx, tenant, id, 0)
		if err != nil {
			return err
		}
		if c.Version != version {
			return shared.ErrConflict
		}
		var requirement string
		if err = tx.QueryRow(ctx, `SELECT COALESCE((SELECT sso_requirement FROM identity_policies WHERE tenant_id=$1),'optional')`, tenant.String()).Scan(&requirement); err != nil {
			return err
		}
		if requirement == "required" {
			var access bool
			if err = tx.QueryRow(ctx, `SELECT synapse_identity_usable_admin_access($1,$2,$3)`, tenant.String(), id.String(), proof.At).Scan(&access); err != nil {
				return err
			}
			if !access {
				return fmt.Errorf("%w: cannot disable the last usable administrator connection", shared.ErrConflict)
			}
		}
		if _, err = tx.Exec(ctx, `UPDATE identity_connections SET enabled=false,version=version+1,updated_at=$3 WHERE tenant_id=$1 AND id=$2`, tenant.String(), id.String(), proof.At); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE identity_transactions SET consumed_at=$3 WHERE tenant_id=$1 AND connection_id=$2 AND consumed_at IS NULL`, tenant.String(), id.String(), proof.At); err != nil {
			return err
		}
		if err = appendTenantAudit(ctx, tx, tenant.String(), ports.AuditEntry{Actor: proof.Principal.ActorID, Action: "identity.connection_disabled", Target: id.String(), At: proof.At}); err != nil {
			return err
		}
		out, err = connectionByRevision(ctx, tx, tenant, id, 0)
		return err
	})
	return out, err
}
