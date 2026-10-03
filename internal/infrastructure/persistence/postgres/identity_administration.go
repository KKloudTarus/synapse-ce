package postgres

import (
	"context"
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

var _ ports.IdentityAdministrationStore = (*IdentityFoundationStore)(nil)

func (s *IdentityFoundationStore) ListIdentityRoster(ctx context.Context, tenant shared.ID, limit int) (out []ports.IdentityRosterMember, err error) {
	if limit < 1 || limit > 100 {
		return nil, fmt.Errorf("%w: roster limit", shared.ErrValidation)
	}
	err = s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT m.id,m.person_id,COALESCE(u.name,'Unknown member'),m.role,m.state,m.version FROM identity_memberships m LEFT JOIN users u ON u.ownership_tenant_id=m.tenant_id AND u.id=m.legacy_user_id WHERE m.tenant_id=$1 ORDER BY m.id LIMIT $2`, tenant.String(), limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var m ports.IdentityRosterMember
			var id, p string
			if e = rows.Scan(&id, &p, &m.Name, &m.Role, &m.State, &m.Version); e != nil {
				return e
			}
			m.ID, m.PersonID = shared.ID(id), shared.ID(p)
			out = append(out, m)
		}
		return rows.Err()
	})
	return
}
func (s *IdentityFoundationStore) ChangeIdentityMembershipAdministration(ctx context.Context, c ports.IdentityMembershipAdministration) (out ports.IdentityMembership, err error) {
	if c.ExpectedVersion < 1 {
		return out, fmt.Errorf("%w: membership version required", shared.ErrValidation)
	}
	err = s.withIdentityTenant(ctx, c.TenantID, func(tx pgx.Tx) error {
		if err = lockIdentityAdministration(ctx, tx, c.TenantID); err != nil {
			return err
		}
		if c.Proof.Recovery {
			if c.Kind != ports.IdentityMembershipChangeRole && c.Kind != ports.IdentityMembershipChangeSuspend && c.Kind != ports.IdentityMembershipChangeReactivate {
				return shared.ErrForbidden
			}
			if err = identityRepairAdmin(ctx, tx, c.TenantID, c.Proof, c.Proof.At); err != nil {
				return err
			}
		} else if err = identityAdmin(ctx, tx, c.TenantID, c.Proof); err != nil {
			return err
		}
		bound := context.WithValue(ctx, tenantTransactionKey{}, tenantTransaction{tx: tx, tenantID: c.TenantID.String()})
		out, err = s.ChangeMembership(bound, c.TenantID, c.MembershipID, ports.IdentityMembershipChange{Kind: c.Kind, Role: c.Role, ExpectedVersion: c.ExpectedVersion, Actor: c.Proof.Principal.ActorID, At: c.Proof.At})
		if err != nil {
			return err
		}
		var required bool
		if err = tx.QueryRow(ctx, `SELECT sso_requirement='required' FROM identity_policies WHERE tenant_id=$1`, c.TenantID.String()).Scan(&required); err != nil {
			return err
		}
		if required {
			var usable bool
			if err = tx.QueryRow(ctx, `SELECT synapse_identity_usable_admin_access($1,NULL,$2)`, c.TenantID.String(), c.Proof.At).Scan(&usable); err != nil {
				return err
			}
			if !usable {
				return fmt.Errorf("%w: required identity policy needs usable administrator", shared.ErrConflict)
			}
		}
		return err
	})
	return
}
func (s *IdentityFoundationStore) ListOwnIdentityAuthenticators(ctx context.Context, p ports.IdentityAdminProof) (out []ports.IdentityAuthenticatorProjection, err error) {
	tenant := shared.ID(p.Principal.TenantID)
	err = s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		if err = lockIdentityAdministration(ctx, tx, tenant); err != nil {
			return err
		}
		if p.Recovery || p.Bootstrap != nil || p.Principal.Credential.Kind != authz.KindBrowserSession || p.Principal.Credential.ID == "" {
			return shared.ErrForbidden
		}
		var digest string
		var session lockedEnterpriseSession
		err = tx.QueryRow(ctx, `SELECT c.digest,s.id,s.credential_id,s.membership_id,s.person_id,COALESCE(s.connection_id,''),s.kind,s.lineage_id,s.authenticated_at,s.origin_at,s.person_epoch,s.membership_epoch,COALESCE(s.connection_epoch,0) FROM identity_sessions s JOIN identity_credentials c ON c.tenant_id=s.tenant_id AND c.id=s.credential_id WHERE s.tenant_id=$1 AND s.id=$2 AND s.person_id=$3 AND s.membership_id=$4 AND s.revoked_at IS NULL AND s.expires_at>$5 FOR UPDATE OF s,c`, tenant.String(), p.Principal.Credential.ID, p.Principal.PersonID, p.Principal.MembershipID, p.At).Scan(&digest, &session.ID, &session.CredentialID, &session.MembershipID, &session.PersonID, &session.ConnectionID, &session.Kind, &session.LineageID, &session.AuthenticatedAt, &session.OriginAt, &session.PersonEpoch, &session.MembershipEpoch, &session.ConnectionEpoch)
		if err != nil {
			return err
		}
		if session.Kind != identity.EnterpriseSessionKindBrowser {
			return shared.ErrForbidden
		}
		if err = validateLockedSessionFences(ctx, tx, tenant, digest, session, p.At); err != nil {
			return err
		}
		rows, e := tx.Query(ctx, `SELECT a.connection_id,c.display_name,a.state FROM identity_authenticators a JOIN identity_connections c ON c.tenant_id=a.tenant_id AND c.id=a.connection_id WHERE a.tenant_id=$1 AND a.person_id=$2 AND a.membership_id=$3`, tenant.String(), p.Principal.PersonID, p.Principal.MembershipID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var x ports.IdentityAuthenticatorProjection
			var id string
			if e = rows.Scan(&id, &x.Name, &x.State); e != nil {
				return e
			}
			x.ConnectionID = shared.ID(id)
			out = append(out, x)
		}
		return rows.Err()
	})
	return
}
