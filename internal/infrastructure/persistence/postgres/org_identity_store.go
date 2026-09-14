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
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// OrganizationIdentityStore persists authoritative human identity under a tenant-bound RLS
// transaction. Global person rows are reachable here only through membership ownership; this type
// exposes no global person lookup.
type OrganizationIdentityStore struct{ pool *pgxpool.Pool }

func NewOrganizationIdentityStore(pool *pgxpool.Pool) (*OrganizationIdentityStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: organization identity store requires pool", shared.ErrValidation)
	}
	return &OrganizationIdentityStore{pool: pool}, nil
}

var _ ports.OrganizationIdentityStore = (*OrganizationIdentityStore)(nil)

func (s *OrganizationIdentityStore) CreatePersonMembership(ctx context.Context, person orgidentity.Person, membership orgidentity.Membership) error {
	if err := person.Valid(); err != nil {
		return err
	}
	if err := membership.Valid(); err != nil {
		return err
	}
	if membership.PersonID != person.ID {
		return fmt.Errorf("%w: membership must belong to person", shared.ErrValidation)
	}
	return WithTenant(ctx, s.pool, membership.TenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO persons(id,display_name,status,credential_epoch,version,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7)`, person.ID.String(), person.DisplayName, string(person.Status), person.CredentialEpoch, person.Version, person.CreatedAt, person.UpdatedAt); err != nil {
			return identityWriteError("create person", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO memberships(tenant_id,id,person_id,role,status,epoch,version,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, membership.TenantID.String(), membership.ID.String(), membership.PersonID.String(), string(membership.Role), string(membership.Status), membership.Epoch, membership.Version, membership.CreatedAt, membership.UpdatedAt); err != nil {
			return identityWriteError("create membership", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO person_organization_index(person_id,tenant_id) VALUES($1,$2)`, person.ID.String(), membership.TenantID.String()); err != nil {
			return identityWriteError("index person organization", err)
		}
		return nil
	})
}

func (s *OrganizationIdentityStore) PutMembership(ctx context.Context, membership orgidentity.Membership) error {
	if err := membership.Valid(); err != nil {
		return err
	}
	if membership.Version <= 1 {
		return fmt.Errorf("%w: existing membership update requires version greater than one", shared.ErrValidation)
	}
	return WithTenant(ctx, s.pool, membership.TenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE memberships SET role=$4,status=$5,epoch=$6,version=$7,updated_at=$8
			WHERE tenant_id=$1 AND id=$2 AND person_id=$3 AND version=$9`, membership.TenantID.String(), membership.ID.String(), membership.PersonID.String(), string(membership.Role), string(membership.Status), membership.Epoch, membership.Version, membership.UpdatedAt, membership.Version-1)
		if err != nil {
			return identityWriteError("update membership", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: membership changed concurrently or is outside tenant", shared.ErrConflict)
		}
		return nil
	})
}

func (s *OrganizationIdentityStore) GetMembership(ctx context.Context, tenantID, membershipID shared.ID) (out orgidentity.Membership, err error) {
	if tenantID.IsZero() || membershipID.IsZero() {
		return out, fmt.Errorf("%w: tenant and membership are required", shared.ErrValidation)
	}
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		return scanMembership(tx.QueryRow(ctx, `SELECT tenant_id,id,person_id,role,status,epoch,version,created_at,updated_at
			FROM memberships WHERE tenant_id=$1 AND id=$2`, tenantID.String(), membershipID.String()), &out)
	})
	return out, identityReadError("get membership", err)
}

func (s *OrganizationIdentityStore) GetMembershipByPerson(ctx context.Context, tenantID, personID shared.ID) (out orgidentity.Membership, err error) {
	if tenantID.IsZero() || personID.IsZero() {
		return out, fmt.Errorf("%w: tenant and person are required", shared.ErrValidation)
	}
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		return scanMembership(tx.QueryRow(ctx, `SELECT tenant_id,id,person_id,role,status,epoch,version,created_at,updated_at
			FROM memberships WHERE tenant_id=$1 AND person_id=$2`, tenantID.String(), personID.String()), &out)
	})
	return out, identityReadError("get membership by person", err)
}

func (s *OrganizationIdentityStore) GetPersonThroughMembership(ctx context.Context, tenantID, membershipID shared.ID) (person orgidentity.Person, membership orgidentity.Membership, err error) {
	if tenantID.IsZero() || membershipID.IsZero() {
		return person, membership, fmt.Errorf("%w: tenant and membership are required", shared.ErrValidation)
	}
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		var role, membershipStatus, personStatus string
		err := tx.QueryRow(ctx, `SELECT
			p.id,p.display_name,p.status,p.credential_epoch,p.version,p.created_at,p.updated_at,
			m.tenant_id,m.id,m.person_id,m.role,m.status,m.epoch,m.version,m.created_at,m.updated_at
			FROM memberships m JOIN persons p ON p.id=m.person_id
			WHERE m.tenant_id=$1 AND m.id=$2`, tenantID.String(), membershipID.String()).Scan(
			&person.ID, &person.DisplayName, &personStatus, &person.CredentialEpoch, &person.Version, &person.CreatedAt, &person.UpdatedAt,
			&membership.TenantID, &membership.ID, &membership.PersonID, &role, &membershipStatus, &membership.Epoch, &membership.Version, &membership.CreatedAt, &membership.UpdatedAt,
		)
		if err != nil {
			return err
		}
		person.Status = orgidentity.PersonStatus(personStatus)
		membership.Role = user.Role(role)
		membership.Status = orgidentity.MembershipStatus(membershipStatus)
		if err := person.Valid(); err != nil {
			return fmt.Errorf("decode person: %w", err)
		}
		if err := membership.Valid(); err != nil {
			return fmt.Errorf("decode membership: %w", err)
		}
		return nil
	})
	return person, membership, identityReadError("get person through membership", err)
}

func (s *OrganizationIdentityStore) PutConnection(ctx context.Context, connection orgidentity.Connection) error {
	if err := connection.Valid(); err != nil {
		return err
	}
	return WithTenant(ctx, s.pool, connection.TenantID.String(), func(tx pgx.Tx) error {
		if connection.Version == 1 {
			_, err := tx.Exec(ctx, `INSERT INTO sso_connections(tenant_id,id,protocol,trust_identifier,enabled,active_revision,connection_epoch,version,created_at,updated_at)
				VALUES($1,$2,$3,$4,$5,NULLIF($6,0),$7,$8,$9,$10)`, connection.TenantID.String(), connection.ID.String(), string(connection.Protocol), connection.TrustIdentifier, connection.Enabled, connection.ActiveRevision, connection.ConnectionEpoch, connection.Version, connection.CreatedAt, connection.UpdatedAt)
			return identityWriteError("create SSO connection", err)
		}
		tag, err := tx.Exec(ctx, `UPDATE sso_connections SET enabled=$5,active_revision=NULLIF($6,0),connection_epoch=$7,version=$8,updated_at=$9
			WHERE tenant_id=$1 AND id=$2 AND protocol=$3 AND trust_identifier=$4 AND version=$10`, connection.TenantID.String(), connection.ID.String(), string(connection.Protocol), connection.TrustIdentifier, connection.Enabled, connection.ActiveRevision, connection.ConnectionEpoch, connection.Version, connection.UpdatedAt, connection.Version-1)
		if err != nil {
			return identityWriteError("update SSO connection", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: connection changed concurrently or trust boundary changed", shared.ErrConflict)
		}
		return nil
	})
}

func (s *OrganizationIdentityStore) PutConnectionRevision(ctx context.Context, revision orgidentity.ConnectionRevision) error {
	if revision.TenantID.IsZero() || revision.ConnectionID.IsZero() || revision.Revision <= 0 || !revision.Protocol.Valid() {
		return fmt.Errorf("%w: invalid connection revision", shared.ErrValidation)
	}
	return WithTenant(ctx, s.pool, revision.TenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO sso_connection_revisions(tenant_id,connection_id,revision,protocol,configuration,encrypted_secret_ref,test_status,test_result,created_by,created_at,tested_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, revision.TenantID.String(), revision.ConnectionID.String(), revision.Revision, string(revision.Protocol), []byte(revision.Configuration), revision.EncryptedSecretRef, string(revision.TestStatus), []byte(revision.TestResult), revision.CreatedBy, revision.CreatedAt, revision.TestedAt)
		return identityWriteError("create SSO connection revision", err)
	})
}

func (s *OrganizationIdentityStore) GetConnection(ctx context.Context, tenantID, connectionID shared.ID) (out orgidentity.Connection, err error) {
	if tenantID.IsZero() || connectionID.IsZero() {
		return out, fmt.Errorf("%w: tenant and connection are required", shared.ErrValidation)
	}
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		var protocol string
		err := tx.QueryRow(ctx, `SELECT tenant_id,id,protocol,trust_identifier,enabled,COALESCE(active_revision,0),connection_epoch,version,created_at,updated_at
			FROM sso_connections WHERE tenant_id=$1 AND id=$2`, tenantID.String(), connectionID.String()).Scan(&out.TenantID, &out.ID, &protocol, &out.TrustIdentifier, &out.Enabled, &out.ActiveRevision, &out.ConnectionEpoch, &out.Version, &out.CreatedAt, &out.UpdatedAt)
		out.Protocol = orgidentity.Protocol(protocol)
		if err == nil {
			err = out.Valid()
		}
		return err
	})
	return out, identityReadError("get SSO connection", err)
}

func (s *OrganizationIdentityStore) PutAuthenticationIdentity(ctx context.Context, identity orgidentity.AuthenticationIdentity) error {
	if identity.TenantID.IsZero() || identity.ID.IsZero() || identity.MembershipID.IsZero() || identity.PersonID.IsZero() || identity.ConnectionID.IsZero() || identity.ProtocolSubject == "" || identity.CreationRevision <= 0 || identity.CreatedAt.IsZero() {
		return fmt.Errorf("%w: invalid authentication identity", shared.ErrValidation)
	}
	return WithTenant(ctx, s.pool, identity.TenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO authentication_identities(tenant_id,id,membership_id,person_id,connection_id,protocol_subject,creation_revision,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, identity.TenantID.String(), identity.ID.String(), identity.MembershipID.String(), identity.PersonID.String(), identity.ConnectionID.String(), identity.ProtocolSubject, identity.CreationRevision, identity.CreatedAt)
		return identityWriteError("create authentication identity", err)
	})
}

func (s *OrganizationIdentityStore) GetAuthenticationIdentity(ctx context.Context, tenantID, connectionID shared.ID, protocolSubject string) (out orgidentity.AuthenticationIdentity, err error) {
	if tenantID.IsZero() || connectionID.IsZero() || protocolSubject == "" {
		return out, fmt.Errorf("%w: tenant, connection, and subject are required", shared.ErrValidation)
	}
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_id,id,membership_id,person_id,connection_id,protocol_subject,creation_revision,created_at
			FROM authentication_identities WHERE tenant_id=$1 AND connection_id=$2 AND protocol_subject=$3`, tenantID.String(), connectionID.String(), protocolSubject).Scan(&out.TenantID, &out.ID, &out.MembershipID, &out.PersonID, &out.ConnectionID, &out.ProtocolSubject, &out.CreationRevision, &out.CreatedAt)
	})
	return out, identityReadError("get authentication identity", err)
}

func scanMembership(row pgx.Row, out *orgidentity.Membership) error {
	var role, status string
	if err := row.Scan(&out.TenantID, &out.ID, &out.PersonID, &role, &status, &out.Epoch, &out.Version, &out.CreatedAt, &out.UpdatedAt); err != nil {
		return err
	}
	out.Role = user.Role(role)
	out.Status = orgidentity.MembershipStatus(status)
	return out.Valid()
}

func identityReadError(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, shared.ErrNotFound) {
		return shared.ErrNotFound
	}
	return fmt.Errorf("%s: %w", op, err)
}

func identityWriteError(op string, err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return fmt.Errorf("%s: %w", op, shared.ErrConflict)
		case "23503":
			return fmt.Errorf("%s: %w", op, shared.ErrForbidden)
		case "23514":
			return fmt.Errorf("%s: %w", op, shared.ErrValidation)
		}
	}
	return fmt.Errorf("%s: %w", op, err)
}
