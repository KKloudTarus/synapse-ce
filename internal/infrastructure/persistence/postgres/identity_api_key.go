package postgres

import (
	"context"
	"errors"
	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"time"
)

var _ ports.IdentityAPIKeyAuthentication = (*IdentityFoundationStore)(nil)

func (s *IdentityFoundationStore) AuthenticateIdentityAPIKey(ctx context.Context, digest string, now time.Time, grace time.Duration) (out authz.Principal, err error) {
	route, err := s.RouteCredentialDigest(ctx, digest)
	if err != nil {
		return out, err
	}
	if route.Kind != ports.IdentityCredentialAPIKey {
		return out, shared.ErrNotFound
	}
	err = s.withIdentityTenant(ctx, route.TenantID, func(tx pgx.Tx) error {
		var policy authz.OrganizationPolicy
		var personEpoch *int64
		var graceUntil *time.Time
		err := tx.QueryRow(ctx, `SELECT c.id,m.id,m.person_id,COALESCE(m.legacy_user_id,m.id),m.role,m.epoch,synapse_identity_person_epoch(c.digest,m.person_id),p.sso_requirement,COALESCE(p.activation_time,'epoch'::timestamptz),p.grace_enabled,p.legacy_bearer_grace_until FROM identity_credentials c JOIN identity_memberships m ON m.tenant_id=c.tenant_id AND m.id=c.membership_id AND m.person_id=c.person_id JOIN identity_policies p ON p.tenant_id=c.tenant_id WHERE c.tenant_id=$1 AND c.digest=$2 AND c.kind='api_key' AND c.state='active' AND m.state='active' AND p.cutover_phase='declared'`, route.TenantID.String(), digest).Scan(&out.Credential.ID, &out.MembershipID, &out.PersonID, &out.ActorID, &out.Role, &out.Epochs.Membership, &personEpoch, &policy.Requirement, &policy.ActivatedAt, &policy.LegacyBearerGraceEnabled, &graceUntil)
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return err
		}
		if personEpoch == nil {
			return shared.ErrNotFound
		}
		policy.DeploymentGraceDuration = grace
		if graceUntil == nil {
			policy.DeploymentGraceDuration = 0
		} else if stored := graceUntil.Sub(policy.ActivatedAt); stored < grace {
			policy.DeploymentGraceDuration = stored
		}
		if !policy.EvaluateAuthentication(authz.KindAPIKey, authz.DestinationAuthentication{ActiveMembership: true}, now).Allowed {
			return shared.ErrForbidden
		}
		out.TenantID = route.TenantID.String()
		out.Credential.Kind = authz.KindAPIKey
		out.Provenance = "enterprise_bearer"
		out.Epochs.Person = *personEpoch
		return nil
	})
	return out, err
}
