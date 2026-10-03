package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.IdentityRecoveryStore = (*IdentityFoundationStore)(nil)

// IdentityMaintenanceTenants uses the shared reference-data enumeration. Retained recovery
// obligations must remain deliverable even after a tenant is removed from deployment flags.
func (s *IdentityFoundationStore) IdentityMaintenanceTenants(ctx context.Context) ([]shared.ID, error) {
	return listTenantIDs(ctx, s.pool, "identity maintenance")
}

func (s *IdentityFoundationStore) GetIdentityRecoveryPolicy(ctx context.Context, tenant shared.ID) (out ports.IdentityRecoveryPolicy, err error) {
	err = s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		var grace *time.Time
		err := tx.QueryRow(ctx, `SELECT p.sso_requirement,p.legacy_bearer_grace_until,p.version,(r.last_alert_tested_at IS NOT NULL),COALESCE(r.last_rehearsed_at,'epoch'::timestamptz),COALESCE(r.updated_at,p.updated_at),COALESCE(p.activation_time,'epoch'::timestamptz),p.grace_enabled FROM identity_policies p LEFT JOIN identity_recovery_policies r ON p.tenant_id=r.tenant_id WHERE p.tenant_id=$1`, tenant.String()).Scan(&out.Organization.Requirement, &grace, &out.Version, &out.AlertConfigured, &out.LastRehearsedAt, &out.UpdatedAt, &out.Organization.ActivatedAt, &out.Organization.LegacyBearerGraceEnabled)
		if grace != nil {
			out.Organization.DeploymentGraceDuration = grace.Sub(out.Organization.ActivatedAt)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		return err
	})
	out.TenantID = tenant
	return out, err
}

func (s *IdentityFoundationStore) SaveIdentityRecoveryPolicy(ctx context.Context, p ports.IdentityRecoveryPolicy, proof ports.IdentityAdminProof) (out ports.IdentityRecoveryPolicy, err error) {
	err = s.withIdentityTenant(ctx, p.TenantID, func(tx pgx.Tx) error {
		if err := lockIdentityAdministration(ctx, tx, p.TenantID); err != nil {
			return err
		}
		if proof.Recovery {
			if err := identityRepairAdmin(ctx, tx, p.TenantID, proof, p.UpdatedAt); err != nil {
				return err
			}
		} else if err := identityAdmin(ctx, tx, p.TenantID, proof); err != nil {
			return err
		}
		var current int
		var currentRequirement string
		var activation *time.Time
		if err := tx.QueryRow(ctx, `SELECT version,sso_requirement,activation_time FROM identity_policies WHERE tenant_id=$1 FOR UPDATE`, p.TenantID.String()).Scan(&current, &currentRequirement, &activation); err != nil {
			return err
		}
		if p.ExpectedVersion != current {
			return fmt.Errorf("%w: identity policy version is %d, not %d", shared.ErrConflict, current, p.ExpectedVersion)
		}
		if p.Organization.Requirement != authz.SSOOptional && p.Organization.Requirement != authz.SSORequired {
			return fmt.Errorf("%w: invalid SSO requirement", shared.ErrValidation)
		}
		if p.Organization.Requirement == authz.SSORequired && currentRequirement != string(authz.SSORequired) {
			value := p.UpdatedAt.UTC()
			activation = &value
		}
		var grace *time.Time
		if p.Organization.LegacyBearerGraceEnabled {
			if activation == nil || p.Organization.DeploymentGraceDuration <= 0 || p.Organization.DeploymentGraceDuration > 24*time.Hour {
				return fmt.Errorf("%w: invalid legacy bearer grace", shared.ErrValidation)
			}
			value := activation.Add(p.Organization.DeploymentGraceDuration).UTC()
			grace = &value
		}
		if _, err := tx.Exec(ctx, `UPDATE identity_policies SET sso_requirement=$2,activation_time=$3,legacy_bearer_grace_until=$4,grace_enabled=$5,break_glass_enabled=true,updated_at=$6 WHERE tenant_id=$1`, p.TenantID.String(), string(p.Organization.Requirement), activation, grace, p.Organization.LegacyBearerGraceEnabled, p.UpdatedAt); err != nil {
			return err
		}
		var rehearsed, alertTest *time.Time
		readinessErr := tx.QueryRow(ctx, `SELECT last_rehearsed_at,last_alert_tested_at FROM identity_recovery_policies WHERE tenant_id=$1 FOR UPDATE`, p.TenantID.String()).Scan(&rehearsed, &alertTest)
		if errors.Is(readinessErr, pgx.ErrNoRows) {
			rehearsed = nil
			alertTest = nil
		} else if readinessErr != nil {
			return readinessErr
		}
		if p.Organization.Requirement == authz.SSORequired && (rehearsed == nil || p.UpdatedAt.Sub(*rehearsed) > 30*24*time.Hour || alertTest == nil) {
			return fmt.Errorf("%w: required recovery needs current server evidence", shared.ErrConflict)
		}
		if proof.Recovery && (p.Organization.Requirement != authz.SSOOptional || p.Organization.LegacyBearerGraceEnabled) {
			return shared.ErrForbidden
		}
		if p.Organization.Requirement == authz.SSORequired {
			var usable bool
			if err := tx.QueryRow(ctx, `SELECT synapse_identity_usable_admin_access($1,NULL,$2)`, p.TenantID.String(), p.UpdatedAt).Scan(&usable); err != nil {
				return err
			}
			if !usable {
				return fmt.Errorf("%w: required recovery needs usable administrator", shared.ErrConflict)
			}
		}
		err := tx.QueryRow(ctx, `INSERT INTO identity_recovery_policies(tenant_id,updated_at)
			VALUES($1,$2) ON CONFLICT(tenant_id) DO UPDATE SET updated_at=EXCLUDED.updated_at,version=identity_recovery_policies.version+1
			RETURNING version`, p.TenantID.String(), p.UpdatedAt).Scan(&out.Version)
		if err != nil {
			return err
		}
		out = p
		if err := tx.QueryRow(ctx, `SELECT version FROM identity_policies WHERE tenant_id=$1`, p.TenantID.String()).Scan(&out.Version); err != nil {
			return err
		}
		if rehearsed != nil {
			out.LastRehearsedAt = *rehearsed
		}
		out.AlertConfigured = alertTest != nil
		if activation != nil {
			out.Organization.ActivatedAt = *activation
		}
		return appendTenantAudit(ctx, tx, p.TenantID.String(), ports.AuditEntry{Actor: proof.Principal.ActorID, Action: "identity.recovery_policy_updated", Target: p.TenantID.String(), At: p.UpdatedAt})
	})
	return out, err
}

func (s *IdentityFoundationStore) RehearseIdentityRecovery(ctx context.Context, tenant shared.ID, proof ports.IdentityAdminProof, now time.Time) error {
	return s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		if err := lockIdentityAdministration(ctx, tx, tenant); err != nil {
			return err
		}
		if err := identityAdmin(ctx, tx, tenant, proof); err != nil {
			return err
		}
		var usable int
		if err := tx.QueryRow(ctx, `SELECT count(DISTINCT m.id) FROM identity_memberships m JOIN identity_authenticators a ON a.tenant_id=m.tenant_id AND a.membership_id=m.id AND a.person_id=m.person_id AND a.state='approved' JOIN identity_connections c ON c.tenant_id=a.tenant_id AND c.id=a.connection_id AND c.enabled JOIN identity_connection_tests t ON t.tenant_id=c.tenant_id AND t.connection_id=c.id AND t.revision=c.revision AND t.state='passed' AND t.expires_at>$2 WHERE m.tenant_id=$1 AND m.role='admin' AND m.state='active'`, tenant.String(), now).Scan(&usable); err != nil {
			return err
		}
		if usable < 1 {
			return fmt.Errorf("%w: no usable administrator connection", shared.ErrConflict)
		}
		_, err := tx.Exec(ctx, `INSERT INTO identity_recovery_policies(tenant_id,last_rehearsed_at,updated_at) VALUES($1,$2,$2) ON CONFLICT(tenant_id) DO UPDATE SET last_rehearsed_at=EXCLUDED.last_rehearsed_at,updated_at=EXCLUDED.updated_at`, tenant.String(), now)
		return err
	})
}
func (s *IdentityFoundationStore) RecordIdentityRecoveryAlertTest(ctx context.Context, tenant shared.ID, proof ports.IdentityAdminProof, now time.Time) error {
	return s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		if err := lockIdentityAdministration(ctx, tx, tenant); err != nil {
			return err
		}
		if err := identityAdmin(ctx, tx, tenant, proof); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO identity_recovery_policies(tenant_id,last_alert_tested_at,updated_at) VALUES($1,$2,$2) ON CONFLICT(tenant_id) DO UPDATE SET last_alert_tested_at=EXCLUDED.last_alert_tested_at,updated_at=EXCLUDED.updated_at`, tenant.String(), now)
		return err
	})
}

func (s *IdentityFoundationStore) CreateIdentityRecoveryActivation(ctx context.Context, a ports.IdentityRecoveryActivation, proof ports.IdentityAdminProof) error {
	if a.ID.IsZero() || a.TenantID.IsZero() || a.MembershipID.IsZero() || a.PersonID.IsZero() || !identityDigestPattern.MatchString(a.SecretDigest) || a.CreatedAt.IsZero() || !a.ExpiresAt.After(a.CreatedAt) || strings.TrimSpace(a.CreatedBy) == "" {
		return fmt.Errorf("%w: invalid identity recovery activation", shared.ErrValidation)
	}
	return s.withIdentityTenant(ctx, a.TenantID, func(tx pgx.Tx) error {
		if err := lockIdentityAdministration(ctx, tx, a.TenantID); err != nil {
			return err
		}
		if err := identityAdmin(ctx, tx, a.TenantID, proof); err != nil {
			return err
		}
		var found int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM identity_memberships WHERE tenant_id=$1 AND id=$2 AND person_id=$3 AND role='admin' AND state='active' FOR UPDATE`, a.TenantID.String(), a.MembershipID.String(), a.PersonID.String()).Scan(&found); err != nil {
			return err
		}
		// Rotating an activation makes every older secret unusable before the new digest is stored.
		if _, err := tx.Exec(ctx, `UPDATE identity_recovery_activations SET consumed_at=$4,consumed_session_id='rotated' WHERE tenant_id=$1 AND membership_id=$2 AND consumed_at IS NULL AND expires_at>$3`, a.TenantID.String(), a.MembershipID.String(), a.CreatedAt, a.CreatedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO identity_recovery_activations(tenant_id,id,membership_id,person_id,secret_digest,created_by,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, a.TenantID.String(), a.ID.String(), a.MembershipID.String(), a.PersonID.String(), a.SecretDigest, a.CreatedBy, a.ExpiresAt, a.CreatedAt); err != nil {
			return err
		}
		return appendTenantAudit(ctx, tx, a.TenantID.String(), ports.AuditEntry{Actor: a.CreatedBy, Action: "identity.recovery_activation_rotated", Target: a.ID.String(), At: a.CreatedAt, Metadata: map[string]string{"membership_id": a.MembershipID.String()}})
	})
}

func (s *IdentityFoundationStore) ResolveIdentityRecoveryActivationTenant(ctx context.Context, secretDigest string) (shared.ID, error) {
	if !identityDigestPattern.MatchString(secretDigest) {
		return "", shared.ErrNotFound
	}
	var tenant *string
	if err := s.pool.QueryRow(ctx, `SELECT synapse_identity_recovery_activation_tenant($1)`, secretDigest).Scan(&tenant); err != nil {
		return "", fmt.Errorf("locate identity recovery activation: %w", err)
	}
	if tenant == nil || *tenant == "" {
		return "", shared.ErrNotFound
	}
	return shared.ID(*tenant), nil
}

func (s *IdentityFoundationStore) ConsumeIdentityRecoveryActivation(ctx context.Context, c ports.IdentityRecoveryConsume) (out identity.EnterpriseSession, err error) {
	if !identityDigestPattern.MatchString(c.SecretDigest) || c.Now.IsZero() || c.Issue.CredentialDigest == "" || c.Issue.Session.Kind != identity.EnterpriseSessionKindBreakGlass {
		return out, fmt.Errorf("%w: invalid identity recovery consume command", shared.ErrValidation)
	}
	tenantID, err := s.ResolveIdentityRecoveryActivationTenant(ctx, c.SecretDigest)
	if err != nil {
		return out, err
	}
	tenant := tenantID.String()
	err = s.withIdentityTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err = lockOrganizationPolicy(ctx, tx, tenantID); err != nil {
			return err
		}
		var membership, person string
		var expires time.Time
		err := tx.QueryRow(ctx, `SELECT membership_id,person_id,expires_at FROM identity_recovery_activations WHERE tenant_id=$1 AND secret_digest=$2 AND consumed_at IS NULL FOR UPDATE`, tenant, c.SecretDigest).Scan(&membership, &person, &expires)
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return err
		}
		if !expires.After(c.Now) {
			return shared.ErrNotFound
		}
		var requirement string
		var alertTested *time.Time
		err = tx.QueryRow(ctx, `SELECT p.sso_requirement,r.last_alert_tested_at FROM identity_recovery_policies r JOIN identity_policies p ON p.tenant_id=r.tenant_id WHERE r.tenant_id=$1 FOR UPDATE`, tenant).Scan(&requirement, &alertTested)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: recovery policy is not configured", shared.ErrForbidden)
		}
		if err != nil {
			return err
		}
		// A stale rehearsal blocks policy enforcement changes, never an already-issued emergency
		// activation: the latter must remain available during the outage it was prepared for.
		if requirement == string(authz.SSORequired) && alertTested == nil {
			return fmt.Errorf("%w: required recovery policy is not current", shared.ErrForbidden)
		}
		var role string
		var membershipEpoch int64
		if err = tx.QueryRow(ctx, `SELECT role,epoch FROM identity_memberships WHERE tenant_id=$1 AND id=$2 AND person_id=$3 AND state='active' FOR UPDATE`, tenant, membership, person).Scan(&role, &membershipEpoch); err != nil {
			return err
		}
		if role != string(user.RoleAdmin) {
			return shared.ErrForbidden
		}
		var personEpoch int64
		if err = tx.QueryRow(ctx, `SELECT synapse_identity_recovery_person_epoch($1,$2)`, c.SecretDigest, person).Scan(&personEpoch); err != nil {
			return shared.ErrNotFound
		}
		v := c.Issue.Session
		v.TenantID = shared.ID(tenant)
		v.MembershipID = shared.ID(membership)
		v.PersonID = shared.ID(person)
		v.PersonEpoch = personEpoch
		v.MembershipEpoch = membershipEpoch
		v.ConnectionID = ""
		v.ConnectionEpoch = 0
		if err = v.Valid(); err != nil {
			return err
		}
		if !v.ExpiresAt.After(c.Now) || v.ExpiresAt.After(c.Now.Add(15*time.Minute)) {
			return fmt.Errorf("%w: break-glass session lifetime exceeds 15 minutes", shared.ErrValidation)
		}
		if err = insertEnterpriseSession(ctx, tx, ports.IdentitySessionIssue{Session: v, CredentialDigest: c.Issue.CredentialDigest}, c.Actor, c.Now); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE identity_recovery_activations SET consumed_at=$3,consumed_session_id=$4 WHERE tenant_id=$1 AND secret_digest=$2 AND consumed_at IS NULL`, tenant, c.SecretDigest, c.Now, v.ID.String()); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO identity_recovery_alerts(tenant_id,id,membership_id,session_id,next_attempt_at,created_at) VALUES($1,$2,$3,$4,$5,$5)`, tenant, "recovery-alert-"+v.ID.String(), membership, v.ID.String(), c.Now); err != nil {
			return err
		}
		out = v
		return appendTenantAudit(ctx, tx, tenant, ports.AuditEntry{Actor: c.Actor, Action: "identity.recovery_activated", Target: v.ID.String(), At: c.Now, Metadata: map[string]string{"membership_id": membership}})
	})
	return out, err
}

func (s *IdentityFoundationStore) ClaimIdentityRecoveryAlerts(ctx context.Context, tenant shared.ID, now time.Time, limit int) ([]ports.IdentityRecoveryAlert, error) {
	if limit < 1 || limit > 100 {
		return nil, fmt.Errorf("%w: recovery alert limit must be 1..100", shared.ErrValidation)
	}
	out := []ports.IdentityRecoveryAlert{}
	err := s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id,membership_id,session_id,state,attempts,max_attempts,next_attempt_at,created_at FROM identity_recovery_alerts WHERE tenant_id=$1 AND state='pending' AND next_attempt_at<=$2 AND (lease_until IS NULL OR lease_until<=$2) ORDER BY next_attempt_at,id LIMIT $3 FOR UPDATE SKIP LOCKED`, tenant.String(), now, limit)
		if err != nil {
			return err
		}
		for rows.Next() {
			var a ports.IdentityRecoveryAlert
			var id, m, s string
			if err = rows.Scan(&id, &m, &s, &a.State, &a.Attempts, &a.MaxAttempts, &a.NextAttemptAt, &a.CreatedAt); err != nil {
				return err
			}
			a.ID, a.TenantID, a.MembershipID, a.SessionID = shared.ID(id), tenant, shared.ID(m), shared.ID(s)
			out = append(out, a)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		for _, a := range out {
			if _, err := tx.Exec(ctx, `UPDATE identity_recovery_alerts SET lease_until=$3 WHERE tenant_id=$1 AND id=$2`, tenant.String(), a.ID.String(), now.Add(5*time.Minute)); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

func (s *IdentityFoundationStore) CompleteIdentityRecoveryAlert(ctx context.Context, tenant, id shared.ID, delivered bool, message string, now time.Time) error {
	return s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		message = strings.TrimSpace(message)
		if len(message) > 512 {
			message = message[:512]
		}
		var attempts, max int
		if err := tx.QueryRow(ctx, `SELECT attempts,max_attempts FROM identity_recovery_alerts WHERE tenant_id=$1 AND id=$2 AND state='pending' FOR UPDATE`, tenant.String(), id.String()).Scan(&attempts, &max); err != nil {
			return err
		}
		attempts++
		state := "pending"
		next := now.Add(identityDeliveryBackoff(attempts))
		if delivered {
			state = "delivered"
			next = now
		} else if attempts >= max {
			state = "exhausted"
		}
		_, err := tx.Exec(ctx, `UPDATE identity_recovery_alerts SET state=$3,attempts=$4,next_attempt_at=$5,last_error=$6,lease_until=NULL,delivered_at=CASE WHEN $3='delivered' THEN $5::timestamptz ELSE NULL END WHERE tenant_id=$1 AND id=$2`, tenant.String(), id.String(), state, attempts, next, message)
		return err
	})
}

func (s *IdentityFoundationStore) ListIdentityRecoveryAlerts(ctx context.Context, tenant shared.ID, limit int) ([]ports.IdentityRecoveryAlert, error) {
	if limit < 1 || limit > 100 {
		return nil, fmt.Errorf("%w: recovery alert limit must be 1..100", shared.ErrValidation)
	}
	out := []ports.IdentityRecoveryAlert{}
	err := s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id,membership_id,session_id,state,attempts,max_attempts,next_attempt_at,created_at FROM identity_recovery_alerts WHERE tenant_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2`, tenant.String(), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a ports.IdentityRecoveryAlert
			var id, membership, session string
			if err := rows.Scan(&id, &membership, &session, &a.State, &a.Attempts, &a.MaxAttempts, &a.NextAttemptAt, &a.CreatedAt); err != nil {
				return err
			}
			a.ID, a.TenantID, a.MembershipID, a.SessionID = shared.ID(id), tenant, shared.ID(membership), shared.ID(session)
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func (s *IdentityFoundationStore) IdentityRecoveryAlertRecipients(ctx context.Context, tenant, membership shared.ID) ([]string, error) {
	out := []string{}
	err := s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT c.value FROM identity_memberships m JOIN user_contacts c ON c.tenant_id=m.tenant_id AND c.user_id=m.legacy_user_id AND c.kind='email' AND c.verified_at IS NOT NULL WHERE m.tenant_id=$1 AND m.id=$2 AND m.state='active' AND m.role='admin'`, tenant.String(), membership.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				return err
			}
			out = append(out, value)
		}
		return rows.Err()
	})
	return out, err
}
