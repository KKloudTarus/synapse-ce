package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.IdentitySessionStore = (*IdentityFoundationStore)(nil)

func (s *IdentityFoundationStore) AuthenticateEnterpriseSession(ctx context.Context, digest string, now time.Time) (ports.IdentitySessionAuthentication, error) {
	route, err := s.RouteCredentialDigest(ctx, digest)
	if err != nil {
		return ports.IdentitySessionAuthentication{}, err
	}
	if route.Kind != ports.IdentityCredentialBrowserSession && route.Kind != ports.IdentityCredentialBreakGlass {
		return ports.IdentitySessionAuthentication{}, shared.ErrNotFound
	}
	var out ports.IdentitySessionAuthentication
	err = s.withIdentityTenant(ctx, route.TenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT s.id,s.tenant_id,s.credential_id,s.membership_id,s.person_id,COALESCE(s.connection_id,''),s.kind,s.lineage_id,COALESCE(s.rotated_from_session_id,''),s.authenticated_at,s.origin_at,s.expires_at,s.person_epoch,s.membership_epoch,COALESCE(s.connection_epoch,0),s.csrf_token_hash,s.revoked_at,s.created_at,m.role
			FROM identity_sessions s JOIN identity_credentials c ON c.tenant_id=s.tenant_id AND c.id=s.credential_id JOIN identity_memberships m ON m.tenant_id=s.tenant_id AND m.id=s.membership_id AND m.person_id=s.person_id
			WHERE s.tenant_id=$1 AND c.digest=$2 AND c.kind=s.kind AND c.state='active' AND m.state='active' AND s.revoked_at IS NULL AND s.expires_at>$3`, route.TenantID.String(), digest, now)
		var role string
		out.Session, role, err = scanEnterpriseSession(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return err
		}
		out.Role = role
		if out.Session.BeyondMaxAge(now) {
			return shared.ErrNotFound
		}
		var personEpoch *int64
		var membershipEpoch, connectionEpoch int64
		err = tx.QueryRow(ctx, `SELECT synapse_identity_person_epoch($1,$2)`, digest, out.Session.PersonID.String()).Scan(&personEpoch)
		if errors.Is(err, pgx.ErrNoRows) || personEpoch == nil {
			return shared.ErrNotFound
		}
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `SELECT epoch FROM identity_memberships WHERE tenant_id=$1 AND id=$2 AND state='active'`, route.TenantID.String(), out.Session.MembershipID.String()).Scan(&membershipEpoch)
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return err
		}
		if !out.Session.ConnectionID.IsZero() {
			err = tx.QueryRow(ctx, `SELECT epoch FROM identity_connections WHERE tenant_id=$1 AND id=$2 AND enabled`, route.TenantID.String(), out.Session.ConnectionID.String()).Scan(&connectionEpoch)
			if errors.Is(err, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			if err != nil {
				return err
			}
		}
		if *personEpoch != out.Session.PersonEpoch || membershipEpoch != out.Session.MembershipEpoch || (!out.Session.ConnectionID.IsZero() && connectionEpoch != out.Session.ConnectionEpoch) {
			return shared.ErrNotFound
		}
		var policy authz.OrganizationPolicy
		var proof authz.DestinationAuthentication
		proof.ActiveMembership = true
		if err := tx.QueryRow(ctx, `SELECT sso_requirement,COALESCE(activation_time,'epoch'::timestamptz),grace_enabled FROM identity_policies WHERE tenant_id=$1`, route.TenantID.String()).Scan(&policy.Requirement, &policy.ActivatedAt, &policy.LegacyBearerGraceEnabled); err != nil {
			return err
		}
		if !out.Session.ConnectionID.IsZero() {
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_authenticators WHERE tenant_id=$1 AND connection_id=$2 AND membership_id=$3 AND person_id=$4 AND state='approved')`, route.TenantID.String(), out.Session.ConnectionID.String(), out.Session.MembershipID.String(), out.Session.PersonID.String()).Scan(&proof.ApprovedDestinationSSO); err != nil {
				return err
			}
		}
		if !policy.EvaluateAuthentication(authz.CredentialKind(out.Session.Kind), proof, now).Allowed {
			return shared.ErrNotFound
		}
		return nil
	})
	return out, err
}

func (s *IdentityFoundationStore) CreateEnterpriseSession(ctx context.Context, issue ports.IdentitySessionIssue, actor string, now time.Time) error {
	if err := issue.Session.Valid(); err != nil {
		return err
	}
	return s.withIdentityTenant(ctx, issue.Session.TenantID, func(tx pgx.Tx) error {
		if _, err := lockOrganizationPolicy(ctx, tx, issue.Session.TenantID); err != nil {
			return err
		}
		return insertEnterpriseSession(ctx, tx, issue, actor, now)
	})
}

func (s *IdentityFoundationStore) RotateEnterpriseSession(ctx context.Context, sourceDigest string, issue ports.IdentitySessionIssue, actor string, now time.Time) error {
	if err := issue.Session.Valid(); err != nil {
		return err
	}
	route, err := s.RouteCredentialDigest(ctx, sourceDigest)
	if err != nil {
		return err
	}
	if route.TenantID != issue.Session.TenantID {
		return shared.ErrForbidden
	}
	return s.withIdentityTenant(ctx, route.TenantID, func(tx pgx.Tx) error {
		if _, err := lockOrganizationPolicy(ctx, tx, route.TenantID); err != nil {
			return err
		}
		var source lockedEnterpriseSession
		if err := loadLockedEnterpriseSession(ctx, tx, route.TenantID, sourceDigest, now, &source); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			return err
		}
		if !sameSessionLineage(source, issue.Session) {
			return fmt.Errorf("%w: rotation replacement does not preserve source session lineage", shared.ErrForbidden)
		}
		if err := validateLockedSessionFences(ctx, tx, route.TenantID, sourceDigest, source, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE identity_sessions SET revoked_at=$3 WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL`, route.TenantID.String(), source.ID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE identity_credentials SET state='revoked',revoked_at=$3,updated_at=$3 WHERE tenant_id=$1 AND id=$2 AND state='active'`, route.TenantID.String(), source.CredentialID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE identity_session_switch_retries SET revoked_at=$3 WHERE tenant_id=$1 AND source_credential_id=$2 AND revoked_at IS NULL`, route.TenantID.String(), source.CredentialID, now); err != nil {
			return err
		}
		return insertEnterpriseSession(ctx, tx, issue, actor, now)
	})
}

func (s *IdentityFoundationStore) LogoutEnterpriseSession(ctx context.Context, digest, actor string, now time.Time) error {
	route, err := s.RouteCredentialDigest(ctx, digest)
	if err != nil {
		return err
	}
	return s.withIdentityTenant(ctx, route.TenantID, func(tx pgx.Tx) error {
		if _, err := lockOrganizationPolicy(ctx, tx, route.TenantID); err != nil {
			return err
		}
		var credentialID string
		if err := tx.QueryRow(ctx, `SELECT id FROM identity_credentials WHERE tenant_id=$1 AND digest=$2 AND state='active' FOR UPDATE`, route.TenantID.String(), digest).Scan(&credentialID); err != nil {
			return shared.ErrNotFound
		}
		if _, err := tx.Exec(ctx, `UPDATE identity_sessions SET revoked_at=$3 WHERE tenant_id=$1 AND credential_id=$2 AND revoked_at IS NULL`, route.TenantID.String(), credentialID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE identity_credentials SET state='revoked',revoked_at=$3,updated_at=$3 WHERE tenant_id=$1 AND id=$2 AND state='active'`, route.TenantID.String(), credentialID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE identity_session_switch_retries SET revoked_at=$3 WHERE tenant_id=$1 AND source_credential_id=$2 AND revoked_at IS NULL`, route.TenantID.String(), credentialID, now); err != nil {
			return err
		}
		return appendTenantAudit(ctx, tx, route.TenantID.String(), ports.AuditEntry{Actor: actor, Action: "identity.session_logged_out", Target: credentialID, At: now})
	})
}

// SwitchEnterpriseSession is the sole persistence path allowed to rebind RLS. It rejects an
// ambient transaction, locks tenants and memberships in lexical order, then revokes the source
// only after destination policy, membership, connection and exact approved-subject checks hold.
func (s *IdentityFoundationStore) SwitchEnterpriseSession(ctx context.Context, command ports.IdentitySessionSwitch, actor string) (out ports.IdentitySessionSwitchResult, err error) {
	if command.DestinationTenantID.IsZero() || command.DestinationMembershipID.IsZero() || command.Replacement.Session.Valid() != nil || command.Now.IsZero() || actor == "" ||
		(command.SourceCSRFTokenHash != "" && !identityDigestPattern.MatchString(command.SourceCSRFTokenHash)) ||
		(!command.DestinationConnectionID.IsZero() && (command.DestinationRevision < 1 || command.DestinationAuthenticatedAt.IsZero() || command.DestinationAuthenticatedAt.After(command.Now) || !command.Now.Before(command.DestinationAuthenticatedAt.Add(15*time.Minute)))) ||
		(command.DestinationConnectionID.IsZero() && command.DestinationRevision != 0) {
		return out, fmt.Errorf("%w: invalid enterprise session switch command", shared.ErrValidation)
	}
	if _, bound := ctx.Value(tenantTransactionKey{}).(tenantTransaction); bound {
		return out, fmt.Errorf("%w: cross-tenant switch cannot join an ambient tenant transaction", shared.ErrValidation)
	}
	route, err := s.RouteCredentialDigest(ctx, command.SourceCredentialDigest)
	if err != nil {
		if !errors.Is(err, shared.ErrNotFound) || command.RetryKey == "" || command.RetryPayloadHash == "" {
			return out, err
		}
		var tenant *string
		if lookupErr := s.pool.QueryRow(ctx, `SELECT synapse_identity_switch_retry_tenant($1,$2,$3)`, command.SourceCredentialDigest, command.RetryKey, command.RetryPayloadHash).Scan(&tenant); lookupErr != nil {
			return out, fmt.Errorf("locate enterprise switch retry: %w", lookupErr)
		}
		if tenant == nil || *tenant == "" {
			return out, shared.ErrNotFound
		}
		return s.replayEnterpriseSwitch(ctx, shared.ID(*tenant), switchReplayFromCommand(command))
	}
	if route.TenantID == command.DestinationTenantID {
		return out, fmt.Errorf("%w: source and destination organizations must differ", shared.ErrValidation)
	}
	if route.Kind == ports.IdentityCredentialBreakGlass {
		return out, fmt.Errorf("%w: break-glass sessions cannot switch organizations", shared.ErrForbidden)
	}
	if route.Kind != ports.IdentityCredentialBrowserSession {
		return out, shared.ErrNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return out, fmt.Errorf("begin identity switch: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(context.Background())
		}
	}()
	bind := func(tenant shared.ID) error {
		_, e := tx.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, tenant.String())
		return e
	}
	// Tenant policy rows are locked in a deterministic global order before either membership.
	first, second := route.TenantID, command.DestinationTenantID
	if second.String() < first.String() {
		first, second = second, first
	}
	for _, tenant := range []shared.ID{first, second} {
		if err = bind(tenant); err != nil {
			return out, err
		}
		if _, err = lockOrganizationPolicy(ctx, tx, tenant); err != nil {
			return out, fmt.Errorf("lock identity policy: %w", err)
		}
	}
	// Source is locked first only when it sorts first; otherwise it is locked after destination.
	var source lockedEnterpriseSession
	var destinationMembershipEpoch, destinationConnectionEpoch int64
	for _, tenant := range []shared.ID{first, second} {
		if err = bind(tenant); err != nil {
			return out, err
		}
		if tenant == route.TenantID {
			err = loadLockedEnterpriseSession(ctx, tx, tenant, command.SourceCredentialDigest, command.Now, &source)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					if command.RetryKey != "" && command.RetryPayloadHash != "" {
						if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
							return out, rollbackErr
						}
						committed = true
						return s.replayEnterpriseSwitch(ctx, route.TenantID, switchReplayFromCommand(command))
					}
					return out, shared.ErrNotFound
				}
				return out, err
			}
			if err = validateLockedSessionFences(ctx, tx, tenant, command.SourceCredentialDigest, source, command.Now); err != nil {
				return out, err
			}
		} else {
			var person string
			if command.DestinationConnectionID.IsZero() {
				err = tx.QueryRow(ctx, `SELECT person_id,epoch FROM identity_memberships WHERE tenant_id=$1 AND id=$2 AND state='active' FOR UPDATE`, tenant.String(), command.DestinationMembershipID.String()).Scan(&person, &destinationMembershipEpoch)
			} else {
				err = tx.QueryRow(ctx, `SELECT m.person_id,m.epoch,c.epoch FROM identity_memberships m JOIN identity_connections c ON c.tenant_id=m.tenant_id AND c.id=$3 AND c.enabled AND c.revision=$4 JOIN identity_authenticators a ON a.tenant_id=m.tenant_id AND a.connection_id=c.id AND a.membership_id=m.id AND a.person_id=m.person_id AND a.protocol_subject=$5 AND a.state='approved' WHERE m.tenant_id=$1 AND m.id=$2 AND m.state='active' AND COALESCE((SELECT t.state='passed' FROM identity_connection_tests t WHERE t.tenant_id=m.tenant_id AND t.connection_id=c.id AND t.revision=c.revision ORDER BY t.tested_at DESC,t.id DESC LIMIT 1),false) FOR UPDATE`, tenant.String(), command.DestinationMembershipID.String(), command.DestinationConnectionID.String(), command.DestinationRevision, command.DestinationSubject).Scan(&person, &destinationMembershipEpoch, &destinationConnectionEpoch)
			}
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return out, fmt.Errorf("destination reauthentication required: %w", shared.ErrForbidden)
				}
				return out, err
			}
			if person != command.Replacement.Session.PersonID.String() {
				return out, fmt.Errorf("destination identity differs from source: %w", shared.ErrForbidden)
			}
		}
	}
	if source.PersonID != command.Replacement.Session.PersonID.String() || source.Kind != identity.EnterpriseSessionKindBrowser {
		return out, fmt.Errorf("destination identity differs from source: %w", shared.ErrForbidden)
	}
	// The switch establishes a fresh destination membership but remains in the source session
	// lineage. Caller-provided lineage, origin, and optional-SSO authentication timestamps are
	// never trusted.
	command.Replacement.Session.LineageID = shared.ID(source.LineageID)
	command.Replacement.Session.OriginAt = source.OriginAt
	command.Replacement.Session.RotatedFromSessionID = ""
	command.Replacement.Session.PersonEpoch = source.PersonEpoch
	command.Replacement.Session.MembershipEpoch = destinationMembershipEpoch
	command.Replacement.Session.ConnectionEpoch = destinationConnectionEpoch
	if command.DestinationConnectionID.IsZero() {
		command.Replacement.Session.AuthenticatedAt = source.AuthenticatedAt
	} else {
		command.Replacement.Session.AuthenticatedAt = command.DestinationAuthenticatedAt
	}
	if err = command.Replacement.Session.Valid(); err != nil {
		return out, err
	}
	if err = bind(command.DestinationTenantID); err != nil {
		return out, err
	}
	if err = insertEnterpriseSession(ctx, tx, command.Replacement, actor, command.Now); err != nil {
		return out, err
	}
	if err = bind(route.TenantID); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `UPDATE identity_sessions SET revoked_at=$3 WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL`, route.TenantID.String(), source.ID, command.Now); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `UPDATE identity_credentials SET state='revoked',revoked_at=$3,updated_at=$3 WHERE tenant_id=$1 AND id=$2 AND state='active'`, route.TenantID.String(), source.CredentialID, command.Now); err != nil {
		return out, err
	}
	if err = appendTenantAudit(ctx, tx, route.TenantID.String(), ports.AuditEntry{Actor: actor, Action: "identity.session_switched_out", Target: source.ID, At: command.Now, Metadata: map[string]string{"destination_tenant": command.DestinationTenantID.String()}}); err != nil {
		return out, err
	}
	if command.RetryKey != "" {
		if _, err = tx.Exec(ctx, `INSERT INTO identity_session_switch_retries(tenant_id,retry_key,payload_hash,source_credential_id,source_digest,destination_tenant_id,destination_session_id,response_ciphertext,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, route.TenantID.String(), command.RetryKey, command.RetryPayloadHash, source.CredentialID, command.SourceCredentialDigest, command.DestinationTenantID.String(), command.Replacement.Session.ID.String(), command.RetryCiphertext, command.Now.Add(5*time.Minute), command.Now); err != nil {
			return out, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return out, fmt.Errorf("commit identity switch: %w", err)
	}
	committed = true
	return ports.IdentitySessionSwitchResult{Session: command.Replacement.Session, RetryCiphertext: command.RetryCiphertext}, nil
}

// replayEnterpriseSwitch rebinds RLS only within its own transaction. The retry row is scoped to
// the revoked source tenant; the replacement session is then read under its recorded destination.
// ReplayEnterpriseSessionSwitch resolves the source tenant through the global exact locator, then
// checks the CSRF secret retained by the revoked source credential before returning a stored reply.
func (s *IdentityFoundationStore) ReplayEnterpriseSessionSwitch(ctx context.Context, replay ports.IdentitySessionSwitchReplay) (out ports.IdentitySessionSwitchResult, err error) {
	if !identityDigestPattern.MatchString(replay.SourceCredentialDigest) || !identityDigestPattern.MatchString(replay.SourceCSRFTokenHash) || replay.RetryKey == "" || len(replay.RetryKey) > 256 || !identityDigestPattern.MatchString(replay.PayloadHash) || replay.Now.IsZero() {
		return out, fmt.Errorf("%w: invalid enterprise session switch replay", shared.ErrValidation)
	}
	var tenant *string
	if err := s.pool.QueryRow(ctx, `SELECT synapse_identity_switch_retry_tenant($1,$2,$3)`, replay.SourceCredentialDigest, replay.RetryKey, replay.PayloadHash).Scan(&tenant); err != nil {
		return out, fmt.Errorf("locate enterprise switch retry: %w", err)
	}
	if tenant == nil || *tenant == "" {
		return out, shared.ErrNotFound
	}
	return s.replayEnterpriseSwitch(ctx, shared.ID(*tenant), replay)
}

func switchReplayFromCommand(command ports.IdentitySessionSwitch) ports.IdentitySessionSwitchReplay {
	return ports.IdentitySessionSwitchReplay{SourceCredentialDigest: command.SourceCredentialDigest, SourceCSRFTokenHash: command.SourceCSRFTokenHash, RetryKey: command.RetryKey, PayloadHash: command.RetryPayloadHash, Now: command.Now}
}

func (s *IdentityFoundationStore) replayEnterpriseSwitch(ctx context.Context, sourceTenant shared.ID, replay ports.IdentitySessionSwitchReplay) (out ports.IdentitySessionSwitchResult, err error) {
	destinationTenant, err := s.switchRetryDestinationTenant(ctx, replay)
	if err != nil {
		return out, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	bind := func(t shared.ID) error {
		_, e := tx.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, t.String())
		return e
	}
	first, second := sourceTenant, destinationTenant
	if second.String() < first.String() {
		first, second = second, first
	}
	for _, tenant := range []shared.ID{first, second} {
		if err = bind(tenant); err != nil {
			return out, err
		}
		if _, err = lockOrganizationPolicy(ctx, tx, tenant); err != nil {
			return out, fmt.Errorf("lock identity policy: %w", err)
		}
	}
	if err = bind(sourceTenant); err != nil {
		return out, err
	}
	var lockedDestinationTenant, sessionID string
	var sourceCSRFHash string
	if err = tx.QueryRow(ctx, `SELECT s.csrf_token_hash FROM identity_sessions s JOIN identity_credentials c ON c.tenant_id=s.tenant_id AND c.id=s.credential_id WHERE s.tenant_id=$1 AND c.digest=$2`, sourceTenant.String(), replay.SourceCredentialDigest).Scan(&sourceCSRFHash); err != nil {
		return out, switchRetryError(err)
	}
	if replay.SourceCSRFTokenHash != "" && sourceCSRFHash != replay.SourceCSRFTokenHash {
		return out, shared.ErrNotFound
	}
	if err = tx.QueryRow(ctx, `SELECT destination_tenant_id,destination_session_id,response_ciphertext FROM identity_session_switch_retries WHERE tenant_id=$1 AND retry_key=$2 AND payload_hash=$3 AND source_digest=$4 AND revoked_at IS NULL AND expires_at>$5 FOR UPDATE`, sourceTenant.String(), replay.RetryKey, replay.PayloadHash, replay.SourceCredentialDigest, replay.Now).Scan(&lockedDestinationTenant, &sessionID, &out.RetryCiphertext); err != nil {
		return out, switchRetryError(err)
	}
	if lockedDestinationTenant != destinationTenant.String() {
		return out, shared.ErrNotFound
	}
	if err = bind(destinationTenant); err != nil {
		return out, err
	}
	out.Session, _, err = scanEnterpriseSession(tx.QueryRow(ctx, `SELECT s.id,s.tenant_id,s.credential_id,s.membership_id,s.person_id,COALESCE(s.connection_id,''),s.kind,s.lineage_id,COALESCE(s.rotated_from_session_id,''),s.authenticated_at,s.origin_at,s.expires_at,s.person_epoch,s.membership_epoch,COALESCE(s.connection_epoch,0),s.csrf_token_hash,s.revoked_at,s.created_at,m.role FROM identity_sessions s JOIN identity_memberships m ON m.tenant_id=s.tenant_id AND m.id=s.membership_id AND m.state='active' JOIN identity_credentials c ON c.tenant_id=s.tenant_id AND c.id=s.credential_id AND c.state='active' WHERE s.tenant_id=$1 AND s.id=$2 AND s.revoked_at IS NULL AND s.expires_at>$3 FOR UPDATE OF s,m,c`, destinationTenant, sessionID, replay.Now))
	if err != nil {
		return out, switchRetryError(err)
	}
	var destinationDigest string
	if err = tx.QueryRow(ctx, `SELECT digest FROM identity_credentials WHERE tenant_id=$1 AND id=$2 AND state='active'`, destinationTenant, out.Session.CredentialID.String()).Scan(&destinationDigest); err != nil {
		return out, switchRetryError(err)
	}
	if err = validateLockedSessionFences(ctx, tx, destinationTenant, destinationDigest, lockedEnterpriseSession{
		ID: out.Session.ID.String(), CredentialID: out.Session.CredentialID.String(), MembershipID: out.Session.MembershipID.String(), PersonID: out.Session.PersonID.String(), ConnectionID: out.Session.ConnectionID.String(), Kind: out.Session.Kind, LineageID: out.Session.LineageID.String(), AuthenticatedAt: out.Session.AuthenticatedAt, OriginAt: out.Session.OriginAt, PersonEpoch: out.Session.PersonEpoch, MembershipEpoch: out.Session.MembershipEpoch, ConnectionEpoch: out.Session.ConnectionEpoch,
	}, replay.Now); err != nil {
		return out, switchRetryError(err)
	}
	out.Replayed = true
	return out, nil
}

func (s *IdentityFoundationStore) switchRetryDestinationTenant(ctx context.Context, replay ports.IdentitySessionSwitchReplay) (shared.ID, error) {
	var destination *string
	if err := s.pool.QueryRow(ctx, `SELECT synapse_identity_switch_retry_destination_tenant($1,$2,$3)`, replay.SourceCredentialDigest, replay.RetryKey, replay.PayloadHash).Scan(&destination); err != nil {
		return "", fmt.Errorf("locate enterprise switch retry destination: %w", err)
	}
	if destination == nil || *destination == "" {
		return "", shared.ErrNotFound
	}
	return shared.ID(*destination), nil
}

func switchRetryError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, shared.ErrNotFound) || errors.Is(err, shared.ErrForbidden) || errors.Is(err, shared.ErrConflict) {
		return shared.ErrNotFound
	}
	return fmt.Errorf("read retained switch response: %w", err)
}

func (s *IdentityFoundationStore) CleanupEnterpriseSessionRetries(ctx context.Context, tenantID shared.ID, now time.Time, limit int) (int, error) {
	if limit < 1 || limit > 1000 {
		return 0, fmt.Errorf("%w: cleanup limit must be 1..1000", shared.ErrValidation)
	}
	count := 0
	err := s.withIdentityTenant(ctx, tenantID, func(tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `WITH expired AS MATERIALIZED (SELECT retry_key FROM identity_session_switch_retries WHERE tenant_id=$1 AND (expires_at <= $2 OR revoked_at IS NOT NULL) ORDER BY expires_at,retry_key LIMIT $3 FOR UPDATE SKIP LOCKED)
 DELETE FROM identity_session_switch_retries target USING expired WHERE target.tenant_id=$1 AND target.retry_key=expired.retry_key`, tenantID.String(), now, limit)
		count = int(ct.RowsAffected())
		return e
	})
	if err != nil {
		return 0, fmt.Errorf("cleanup session switch retries: %w", err)
	}
	return count, nil
}

func insertEnterpriseSession(ctx context.Context, tx pgx.Tx, issue ports.IdentitySessionIssue, actor string, now time.Time) error {
	v := issue.Session
	policy, err := lockOrganizationPolicy(ctx, tx, v.TenantID)
	if err != nil {
		return err
	}
	// These rows are the authoritative issuance fence. QueryRow, rather than Exec(SELECT), makes
	// a missing membership or connection an error instead of silently issuing a session.
	var membershipEpoch int64
	if err := tx.QueryRow(ctx, `SELECT epoch FROM identity_memberships WHERE tenant_id=$1 AND id=$2 AND person_id=$3 AND state='active' FOR UPDATE`, v.TenantID.String(), v.MembershipID.String(), v.PersonID.String()).Scan(&membershipEpoch); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		return err
	}
	if membershipEpoch != v.MembershipEpoch {
		return shared.ErrNotFound
	}
	if !v.ConnectionID.IsZero() {
		var connectionEpoch int64
		if err := tx.QueryRow(ctx, `SELECT c.epoch FROM identity_connections c WHERE c.tenant_id=$1 AND c.id=$2 AND c.enabled AND COALESCE((SELECT t.state='passed' FROM identity_connection_tests t WHERE t.tenant_id=c.tenant_id AND t.connection_id=c.id AND t.revision=c.revision ORDER BY t.tested_at DESC,t.id DESC LIMIT 1),false) FOR UPDATE`, v.TenantID.String(), v.ConnectionID.String()).Scan(&connectionEpoch); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			return err
		}
		if connectionEpoch != v.ConnectionEpoch {
			return shared.ErrNotFound
		}
	}
	if err := evaluateSessionPolicy(ctx, tx, v, policy, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO identity_credentials(tenant_id,id,kind,digest,membership_id,person_id,source,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'native','active',$7,$7)`, v.TenantID.String(), v.CredentialID.String(), v.Kind, issue.CredentialDigest, v.MembershipID.String(), v.PersonID.String(), now); err != nil {
		return err
	}
	var personEpoch *int64
	if err := tx.QueryRow(ctx, `SELECT synapse_identity_lock_person_epoch($1,$2)`, issue.CredentialDigest, v.PersonID.String()).Scan(&personEpoch); err != nil {
		return err
	}
	if personEpoch == nil || *personEpoch != v.PersonEpoch {
		return shared.ErrNotFound
	}
	_, err = tx.Exec(ctx, `INSERT INTO identity_sessions(tenant_id,id,credential_id,membership_id,person_id,connection_id,lineage_id,rotated_from_session_id,authenticated_at,origin_at,expires_at,person_epoch,membership_epoch,connection_epoch,created_at,kind,csrf_token_hash) VALUES($1,$2,$3,$4,$5,NULLIF($6,''),$7,NULLIF($8,''),$9,$10,$11,$12,$13,NULLIF($14,0),$15,$16,$17)`, v.TenantID.String(), v.ID.String(), v.CredentialID.String(), v.MembershipID.String(), v.PersonID.String(), v.ConnectionID.String(), v.LineageID.String(), v.RotatedFromSessionID.String(), v.AuthenticatedAt, v.OriginAt, v.ExpiresAt, v.PersonEpoch, v.MembershipEpoch, v.ConnectionEpoch, v.CreatedAt, v.Kind, v.CSRFTokenHash)
	if err != nil {
		return err
	}
	return appendTenantAudit(ctx, tx, v.TenantID.String(), ports.AuditEntry{Actor: actor, Action: "identity.session_created", Target: v.ID.String(), At: now, Metadata: map[string]string{"person_id": v.PersonID.String(), "kind": v.Kind}})
}

type lockedEnterpriseSession struct {
	ID              string
	CredentialID    string
	MembershipID    string
	PersonID        string
	ConnectionID    string
	Kind            string
	LineageID       string
	AuthenticatedAt time.Time
	OriginAt        time.Time
	PersonEpoch     int64
	MembershipEpoch int64
	ConnectionEpoch int64
}

func loadLockedEnterpriseSession(ctx context.Context, tx pgx.Tx, tenantID shared.ID, digest string, now time.Time, out *lockedEnterpriseSession) error {
	return tx.QueryRow(ctx, `SELECT s.id,s.credential_id,s.membership_id,s.person_id,COALESCE(s.connection_id,''),s.kind,s.lineage_id,s.authenticated_at,s.origin_at,s.person_epoch,s.membership_epoch,COALESCE(s.connection_epoch,0)
		FROM identity_sessions s
		JOIN identity_credentials c ON c.tenant_id=s.tenant_id AND c.id=s.credential_id
		WHERE s.tenant_id=$1 AND c.digest=$2 AND c.state='active' AND s.revoked_at IS NULL AND s.expires_at>$3
		FOR UPDATE OF s,c`, tenantID.String(), digest, now).Scan(&out.ID, &out.CredentialID, &out.MembershipID, &out.PersonID, &out.ConnectionID, &out.Kind, &out.LineageID, &out.AuthenticatedAt, &out.OriginAt, &out.PersonEpoch, &out.MembershipEpoch, &out.ConnectionEpoch)
}

func sameSessionLineage(source lockedEnterpriseSession, replacement identity.EnterpriseSession) bool {
	return replacement.TenantID.String() != "" &&
		replacement.MembershipID.String() == source.MembershipID &&
		replacement.PersonID.String() == source.PersonID &&
		replacement.ConnectionID.String() == source.ConnectionID &&
		replacement.Kind == source.Kind &&
		replacement.LineageID.String() == source.LineageID &&
		replacement.RotatedFromSessionID.String() == source.ID &&
		replacement.AuthenticatedAt.Equal(source.AuthenticatedAt) &&
		replacement.OriginAt.Equal(source.OriginAt) &&
		replacement.PersonEpoch == source.PersonEpoch &&
		replacement.MembershipEpoch == source.MembershipEpoch &&
		replacement.ConnectionEpoch == source.ConnectionEpoch
}

func validateLockedSessionFences(ctx context.Context, tx pgx.Tx, tenantID shared.ID, digest string, session lockedEnterpriseSession, now time.Time) error {
	policy, err := lockOrganizationPolicy(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	var membershipEpoch int64
	if err := tx.QueryRow(ctx, `SELECT epoch FROM identity_memberships WHERE tenant_id=$1 AND id=$2 AND person_id=$3 AND state='active' FOR UPDATE`, tenantID.String(), session.MembershipID, session.PersonID).Scan(&membershipEpoch); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		return err
	}
	if membershipEpoch != session.MembershipEpoch {
		return shared.ErrNotFound
	}
	if session.ConnectionID != "" {
		var connectionEpoch int64
		if err := tx.QueryRow(ctx, `SELECT epoch FROM identity_connections WHERE tenant_id=$1 AND id=$2 AND enabled FOR UPDATE`, tenantID.String(), session.ConnectionID).Scan(&connectionEpoch); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return shared.ErrNotFound
			}
			return err
		}
		if connectionEpoch != session.ConnectionEpoch {
			return shared.ErrNotFound
		}
	}
	var personEpoch *int64
	if err := tx.QueryRow(ctx, `SELECT synapse_identity_lock_person_epoch($1,$2)`, digest, session.PersonID).Scan(&personEpoch); err != nil {
		return err
	}
	if personEpoch == nil || *personEpoch != session.PersonEpoch {
		return shared.ErrNotFound
	}
	return evaluateSessionPolicy(ctx, tx, identity.EnterpriseSession{
		TenantID: tenantID, MembershipID: shared.ID(session.MembershipID), PersonID: shared.ID(session.PersonID), ConnectionID: shared.ID(session.ConnectionID), Kind: session.Kind,
	}, policy, now)
}

func lockOrganizationPolicy(ctx context.Context, tx pgx.Tx, tenantID shared.ID) (authz.OrganizationPolicy, error) {
	var policy authz.OrganizationPolicy
	err := tx.QueryRow(ctx, `SELECT sso_requirement,COALESCE(activation_time,'epoch'::timestamptz),grace_enabled FROM identity_policies WHERE tenant_id=$1 FOR UPDATE`, tenantID.String()).Scan(&policy.Requirement, &policy.ActivatedAt, &policy.LegacyBearerGraceEnabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return authz.OrganizationPolicy{}, shared.ErrNotFound
	}
	return policy, err
}

func evaluateSessionPolicy(ctx context.Context, tx pgx.Tx, session identity.EnterpriseSession, policy authz.OrganizationPolicy, now time.Time) error {
	proof := authz.DestinationAuthentication{ActiveMembership: true}
	if !session.ConnectionID.IsZero() {
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_authenticators WHERE tenant_id=$1 AND connection_id=$2 AND membership_id=$3 AND person_id=$4 AND state='approved')`, session.TenantID.String(), session.ConnectionID.String(), session.MembershipID.String(), session.PersonID.String()).Scan(&proof.ApprovedDestinationSSO); err != nil {
			return err
		}
	}
	if !policy.EvaluateAuthentication(authz.CredentialKind(session.Kind), proof, now).Allowed {
		return shared.ErrForbidden
	}
	return nil
}

func scanEnterpriseSession(row pgx.Row) (identity.EnterpriseSession, string, error) {
	var v identity.EnterpriseSession
	var id, tenant, credential, membership, person, connection, kind, lineage, rotated string
	var revoked *time.Time
	var role string
	err := row.Scan(&id, &tenant, &credential, &membership, &person, &connection, &kind, &lineage, &rotated, &v.AuthenticatedAt, &v.OriginAt, &v.ExpiresAt, &v.PersonEpoch, &v.MembershipEpoch, &v.ConnectionEpoch, &v.CSRFTokenHash, &revoked, &v.CreatedAt, &role)
	if err != nil {
		return identity.EnterpriseSession{}, "", err
	}
	v.ID, v.TenantID, v.CredentialID, v.MembershipID, v.PersonID, v.ConnectionID, v.Kind, v.LineageID, v.RotatedFromSessionID = shared.ID(id), shared.ID(tenant), shared.ID(credential), shared.ID(membership), shared.ID(person), shared.ID(connection), kind, shared.ID(lineage), shared.ID(rotated)
	v.RevokedAt = revoked
	return v, role, nil
}
