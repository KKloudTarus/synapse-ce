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

var _ ports.IdentityProvisioningStore = (*IdentityFoundationStore)(nil)

// lockInitialProvisioning takes the same target-policy lock as identity admission. The scoped
// proof never mutates the source tenant and therefore never needs a forged target principal.
func lockInitialProvisioning(ctx context.Context, tx pgx.Tx, tenant shared.ID) error {
	return lockIdentityAdministration(ctx, tx, tenant)
}

func validInitialPrincipal(p authz.Principal, target shared.ID) bool {
	return p.IsBootstrap() && p.Role == user.RoleAdmin && p.TenantID != "" && p.TenantID != target.String() && p.Credential.ID != ""
}

func normalizedInitialRecipient(recipient string, allowEmpty bool) (string, error) {
	if recipient == "" && allowEmpty {
		return "", nil
	}
	normalized, err := user.NormalizeContactEmail(recipient)
	if err != nil {
		return "", fmt.Errorf("%w: initial administrator recipient", shared.ErrValidation)
	}
	return normalized, nil
}

func initialPolicyFresh(ctx context.Context, tx pgx.Tx, tenant shared.ID) error {
	var phase, requirement string
	var breakGlass bool
	if err := tx.QueryRow(ctx, `SELECT cutover_phase,sso_requirement,break_glass_enabled FROM identity_policies WHERE tenant_id=$1 FOR UPDATE`, tenant.String()).Scan(&phase, &requirement, &breakGlass); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrForbidden
		}
		return err
	}
	if phase != "declared" || requirement != "optional" || breakGlass {
		return shared.ErrForbidden
	}
	return nil
}

// initialTargetEmpty permits only a declared native cutover policy and its ledger evidence. Any
// identity, legacy, imported, or recovery history means the first-admin operation cannot safely
// establish the tenant's identity authority.
func initialTargetEmpty(ctx context.Context, tx pgx.Tx, tenant shared.ID) error {
	checks := []struct {
		name  string
		query string
	}{
		{"legacy users", `SELECT count(*) FROM users WHERE ownership_tenant_id=$1`},
		{"connections", `SELECT count(*) FROM identity_connections WHERE tenant_id=$1`},
		{"connection revisions", `SELECT count(*) FROM identity_connection_revisions WHERE tenant_id=$1`},
		{"connection tests", `SELECT count(*) FROM identity_connection_tests WHERE tenant_id=$1`},
		{"memberships", `SELECT count(*) FROM identity_memberships WHERE tenant_id=$1`},
		{"authenticators", `SELECT count(*) FROM identity_authenticators WHERE tenant_id=$1`},
		{"credentials", `SELECT count(*) FROM identity_credentials WHERE tenant_id=$1`},
		{"sessions", `SELECT count(*) FROM identity_sessions WHERE tenant_id=$1`},
		{"invitations", `SELECT count(*) FROM identity_invitations WHERE tenant_id=$1`},
		{"invitation challenges", `SELECT count(*) FROM identity_invitation_challenges WHERE tenant_id=$1`},
		{"protocol proofs", `SELECT count(*) FROM identity_connection_protocol_proofs WHERE tenant_id=$1`},
		{"transactions", `SELECT count(*) FROM identity_transactions WHERE tenant_id=$1`},
		{"backfill items", `SELECT count(*) FROM identity_backfill_items WHERE tenant_id=$1`},
		{"recovery policies", `SELECT count(*) FROM identity_recovery_policies WHERE tenant_id=$1`},
		{"recovery activations", `SELECT count(*) FROM identity_recovery_activations WHERE tenant_id=$1`},
		{"recovery alerts", `SELECT count(*) FROM identity_recovery_alerts WHERE tenant_id=$1`},
	}
	for _, check := range checks {
		var count int
		if err := tx.QueryRow(ctx, check.query, tenant.String()).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("%w: target has %s", shared.ErrConflict, check.name)
		}
	}
	// A zero-user tenant reaches declared cutover through the supported CLI, which intentionally
	// leaves a fence, completed run history, and clean shadow reports. Those records prove an
	// empty import; rejecting them would make a native tenant impossible to bootstrap.
	var badProvenance int
	if err := tx.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM identity_backfill_fences WHERE tenant_id=$1 AND (projection_enabled=false OR checkpoint_user_id<>''))+
 (SELECT count(*) FROM identity_backfill_runs WHERE tenant_id=$1 AND (state<>'completed' OR processed<>0))+
 (SELECT count(*) FROM identity_shadow_reports WHERE tenant_id=$1 AND
   (legacy_users<>0 OR bootstrap_skipped<>0 OR memberships<>0 OR missing_memberships<>0 OR credentials_expected<>0 OR credentials_matched<>0 OR
    authenticators_expected<>0 OR authenticators_matched<>0 OR authenticator_mismatches<>0 OR digest_mismatches<>0 OR routing_mismatches<>0 OR
    role_drift<>0 OR state_drift<>0 OR placeholders<>0 OR ambiguous<>0 OR drift_total<>0 OR aborted OR NOT ready OR NOT rollback_prepared))+
 (SELECT count(*) FROM identity_cutover_ledger WHERE tenant_id=$1 AND action='contracted')`, tenant.String()).Scan(&badProvenance); err != nil {
		return err
	}
	if badProvenance != 0 {
		return fmt.Errorf("%w: target cutover provenance is not an empty native lifecycle", shared.ErrConflict)
	}
	var declared bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_cutover_ledger WHERE tenant_id=$1 AND action='declared')`, tenant.String()).Scan(&declared); err != nil {
		return err
	}
	if !declared {
		return fmt.Errorf("%w: target has no declared native cutover evidence", shared.ErrConflict)
	}
	return nil
}

func initialShape(ctx context.Context, tx pgx.Tx, p ports.IdentityInitialProvisioning) error {
	checks := []struct {
		name  string
		query string
		args  []any
	}{
		{"unreserved connection", `SELECT count(*) FROM identity_connections WHERE tenant_id=$1 AND id<>$2`, []any{p.TenantID.String(), p.ConnectionID.String()}},
		{"unreserved invitation", `SELECT count(*) FROM identity_invitations WHERE tenant_id=$1 AND id<>$2`, []any{p.TenantID.String(), p.InvitationID.String()}},
		{"membership", `SELECT count(*) FROM identity_memberships WHERE tenant_id=$1`, []any{p.TenantID.String()}},
		{"authenticator", `SELECT count(*) FROM identity_authenticators WHERE tenant_id=$1`, []any{p.TenantID.String()}},
		{"credential", `SELECT count(*) FROM identity_credentials WHERE tenant_id=$1`, []any{p.TenantID.String()}},
		{"session", `SELECT count(*) FROM identity_sessions WHERE tenant_id=$1`, []any{p.TenantID.String()}},
		{"unscoped authorization transaction", `SELECT count(*) FROM identity_transactions WHERE tenant_id=$1 AND NOT (purpose='test' AND connection_id=$2 AND session_id IS NULL)`, []any{p.TenantID.String(), p.ConnectionID.String()}},
		{"legacy user", `SELECT count(*) FROM users WHERE ownership_tenant_id=$1`, []any{p.TenantID.String()}},
		{"backfill item", `SELECT count(*) FROM identity_backfill_items WHERE tenant_id=$1`, []any{p.TenantID.String()}},
		{"recovery state", `SELECT count(*) FROM identity_recovery_policies WHERE tenant_id=$1 UNION ALL SELECT count(*) FROM identity_recovery_activations WHERE tenant_id=$1 UNION ALL SELECT count(*) FROM identity_recovery_alerts WHERE tenant_id=$1`, []any{p.TenantID.String()}},
	}
	for _, check := range checks {
		rows, err := tx.Query(ctx, check.query, check.args...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var count int
			if err := rows.Scan(&count); err != nil {
				rows.Close()
				return err
			}
			if count != 0 {
				rows.Close()
				return fmt.Errorf("%w: target has %s", shared.ErrConflict, check.name)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	return nil
}

func scanInitialProvisioning(row pgx.Row) (ports.IdentityInitialProvisioning, error) {
	var out ports.IdentityInitialProvisioning
	var tenant, id, connection, invitation string
	var closedAt *time.Time
	err := row.Scan(&tenant, &id, &connection, &invitation, &out.ActorID, &out.SourceTenantID, &out.CredentialID, &out.Recipient, &out.State, &out.InvitationCodeSealed, &out.Version, &out.CreatedAt, &out.UpdatedAt, &closedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, shared.ErrNotFound
	}
	if err != nil {
		return out, err
	}
	out.TenantID, out.ID, out.ConnectionID, out.InvitationID, out.ClosedAt = shared.ID(tenant), shared.ID(id), shared.ID(connection), shared.ID(invitation), closedAt
	return out, nil
}

const initialProvisioningColumns = `tenant_id,id,connection_id,invitation_id,actor_id,source_tenant_id,credential_id,recipient,state,COALESCE(invitation_code_sealed,''),version,created_at,updated_at,closed_at`

func provisioningByID(ctx context.Context, tx pgx.Tx, tenant, id shared.ID, lock bool) (ports.IdentityInitialProvisioning, error) {
	query := `SELECT ` + initialProvisioningColumns + ` FROM identity_initial_provisioning WHERE tenant_id=$1 AND id=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	return scanInitialProvisioning(tx.QueryRow(ctx, query, tenant.String(), id.String()))
}

func loadInitialProvisioning(ctx context.Context, tx pgx.Tx, proof ports.IdentityProvisioningProof, allowClosed bool) (ports.IdentityInitialProvisioning, error) {
	if !proof.Active() {
		return ports.IdentityInitialProvisioning{}, shared.ErrForbidden
	}
	// Keep the policy-row lock order identical to admission and the membership closure trigger:
	// policy first, then the durable operation. This serializes closure with all scoped reads and
	// writes without an inverse lock order.
	if err := lockInitialProvisioning(ctx, tx, proof.TenantID); err != nil {
		return ports.IdentityInitialProvisioning{}, err
	}
	recipient, err := normalizedInitialRecipient(proof.Recipient, false)
	if err != nil {
		return ports.IdentityInitialProvisioning{}, shared.ErrForbidden
	}
	state, err := provisioningByID(ctx, tx, proof.TenantID, proof.ID, true)
	if err != nil {
		return ports.IdentityInitialProvisioning{}, err
	}
	if (!allowClosed && state.State == "closed") || state.ConnectionID != proof.ConnectionID || state.InvitationID != proof.InvitationID || state.ActorID != proof.Principal.ActorID || state.SourceTenantID != proof.Principal.TenantID || state.CredentialID != proof.Principal.Credential.ID || state.Recipient != recipient {
		return ports.IdentityInitialProvisioning{}, shared.ErrForbidden
	}
	if state.State == "closed" {
		return state, nil
	}
	if err := initialPolicyFresh(ctx, tx, proof.TenantID); err != nil {
		return ports.IdentityInitialProvisioning{}, err
	}
	if err := initialShape(ctx, tx, state); err != nil {
		return ports.IdentityInitialProvisioning{}, err
	}
	return state, nil
}

func hydrateInitialProvisioning(ctx context.Context, tx pgx.Tx, out *ports.IdentityInitialProvisioning, at time.Time) error {
	connection, err := connectionByRevision(ctx, tx, out.TenantID, out.ConnectionID, 0)
	if err == nil {
		// Provisioning operates on an unactivated draft. Once a secret is corrected, the active
		// revision remains unchanged while DraftRevision advances; status must expose that newest
		// revision so a caller cannot accidentally test or activate stale trust material.
		if connection.DraftRevision > connection.Revision {
			connection, err = connectionByRevision(ctx, tx, out.TenantID, out.ConnectionID, connection.DraftRevision)
		}
		if err != nil {
			return err
		}
		// connectionByRevision deliberately projects the active revision's test result for
		// ordinary connection reads. Provisioning can instead expose an unactivated draft,
		// so it must determine status from the settings revision it returns and require a
		// still-valid test at this operation's time.
		if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT state='passed' AND expires_at>$4 AND tested_at+interval '1 hour'>$4 FROM identity_connection_tests WHERE tenant_id=$1 AND connection_id=$2 AND revision=$3 ORDER BY tested_at DESC,id DESC LIMIT 1),false)`, out.TenantID.String(), out.ConnectionID.String(), connection.SettingsRevision, at.UTC()).Scan(&connection.TestPassed); err != nil {
			return err
		}
		out.Connection = &connection
	} else if !errors.Is(err, shared.ErrNotFound) {
		return err
	}
	invitation, err := scanInitialInvitation(ctx, tx, out.TenantID, out.InvitationID)
	if err == nil {
		out.Invitation = &invitation
	} else if !errors.Is(err, shared.ErrNotFound) {
		return err
	}
	return nil
}

func scanInitialInvitation(ctx context.Context, tx pgx.Tx, tenant, id shared.ID) (ports.IdentityInvitation, error) {
	var out ports.IdentityInvitation
	var role string
	var acceptedMembership, acceptedPerson string
	err := tx.QueryRow(ctx, `SELECT recipient,role,state,version,expires_at,created_at,COALESCE(accepted_membership_id,''),COALESCE(accepted_person_id,'') FROM identity_invitations WHERE tenant_id=$1 AND id=$2`, tenant.String(), id.String()).Scan(&out.Recipient, &role, &out.State, &out.Version, &out.ExpiresAt, &out.CreatedAt, &acceptedMembership, &acceptedPerson)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, shared.ErrNotFound
	}
	if err != nil {
		return out, err
	}
	out.ID, out.TenantID, out.Role, out.AcceptedMembershipID, out.AcceptedPersonID = id, tenant, user.Role(role), shared.ID(acceptedMembership), shared.ID(acceptedPerson)
	return out, nil
}

func (s *IdentityFoundationStore) BeginIdentityProvisioning(ctx context.Context, begin ports.IdentityProvisioningBegin) (out ports.IdentityInitialProvisioning, err error) {
	// An empty recipient is intentionally accepted only after a matching durable operation is
	// found below; a first reservation always has an explicit administrator recipient.
	recipient, recipientErr := normalizedInitialRecipient(begin.Recipient, true)
	if recipientErr != nil || begin.TenantID.IsZero() || begin.ID.IsZero() || begin.ConnectionID.IsZero() || begin.InvitationID.IsZero() || begin.At.IsZero() || !validInitialPrincipal(begin.Principal, begin.TenantID) {
		return out, shared.ErrForbidden
	}
	err = s.withIdentityTenant(ctx, begin.TenantID, func(tx pgx.Tx) error {
		if err := lockInitialProvisioning(ctx, tx, begin.TenantID); err != nil {
			return err
		}
		// The tenant primary key, rather than a caller-generated operation id, is the durable
		// retry key. This lets a lost Begin response converge even after process restart.
		existing, getErr := scanInitialProvisioning(tx.QueryRow(ctx, `SELECT `+initialProvisioningColumns+` FROM identity_initial_provisioning WHERE tenant_id=$1 FOR UPDATE`, begin.TenantID.String()))
		if errors.Is(getErr, shared.ErrNotFound) {
			if recipient == "" {
				return shared.ErrValidation
			}
			if err := initialPolicyFresh(ctx, tx, begin.TenantID); err != nil {
				return err
			}
			var other int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM identity_initial_provisioning WHERE tenant_id=$1`, begin.TenantID.String()).Scan(&other); err != nil {
				return err
			}
			if other != 0 {
				return shared.ErrConflict
			}
			if err := initialTargetEmpty(ctx, tx, begin.TenantID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO identity_initial_provisioning(tenant_id,id,connection_id,invitation_id,actor_id,source_tenant_id,credential_id,recipient,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'open',$9,$9)`, begin.TenantID.String(), begin.ID.String(), begin.ConnectionID.String(), begin.InvitationID.String(), begin.Principal.ActorID, begin.Principal.TenantID, begin.Principal.Credential.ID, recipient, begin.At.UTC()); err != nil {
				return err
			}
			if err := appendTenantAudit(ctx, tx, begin.TenantID.String(), ports.AuditEntry{Actor: begin.Principal.ActorID, Action: "identity.initial_provisioning_started", Target: begin.ID.String(), At: begin.At}); err != nil {
				return err
			}
			out, err = provisioningByID(ctx, tx, begin.TenantID, begin.ID, true)
			return err
		}
		if getErr != nil {
			return getErr
		}
		if existing.ActorID != begin.Principal.ActorID || existing.SourceTenantID != begin.Principal.TenantID || (begin.Recipient != "" && existing.Recipient != recipient) {
			return shared.ErrConflict
		}
		if existing.State == "closed" {
			out = existing
			return hydrateInitialProvisioning(ctx, tx, &out, begin.At)
		}
		if err := initialPolicyFresh(ctx, tx, begin.TenantID); err != nil {
			return err
		}
		if existing.CredentialID != begin.Principal.Credential.ID {
			updated, err := tx.Exec(ctx, `UPDATE identity_initial_provisioning SET credential_id=$3,updated_at=$4,version=version+1 WHERE tenant_id=$1 AND id=$2`, begin.TenantID.String(), existing.ID.String(), begin.Principal.Credential.ID, begin.At.UTC())
			if err != nil {
				return err
			}
			if updated.RowsAffected() != 1 {
				return shared.ErrConflict
			}
			if err := appendTenantAudit(ctx, tx, begin.TenantID.String(), ports.AuditEntry{Actor: begin.Principal.ActorID, Action: "identity.initial_provisioning_credential_rebound", Target: existing.ID.String(), At: begin.At}); err != nil {
				return err
			}
		}
		out, err = provisioningByID(ctx, tx, begin.TenantID, existing.ID, true)
		if err != nil {
			return err
		}
		return hydrateInitialProvisioning(ctx, tx, &out, begin.At)
	})
	if err == nil && out.ID == begin.ID {
		err = s.withIdentityTenant(ctx, begin.TenantID, func(tx pgx.Tx) error { return hydrateInitialProvisioning(ctx, tx, &out, begin.At) })
	}
	return out, err
}

func (s *IdentityFoundationStore) ReadIdentityProvisioning(ctx context.Context, proof ports.IdentityProvisioningProof) (out ports.IdentityInitialProvisioning, err error) {
	err = s.withIdentityTenant(ctx, proof.TenantID, func(tx pgx.Tx) error {
		var loadErr error
		out, loadErr = loadInitialProvisioning(ctx, tx, proof, true)
		if loadErr != nil {
			return loadErr
		}
		return hydrateInitialProvisioning(ctx, tx, &out, proof.At)
	})
	return out, err
}

func provisioningDraftValid(d ports.IdentityConnectionDraft, proof ports.IdentityProvisioningProof) bool {
	return d.TenantID == proof.TenantID && d.ID == proof.ConnectionID && d.ExpectedVersion >= 0 && strings.TrimSpace(d.DisplayName) != "" && len(d.DisplayName) <= 200 && d.Issuer != "" && d.Settings.ClientID != "" && d.Settings.SealedClientSecret != ""
}

func (s *IdentityFoundationStore) SaveIdentityProvisioningDraft(ctx context.Context, draft ports.IdentityConnectionDraft, proof ports.IdentityProvisioningProof) (out ports.IdentityInitialProvisioning, err error) {
	if !provisioningDraftValid(draft, proof) {
		return out, shared.ErrValidation
	}
	if err := ports.ValidateAuth0OrganizationID(draft.Settings.Auth0OrganizationID); err != nil {
		return out, err
	}
	if err := ports.ValidateEntraSettings(draft.Issuer, draft.Settings.EntraDiscoveryMode, draft.Settings.Auth0OrganizationID); err != nil {
		return out, err
	}
	err = s.withIdentityTenant(ctx, proof.TenantID, func(tx pgx.Tx) error {
		state, err := loadInitialProvisioning(ctx, tx, proof, false)
		if err != nil {
			return err
		}
		if state.State == "active" || state.State == "invited" {
			return shared.ErrConflict
		}
		current, getErr := connectionByRevision(ctx, tx, proof.TenantID, proof.ConnectionID, 0)
		if getErr == nil {
			if current.Issuer != draft.Issuer || current.DisplayName != draft.DisplayName || current.Settings.ClientID != draft.Settings.ClientID || current.Settings.RedirectURL != draft.Settings.RedirectURL || current.Settings.Auth0OrganizationID != draft.Settings.Auth0OrganizationID || current.Settings.EntraDiscoveryMode != draft.Settings.EntraDiscoveryMode {
				return fmt.Errorf("%w: trust changes require a new connection", shared.ErrConflict)
			}
			if state.State != "draft" && state.State != "tested" {
				return shared.ErrConflict
			}
			// A client that lost the initial response retains ExpectedVersion zero. Sealing is
			// randomized, so the same browser request can carry different ciphertext; replay the
			// already pinned trust without mutating its stored secret. A replacement requires the
			// current connection version below.
			if draft.ExpectedVersion == 0 {
				out = state
				return hydrateInitialProvisioning(ctx, tx, &out, proof.At)
			}
			if draft.ExpectedVersion != current.Version {
				return shared.ErrConflict
			}
			settings, err := json.Marshal(draft.Settings)
			if err != nil {
				return err
			}
			revision := current.DraftRevision + 1
			if _, err = tx.Exec(ctx, `UPDATE identity_connections SET version=version+1,updated_at=$3 WHERE tenant_id=$1 AND id=$2`, proof.TenantID.String(), proof.ConnectionID.String(), proof.At.UTC()); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `INSERT INTO identity_connection_revisions(tenant_id,connection_id,revision,settings,actor,created_at) VALUES($1,$2,$3,$4,$5,$6)`, proof.TenantID.String(), proof.ConnectionID.String(), revision, settings, proof.Principal.ActorID, proof.At.UTC()); err != nil {
				return err
			}
			// A callback initiated with the replaced secret cannot be accepted for the new draft.
			if _, err = tx.Exec(ctx, `UPDATE identity_transactions SET consumed_at=$3 WHERE tenant_id=$1 AND connection_id=$2 AND connection_revision<>$4 AND consumed_at IS NULL`, proof.TenantID.String(), proof.ConnectionID.String(), proof.At.UTC(), revision); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `UPDATE identity_initial_provisioning SET state='draft',updated_at=$3,version=version+1 WHERE tenant_id=$1 AND id=$2`, proof.TenantID.String(), proof.ID.String(), proof.At.UTC()); err != nil {
				return err
			}
			if err = appendTenantAudit(ctx, tx, proof.TenantID.String(), ports.AuditEntry{Actor: proof.Principal.ActorID, Action: "identity.initial_provisioning_secret_replaced", Target: proof.ConnectionID.String(), At: proof.At}); err != nil {
				return err
			}
			out, err = provisioningByID(ctx, tx, proof.TenantID, proof.ID, true)
			if err != nil {
				return err
			}
			return hydrateInitialProvisioning(ctx, tx, &out, proof.At)
		}
		if !errors.Is(getErr, shared.ErrNotFound) {
			return getErr
		}
		if draft.ExpectedVersion != 0 {
			return shared.ErrConflict
		}
		settings, err := json.Marshal(draft.Settings)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO identity_connections(tenant_id,id,protocol,trust_namespace,display_name,created_at,updated_at) VALUES($1,$2,'oidc',$3,$4,$5,$5)`, proof.TenantID.String(), proof.ConnectionID.String(), draft.Issuer, draft.DisplayName, proof.At.UTC()); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO identity_connection_revisions(tenant_id,connection_id,revision,settings,actor,created_at) VALUES($1,$2,1,$3,$4,$5)`, proof.TenantID.String(), proof.ConnectionID.String(), settings, proof.Principal.ActorID, proof.At.UTC()); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE identity_initial_provisioning SET state='draft',updated_at=$3,version=version+1 WHERE tenant_id=$1 AND id=$2`, proof.TenantID.String(), proof.ID.String(), proof.At.UTC()); err != nil {
			return err
		}
		if err = appendTenantAudit(ctx, tx, proof.TenantID.String(), ports.AuditEntry{Actor: proof.Principal.ActorID, Action: "identity.initial_provisioning_draft_saved", Target: proof.ConnectionID.String(), At: proof.At}); err != nil {
			return err
		}
		out, err = provisioningByID(ctx, tx, proof.TenantID, proof.ID, true)
		if err != nil {
			return err
		}
		return hydrateInitialProvisioning(ctx, tx, &out, proof.At)
	})
	return out, err
}

func (s *IdentityFoundationStore) RecordIdentityProvisioningTest(ctx context.Context, test ports.IdentityConnectionTest, proof ports.IdentityProvisioningProof) error {
	if test.ID.IsZero() || test.TenantID != proof.TenantID || test.ConnectionID != proof.ConnectionID || test.Revision < 1 || !test.Passed || test.At.IsZero() || !test.ExpiresAt.After(test.At) || test.ExpiresAt.After(test.At.Add(time.Hour)) {
		return shared.ErrValidation
	}
	return s.withIdentityTenant(ctx, proof.TenantID, func(tx pgx.Tx) error {
		state, err := loadInitialProvisioning(ctx, tx, proof, false)
		if err != nil {
			return err
		}
		if state.State != "draft" && state.State != "tested" {
			return shared.ErrConflict
		}
		connection, err := connectionByRevision(ctx, tx, proof.TenantID, proof.ConnectionID, test.Revision)
		if err != nil {
			return err
		}
		if connection.DraftRevision != test.Revision {
			return shared.ErrConflict
		}
		var existingState string
		err = tx.QueryRow(ctx, `SELECT state FROM identity_connection_tests WHERE tenant_id=$1 AND id=$2`, proof.TenantID.String(), test.ID.String()).Scan(&existingState)
		if errors.Is(err, pgx.ErrNoRows) {
			if _, err = tx.Exec(ctx, `INSERT INTO identity_connection_tests(tenant_id,id,connection_id,revision,state,tested_at,expires_at) VALUES($1,$2,$3,$4,'passed',$5,$6)`, proof.TenantID.String(), test.ID.String(), proof.ConnectionID.String(), test.Revision, test.At.UTC(), test.ExpiresAt.UTC()); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `UPDATE identity_initial_provisioning SET state='tested',updated_at=$3,version=version+1 WHERE tenant_id=$1 AND id=$2`, proof.TenantID.String(), proof.ID.String(), proof.At.UTC()); err != nil {
				return err
			}
			return appendTenantAudit(ctx, tx, proof.TenantID.String(), ports.AuditEntry{Actor: proof.Principal.ActorID, Action: "identity.initial_provisioning_tested", Target: proof.ConnectionID.String(), At: proof.At})
		}
		if err != nil {
			return err
		}
		if existingState != "passed" {
			return shared.ErrConflict
		}
		return nil
	})
}

func (s *IdentityFoundationStore) ActivateIdentityProvisioningConnection(ctx context.Context, revision, version int, proof ports.IdentityProvisioningProof) (out ports.IdentityInitialProvisioning, err error) {
	if revision < 1 || version < 1 {
		return out, shared.ErrValidation
	}
	err = s.withIdentityTenant(ctx, proof.TenantID, func(tx pgx.Tx) error {
		state, err := loadInitialProvisioning(ctx, tx, proof, false)
		if err != nil {
			return err
		}
		connection, err := connectionByRevision(ctx, tx, proof.TenantID, proof.ConnectionID, 0)
		if err != nil {
			return err
		}
		if connection.Enabled && connection.Revision == revision && state.State == "active" {
			out = state
			return hydrateInitialProvisioning(ctx, tx, &out, proof.At)
		}
		if state.State != "tested" || connection.DraftRevision != revision || connection.Version != version {
			return shared.ErrConflict
		}
		var passed bool
		if err = tx.QueryRow(ctx, `SELECT COALESCE((SELECT state='passed' AND expires_at>$4 AND tested_at+interval '1 hour'>$4 FROM identity_connection_tests WHERE tenant_id=$1 AND connection_id=$2 AND revision=$3 ORDER BY tested_at DESC,id DESC LIMIT 1),false)`, proof.TenantID.String(), proof.ConnectionID.String(), revision, proof.At).Scan(&passed); err != nil {
			return err
		}
		if !passed {
			return shared.ErrConflict
		}
		if _, err = tx.Exec(ctx, `UPDATE identity_connections SET enabled=true,revision=$3,version=version+1,updated_at=$4 WHERE tenant_id=$1 AND id=$2`, proof.TenantID.String(), proof.ConnectionID.String(), revision, proof.At.UTC()); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE identity_initial_provisioning SET state='active',updated_at=$3,version=version+1 WHERE tenant_id=$1 AND id=$2`, proof.TenantID.String(), proof.ID.String(), proof.At.UTC()); err != nil {
			return err
		}
		if err = appendTenantAudit(ctx, tx, proof.TenantID.String(), ports.AuditEntry{Actor: proof.Principal.ActorID, Action: "identity.initial_provisioning_activated", Target: proof.ConnectionID.String(), At: proof.At}); err != nil {
			return err
		}
		out, err = provisioningByID(ctx, tx, proof.TenantID, proof.ID, true)
		if err != nil {
			return err
		}
		return hydrateInitialProvisioning(ctx, tx, &out, proof.At)
	})
	return out, err
}

func (s *IdentityFoundationStore) IssueIdentityProvisioningInvitation(ctx context.Context, in ports.IdentityInvitationCreate, sealed string, proof ports.IdentityProvisioningProof) (out ports.IdentityInitialProvisioning, err error) {
	invitation := in.Invitation
	recipient, recipientErr := normalizedInitialRecipient(invitation.Recipient, false)
	if recipientErr != nil || invitation.TenantID != proof.TenantID || invitation.ID != proof.InvitationID || invitation.Role != user.RoleAdmin || in.Actor != proof.Principal.ActorID || !identityDigestPattern.MatchString(in.CodeDigest) || invitation.CreatedAt.IsZero() || invitation.ExpiresAt.IsZero() || !invitation.ExpiresAt.After(invitation.CreatedAt) || invitation.ExpiresAt.Sub(invitation.CreatedAt) > 7*24*time.Hour || strings.TrimSpace(sealed) == "" {
		return out, shared.ErrValidation
	}
	err = s.withIdentityTenant(ctx, proof.TenantID, func(tx pgx.Tx) error {
		state, err := loadInitialProvisioning(ctx, tx, proof, false)
		if err != nil {
			return err
		}
		if recipient != state.Recipient {
			return shared.ErrForbidden
		}
		if state.State == "invited" {
			invitation, err := scanInitialInvitation(ctx, tx, proof.TenantID, proof.InvitationID)
			if err != nil {
				return err
			}
			if invitation.State != "pending" || !invitation.ExpiresAt.After(proof.At) || invitation.Recipient != state.Recipient || invitation.Role != user.RoleAdmin || state.InvitationCodeSealed == "" {
				return shared.ErrConflict
			}
			out = state
			out.Invitation = &invitation
			return nil
		}
		if state.State != "active" {
			return shared.ErrConflict
		}
		connection, err := connectionByRevision(ctx, tx, proof.TenantID, proof.ConnectionID, 0)
		if err != nil || !connection.Enabled || !connection.TestPassed {
			return shared.ErrConflict
		}
		if _, err = tx.Exec(ctx, `INSERT INTO identity_invitations(tenant_id,id,code_digest,recipient,role,state,created_by,expires_at,created_at,updated_at,version) VALUES($1,$2,$3,$4,'admin','pending',$5,$6,$7,$7,1)`, proof.TenantID.String(), proof.InvitationID.String(), in.CodeDigest, state.Recipient, proof.Principal.ActorID, invitation.ExpiresAt.UTC(), invitation.CreatedAt.UTC()); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE identity_initial_provisioning SET state='invited',invitation_code_sealed=$3,updated_at=$4,version=version+1 WHERE tenant_id=$1 AND id=$2`, proof.TenantID.String(), proof.ID.String(), sealed, proof.At.UTC()); err != nil {
			return err
		}
		if err = appendTenantAudit(ctx, tx, proof.TenantID.String(), ports.AuditEntry{Actor: proof.Principal.ActorID, Action: "identity.initial_provisioning_invited", Target: proof.InvitationID.String(), At: proof.At, Metadata: map[string]string{"role": "admin"}}); err != nil {
			return err
		}
		out, err = provisioningByID(ctx, tx, proof.TenantID, proof.ID, true)
		if err != nil {
			return err
		}
		return hydrateInitialProvisioning(ctx, tx, &out, proof.At)
	})
	return out, err
}
