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

	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.IdentityAdmissionStore = (*IdentityFoundationStore)(nil)

func (s *IdentityFoundationStore) CreateIdentityInvitation(ctx context.Context, in ports.IdentityInvitationCreate, proof ports.IdentityAdminProof) error {
	v := in.Invitation
	recipient, err := user.NormalizeContactEmail(v.Recipient)
	if err != nil || v.ID.IsZero() || v.TenantID.IsZero() || !v.Role.Valid() || !identityDigestPattern.MatchString(in.CodeDigest) || in.Actor == "" || v.ExpiresAt.IsZero() || v.CreatedAt.IsZero() || !v.ExpiresAt.After(v.CreatedAt) || v.ExpiresAt.Sub(v.CreatedAt) > 7*24*time.Hour {
		return fmt.Errorf("%w: invalid invitation", shared.ErrValidation)
	}
	return s.withIdentityTenant(ctx, v.TenantID, func(tx pgx.Tx) error {
		if err := lockIdentityAdministration(ctx, tx, v.TenantID); err != nil {
			return err
		}
		if err := identityAdmin(ctx, tx, v.TenantID, proof); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO identity_invitations(tenant_id,id,code_digest,recipient,role,state,created_by,expires_at,created_at,updated_at,version) VALUES($1,$2,$3,$4,$5,'pending',$6,$7,$8,$8,1)`, v.TenantID.String(), v.ID.String(), in.CodeDigest, recipient, string(v.Role), in.Actor, v.ExpiresAt.UTC(), v.CreatedAt.UTC())
		if err != nil {
			return err
		}
		return appendTenantAudit(ctx, tx, v.TenantID.String(), ports.AuditEntry{Actor: in.Actor, Action: "identity.invitation_created", Target: v.ID.String(), At: v.CreatedAt, Metadata: map[string]string{"role": string(v.Role)}})
	})
}

func (s *IdentityFoundationStore) ListIdentityInvitations(ctx context.Context, tenant shared.ID, limit int) ([]ports.IdentityInvitation, error) {
	if tenant.IsZero() || limit < 1 || limit > 100 {
		return nil, fmt.Errorf("%w: invitation list limit", shared.ErrValidation)
	}
	out := []ports.IdentityInvitation{}
	err := s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id,recipient,role,state,version,expires_at,created_at,COALESCE(accepted_membership_id,''),COALESCE(accepted_person_id,'') FROM identity_invitations WHERE tenant_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2`, tenant.String(), limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var v ports.IdentityInvitation
			var id, role, state, m, p string
			if e = rows.Scan(&id, &v.Recipient, &role, &state, &v.Version, &v.ExpiresAt, &v.CreatedAt, &m, &p); e != nil {
				return e
			}
			v.ID, v.TenantID, v.Role, v.State, v.AcceptedMembershipID, v.AcceptedPersonID = shared.ID(id), tenant, user.Role(role), state, shared.ID(m), shared.ID(p)
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, err
}

func (s *IdentityFoundationStore) RevokeIdentityInvitation(ctx context.Context, tenant, id shared.ID, version int, proof ports.IdentityAdminProof, now time.Time) error {
	if tenant.IsZero() || id.IsZero() || version < 1 || now.IsZero() {
		return shared.ErrValidation
	}
	return s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		if e := lockIdentityAdministration(ctx, tx, tenant); e != nil {
			return e
		}
		if e := identityAdmin(ctx, tx, tenant, proof); e != nil {
			return e
		}
		ct, e := tx.Exec(ctx, `UPDATE identity_invitations SET state='revoked',version=version+1,updated_at=$4 WHERE tenant_id=$1 AND id=$2 AND version=$3 AND state='pending'`, tenant.String(), id.String(), version, now.UTC())
		if e != nil {
			return e
		}
		if ct.RowsAffected() != 1 {
			return shared.ErrConflict
		}
		return appendTenantAudit(ctx, tx, tenant.String(), ports.AuditEntry{Actor: proof.Principal.ActorID, Action: "identity.invitation_revoked", Target: id.String(), At: now})
	})
}

func (s *IdentityFoundationStore) GetIdentityInvitation(ctx context.Context, tenant, id shared.ID) (out ports.IdentityInvitation, err error) {
	err = s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		var rid, role, state, m, p string
		err := tx.QueryRow(ctx, `SELECT id,recipient,role,state,version,expires_at,created_at,COALESCE(accepted_membership_id,''),COALESCE(accepted_person_id,'') FROM identity_invitations WHERE tenant_id=$1 AND id=$2`, tenant.String(), id.String()).Scan(&rid, &out.Recipient, &role, &state, &out.Version, &out.ExpiresAt, &out.CreatedAt, &m, &p)
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return err
		}
		out.ID, out.TenantID, out.Role, out.State, out.AcceptedMembershipID, out.AcceptedPersonID = shared.ID(rid), tenant, user.Role(role), state, shared.ID(m), shared.ID(p)
		return nil
	})
	return out, err
}

func (s *IdentityFoundationStore) ResolveIdentityInvitationCode(ctx context.Context, digest string) (out ports.IdentityInvitationRoute, err error) {
	if !identityDigestPattern.MatchString(digest) {
		return out, shared.ErrNotFound
	}
	var tenant, invitation string
	err = s.pool.QueryRow(ctx, `SELECT tenant_id,invitation_id FROM synapse_identity_invitation_tenant($1)`, digest).Scan(&tenant, &invitation)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, shared.ErrNotFound
	}
	if err != nil {
		return out, err
	}
	return ports.IdentityInvitationRoute{TenantID: shared.ID(tenant), InvitationID: shared.ID(invitation)}, nil
}

func (s *IdentityFoundationStore) CreateMailboxChallenge(ctx context.Context, tenant, invitation shared.ID, version int, subject string, person shared.ID, digest string, expires, now time.Time) error {
	if tenant.IsZero() || invitation.IsZero() || person.IsZero() || version < 1 || strings.TrimSpace(subject) == "" || !identityDigestPattern.MatchString(digest) || expires.IsZero() || now.IsZero() || !expires.After(now) {
		return shared.ErrValidation
	}
	return s.withIdentityTenant(ctx, tenant, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `INSERT INTO identity_invitation_challenges(tenant_id,invitation_id,invitation_version,subject,prospective_person_id,challenge_digest,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7 WHERE EXISTS(SELECT 1 FROM identity_invitations WHERE tenant_id=$1 AND id=$2 AND version=$3 AND state='pending' AND expires_at>$8)`, tenant.String(), invitation.String(), version, subject, person.String(), digest, expires, now)
		if err != nil {
			return err
		}
		if ct.RowsAffected() != 1 {
			return shared.ErrForbidden
		}
		return nil
	})
}

// AdmitIdentity locks every binding used to grant authority. Login only follows an existing
// approved authenticator; link is additive and refuses a subject already assigned elsewhere.
func (s *IdentityFoundationStore) AdmitIdentity(ctx context.Context, c ports.IdentityAdmissionCommand) (out ports.IdentityAdmissionResult, err error) {
	if c.TenantID.IsZero() || c.ConnectionID.IsZero() || c.ConnectionRevision < 1 || strings.TrimSpace(c.Subject) == "" || c.Now.IsZero() || c.Actor == "" {
		return out, fmt.Errorf("%w: invalid identity admission", shared.ErrValidation)
	}
	payloadCommand := c
	payloadCommand.Now = time.Time{}
	payloadBytes, e := json.Marshal(payloadCommand)
	if e != nil {
		return out, e
	}
	payloadSum := sha256.Sum256(payloadBytes)
	payloadHash := hex.EncodeToString(payloadSum[:])
	err = s.withIdentityTenant(ctx, c.TenantID, func(tx pgx.Tx) error {
		if c.Purpose == ports.IdentityAuthorizationInvitation {
			var acceptedID, acceptedHash *string
			if e := tx.QueryRow(ctx, `SELECT accepted_session_id,accepted_payload_hash FROM identity_invitations WHERE tenant_id=$1 AND id=$2 AND state='accepted'`, c.TenantID.String(), c.InvitationID.String()).Scan(&acceptedID, &acceptedHash); e == nil {
				if acceptedID == nil || acceptedHash == nil || *acceptedID != c.Issue.Session.ID.String() || *acceptedHash != payloadHash {
					return shared.ErrConflict
				}
				if _, e = lockOrganizationPolicy(ctx, tx, c.TenantID); e != nil {
					return e
				}
				var role string
				out.Session, role, e = scanEnterpriseSession(tx.QueryRow(ctx, `SELECT s.id,s.tenant_id,s.credential_id,s.membership_id,s.person_id,COALESCE(s.connection_id,''),s.kind,s.lineage_id,COALESCE(s.rotated_from_session_id,''),s.authenticated_at,s.origin_at,s.expires_at,s.person_epoch,s.membership_epoch,COALESCE(s.connection_epoch,0),s.csrf_token_hash,s.revoked_at,s.created_at,m.role FROM identity_sessions s JOIN identity_memberships m ON m.tenant_id=s.tenant_id AND m.id=s.membership_id JOIN identity_credentials x ON x.tenant_id=s.tenant_id AND x.id=s.credential_id AND x.state='active' AND x.digest=$3 WHERE s.tenant_id=$1 AND s.id=$2 AND s.revoked_at IS NULL AND s.expires_at>$4 FOR UPDATE OF s,m,x`, c.TenantID.String(), *acceptedID, c.Issue.CredentialDigest, c.Now))
				if e != nil {
					return switchRetryError(e)
				}
				if e = validateLockedSessionFences(ctx, tx, c.TenantID, c.Issue.CredentialDigest, lockedEnterpriseSession{ID: out.Session.ID.String(), CredentialID: out.Session.CredentialID.String(), MembershipID: out.Session.MembershipID.String(), PersonID: out.Session.PersonID.String(), ConnectionID: out.Session.ConnectionID.String(), Kind: out.Session.Kind, LineageID: out.Session.LineageID.String(), AuthenticatedAt: out.Session.AuthenticatedAt, OriginAt: out.Session.OriginAt, PersonEpoch: out.Session.PersonEpoch, MembershipEpoch: out.Session.MembershipEpoch, ConnectionEpoch: out.Session.ConnectionEpoch}, c.Now); e != nil {
					return e
				}
				out.Membership, e = scanIdentityMembership(tx.QueryRow(ctx, `SELECT `+identityMembershipCols+` FROM identity_memberships WHERE tenant_id=$1 AND id=$2`, c.TenantID.String(), out.Session.MembershipID.String()))
				if e != nil {
					return e
				}
				out.Membership.Role = user.Role(role)
				out.PersonID = out.Session.PersonID
				return nil
			} else if !errors.Is(e, pgx.ErrNoRows) {
				return e
			}
		}
		admissionCtx := bindTenantTransaction(ctx, c.TenantID, tx)
		var invitationSourceTenant string
		var sourceLineage string
		var sourceOrigin time.Time
		if c.Purpose == ports.IdentityAuthorizationInvitation && !c.ExpectedPersonID.IsZero() {
			if c.SourceSessionID.IsZero() || !identityDigestPattern.MatchString(c.SourceCredentialDigest) {
				return shared.ErrForbidden
			}
			e := tx.QueryRow(ctx, `SELECT source_tenant,lineage_id,origin_at FROM synapse_identity_admission_source($1,$2,$3,$4)`, c.SourceCredentialDigest, c.SourceSessionID.String(), c.ExpectedPersonID.String(), c.Now).Scan(&invitationSourceTenant, &sourceLineage, &sourceOrigin)
			if errors.Is(e, pgx.ErrNoRows) {
				return shared.ErrForbidden
			}
			if e != nil {
				return e
			}
			if invitationSourceTenant == "" {
				return shared.ErrForbidden
			}
		}
		var phase string
		if e := tx.QueryRow(ctx, `SELECT cutover_phase FROM identity_policies WHERE tenant_id=$1 FOR UPDATE`, c.TenantID.String()).Scan(&phase); e != nil {
			return e
		}
		if phase != "declared" {
			return fmt.Errorf("%w: %w", shared.ErrConflict, ports.ErrIdentityNotRepresentable)
		}
		var epoch int64
		var issuer string
		e := tx.QueryRow(ctx, `SELECT epoch,trust_namespace FROM identity_connections x WHERE tenant_id=$1 AND id=$2 AND enabled AND revision=$3 AND COALESCE((SELECT t.state='passed' FROM identity_connection_tests t WHERE t.tenant_id=x.tenant_id AND t.connection_id=x.id AND t.revision=x.revision ORDER BY t.tested_at DESC,t.id DESC LIMIT 1),false) FOR UPDATE`, c.TenantID.String(), c.ConnectionID.String(), c.ConnectionRevision).Scan(&epoch, &issuer)
		if e != nil {
			return shared.ErrForbidden
		}
		var member ports.IdentityMembership
		var sourceCredential string
		switch c.Purpose {
		case ports.IdentityAuthorizationLogin:
			var mid, pid string
			e = tx.QueryRow(ctx, `SELECT a.membership_id,a.person_id FROM identity_authenticators a JOIN identity_memberships m ON m.tenant_id=a.tenant_id AND m.id=a.membership_id AND m.person_id=a.person_id AND m.state='active' WHERE a.tenant_id=$1 AND a.connection_id=$2 AND a.protocol_subject=$3 AND a.state='approved' FOR UPDATE`, c.TenantID.String(), c.ConnectionID.String(), c.Subject).Scan(&mid, &pid)
			if e != nil {
				return shared.ErrForbidden
			}
			member, e = scanIdentityMembership(tx.QueryRow(ctx, `SELECT `+identityMembershipCols+` FROM identity_memberships WHERE tenant_id=$1 AND id=$2 AND person_id=$3 FOR UPDATE`, c.TenantID.String(), mid, pid))
			if e != nil {
				return e
			}
		case ports.IdentityAuthorizationLink, ports.IdentityAuthorizationStepUp:
			if c.ExpectedPersonID.IsZero() || c.SourceSessionID.IsZero() || !identityDigestPattern.MatchString(c.SourceCredentialDigest) {
				return shared.ErrForbidden
			}
			proofAge := 15 * time.Minute
			if c.Purpose == ports.IdentityAuthorizationStepUp {
				proofAge = 12 * time.Hour
			}
			var source lockedEnterpriseSession
			if e = loadLockedEnterpriseSession(ctx, tx, c.TenantID, c.SourceCredentialDigest, c.Now, &source); e != nil || source.ID != c.SourceSessionID.String() || source.Kind != identity.EnterpriseSessionKindBrowser || source.PersonID != c.ExpectedPersonID.String() || !source.AuthenticatedAt.Add(proofAge).After(c.Now) || !source.OriginAt.Add(12*time.Hour).After(c.Now) {
				return shared.ErrForbidden
			}
			if e = validateLockedSessionFences(ctx, tx, c.TenantID, c.SourceCredentialDigest, source, c.Now); e != nil {
				return shared.ErrForbidden
			}
			sourceCredential, sourceLineage, sourceOrigin = source.CredentialID, source.LineageID, source.OriginAt
			member, e = scanIdentityMembership(tx.QueryRow(ctx, `SELECT `+identityMembershipCols+` FROM identity_memberships WHERE tenant_id=$1 AND person_id=$2 AND state='active' FOR UPDATE`, c.TenantID.String(), c.ExpectedPersonID.String()))
			if e != nil {
				return shared.ErrForbidden
			}
			if c.Purpose == ports.IdentityAuthorizationLink {
				_, e = tx.Exec(ctx, `INSERT INTO identity_authenticators(tenant_id,id,connection_id,protocol_subject,membership_id,person_id,state,approved_by,source,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'approved',$7,'native',$8,$8)`, c.TenantID.String(), "auth_"+c.Issue.Session.ID.String(), c.ConnectionID.String(), c.Subject, member.ID.String(), member.PersonID.String(), c.Actor, c.Now)
				if e != nil {
					return e
				}
				if e = appendTenantAudit(ctx, tx, c.TenantID.String(), ports.AuditEntry{Actor: c.Actor, Action: "identity.authenticator_linked", Target: c.ConnectionID.String(), At: c.Now}); e != nil {
					return e
				}
			} else {
				var approved bool
				if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_authenticators WHERE tenant_id=$1 AND connection_id=$2 AND protocol_subject=$3 AND person_id=$4 AND membership_id=$5 AND state='approved')`, c.TenantID.String(), c.ConnectionID.String(), c.Subject, member.PersonID.String(), member.ID.String()).Scan(&approved); e != nil || !approved {
					return shared.ErrForbidden
				}
			}
		case ports.IdentityAuthorizationInvitation:
			if c.InvitationID.IsZero() || c.InvitationVersion < 1 || !identityDigestPattern.MatchString(c.InvitationCodeDigest) {
				return shared.ErrForbidden
			}
			var recipient, role, state, acceptedPerson, acceptedMembership string
			e = tx.QueryRow(ctx, `SELECT recipient,role,state,COALESCE(accepted_person_id,''),COALESCE(accepted_membership_id,'') FROM identity_invitations WHERE tenant_id=$1 AND id=$2 AND version=$3
 AND code_digest=$4 AND expires_at>$5 FOR UPDATE`, c.TenantID.String(), c.InvitationID.String(), c.InvitationVersion, c.InvitationCodeDigest, c.Now).Scan(&recipient, &role, &state, &acceptedPerson, &acceptedMembership)
			if e != nil {
				return shared.ErrForbidden
			}
			if state != "pending" && state != "accepted" {
				return shared.ErrConflict
			}
			person := c.ExpectedPersonID
			if person.IsZero() {
				person = c.NewPersonID
			}
			if state == "accepted" {
				// Exact retries return above before source authentication; a fresh command can
				// never turn a consumed invitation into another credential issuer.
				return shared.ErrConflict
			}
			mailbox, normalizeErr := user.NormalizeContactEmail(c.VerifiedMailbox)
			mailOK := normalizeErr == nil && mailbox == recipient
			if !mailOK {
				if !identityDigestPattern.MatchString(c.ChallengeDigest) || person.IsZero() {
					return shared.ErrForbidden
				}
				ct, challengeErr := tx.Exec(ctx, `UPDATE identity_invitation_challenges SET consumed_at=$6 WHERE tenant_id=$1 AND invitation_id=$2 AND invitation_version=$3
 AND subject=$4 AND prospective_person_id=$5 AND challenge_digest=$7 AND consumed_at IS NULL AND expires_at>$6`, c.TenantID.String(), c.InvitationID.String(), c.InvitationVersion, c.Subject, person.String(), c.Now, c.ChallengeDigest)
				if challengeErr != nil {
					return fmt.Errorf("consume invitation mailbox proof: %w", challengeErr)
				}
				if ct.RowsAffected() != 1 {
					return shared.ErrForbidden
				}
			}
			if c.ExpectedPersonID.IsZero() {
				if c.NewPersonID.IsZero() {
					return shared.ErrForbidden
				}
				if e = createLegacyPerson(ctx, tx, c.NewPersonID, "invitation acceptance"); e != nil {
					return e
				}
				person = c.NewPersonID
			}
			member, e = scanIdentityMembership(tx.QueryRow(ctx, `SELECT `+identityMembershipCols+` FROM identity_memberships WHERE tenant_id=$1 AND person_id=$2 FOR UPDATE`, c.TenantID.String(), person.String()))
			if errors.Is(e, pgx.ErrNoRows) {
				member, e = s.AddMembership(admissionCtx, c.TenantID, person, c.DisplayName, user.Role(role), c.Actor, c.Now)
				if e != nil {
					return e
				}
			} else if e != nil {
				return e
			} else if member.State != ports.IdentityMembershipActive {
				return shared.ErrForbidden
			}
			// The proven invitation recipient is also a contact for this explicit membership.
			// Importing it never locates or merges a person and shares the acceptance transaction.
			contactID := legacyIdentityID("contact_oidc_", c.TenantID, shared.ID(member.ID.String()+":"+c.ConnectionID.String()))
			if mailOK {
				if e = NewUserContactStore(s.pool).ImportOIDCEmail(admissionCtx, c.TenantID, member.LegacyUserID, contactID, issuer, recipient, c.Now); e != nil {
					return e
				}
			} else {
				contactID = legacyIdentityID("contact_mailbox_", c.TenantID, member.ID)
				if e = tx.QueryRow(ctx, `INSERT INTO user_contacts(tenant_id,id,user_id,kind,source,value,verified_at,created_at,updated_at) VALUES($1,$2,$3,'email','manual',$4,$5,$5,$5) ON CONFLICT(tenant_id,user_id,kind,value) WHERE source='manual' DO UPDATE SET verified_at=EXCLUDED.verified_at,updated_at=EXCLUDED.updated_at RETURNING id`, c.TenantID.String(), contactID.String(), member.LegacyUserID.String(), recipient, c.Now).Scan(&contactID); e != nil {
					return e
				}
				if e = appendTenantAudit(ctx, tx, c.TenantID.String(), ports.AuditEntry{Actor: c.Actor, Action: "user_contact.verified", Target: contactID.String(), At: c.Now, Metadata: map[string]string{"proof_source": "invitation_mailbox_challenge"}}); e != nil {
					return e
				}
			}
			_, e = tx.Exec(ctx, `INSERT INTO identity_authenticators(tenant_id,id,connection_id,protocol_subject,membership_id,person_id,state,approved_by,source,created_at,updated_at)
 VALUES($1,$2,$3,$4,$5,$6,'approved',$7,'native',$8,$8)`, c.TenantID.String(), "auth_"+c.Issue.Session.ID.String(), c.ConnectionID.String(), c.Subject, member.ID.String(), person.String(), c.Actor, c.Now)
			if e != nil {
				return e
			}
			ct, e := tx.Exec(ctx, `UPDATE identity_invitations SET state='accepted',accepted_membership_id=$4,accepted_person_id=$5,updated_at=$6
 WHERE tenant_id=$1 AND id=$2 AND version=$3 AND state='pending'`, c.TenantID.String(), c.InvitationID.String(), c.InvitationVersion, member.ID.String(), person.String(), c.Now)
			if e != nil {
				return e
			}
			if ct.RowsAffected() != 1 {
				return shared.ErrConflict
			}
			if e = appendTenantAudit(ctx, tx, c.TenantID.String(), ports.AuditEntry{Actor: c.Actor, Action: "identity.invitation_accepted", Target: c.InvitationID.String(), At: c.Now}); e != nil {
				return e
			}
		default:
			return fmt.Errorf("%w: admission purpose %s requires invitation handler", shared.ErrValidation, c.Purpose)
		}
		v := c.Issue.Session
		v.TenantID, v.MembershipID, v.PersonID, v.ConnectionID, v.ConnectionEpoch, v.MembershipEpoch = c.TenantID, member.ID, member.PersonID, c.ConnectionID, epoch, member.Epoch
		c.Issue.Session = v
		if c.Purpose == ports.IdentityAuthorizationLink || c.Purpose == ports.IdentityAuthorizationStepUp {
			c.Issue.Session.LineageID = shared.ID(sourceLineage)
			c.Issue.Session.OriginAt = sourceOrigin
			c.Issue.Session.RotatedFromSessionID = c.SourceSessionID
		}
		if c.Purpose == ports.IdentityAuthorizationInvitation && !c.ExpectedPersonID.IsZero() {
			c.Issue.Session.LineageID = shared.ID(sourceLineage)
			c.Issue.Session.OriginAt = sourceOrigin
			if invitationSourceTenant == c.TenantID.String() {
				c.Issue.Session.RotatedFromSessionID = c.SourceSessionID
			} else {
				c.Issue.Session.RotatedFromSessionID = ""
			}
		}
		if cap := c.Issue.Session.OriginAt.Add(identity.MaxSessionAge); cap.Before(c.Issue.Session.ExpiresAt) {
			c.Issue.Session.ExpiresAt = cap
		}
		if e = insertAdmissionSession(ctx, tx, &c.Issue, c.Actor, c.Now); e != nil {
			return e
		}
		if c.Purpose == ports.IdentityAuthorizationInvitation {
			if _, e = tx.Exec(ctx, `UPDATE identity_invitations SET accepted_session_id=$3,accepted_payload_hash=$4 WHERE tenant_id=$1 AND id=$2 AND state='accepted' AND accepted_session_id IS NULL`, c.TenantID.String(), c.InvitationID.String(), c.Issue.Session.ID.String(), payloadHash); e != nil {
				return e
			}
		}
		if c.Purpose == ports.IdentityAuthorizationLink || c.Purpose == ports.IdentityAuthorizationStepUp {
			if _, e = tx.Exec(ctx, `UPDATE identity_sessions SET revoked_at=$3 WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL`, c.TenantID.String(), c.SourceSessionID.String(), c.Now); e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, `UPDATE identity_credentials SET state='revoked',revoked_at=$3,updated_at=$3 WHERE tenant_id=$1 AND id=$2 AND state='active'`, c.TenantID.String(), sourceCredential, c.Now); e != nil {
				return e
			}
		}
		if c.Purpose == ports.IdentityAuthorizationInvitation && !c.ExpectedPersonID.IsZero() {
			var revoked bool
			if e = tx.QueryRow(ctx, `SELECT synapse_identity_revoke_admission_source($1,$2,$3,$4)`, c.SourceCredentialDigest, c.SourceSessionID.String(), c.ExpectedPersonID.String(), c.Now).Scan(&revoked); e != nil || !revoked {
				return shared.ErrForbidden
			}
		}
		out = ports.IdentityAdmissionResult{Session: c.Issue.Session, Membership: member, PersonID: member.PersonID}
		return nil
	})
	return out, err
}

func insertAdmissionSession(ctx context.Context, tx pgx.Tx, issue *ports.IdentitySessionIssue, actor string, now time.Time) error {
	v := issue.Session
	if _, err := tx.Exec(ctx, `INSERT INTO identity_credentials(tenant_id,id,kind,digest,membership_id,person_id,source,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'native','active',$7,$7)`, v.TenantID.String(), v.CredentialID.String(), v.Kind, issue.CredentialDigest, v.MembershipID.String(), v.PersonID.String(), now); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT synapse_identity_lock_person_epoch($1,$2)`, issue.CredentialDigest, v.PersonID.String()).Scan(&v.PersonEpoch); err != nil {
		return err
	}
	issue.Session = v
	if err := v.Valid(); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO identity_sessions(tenant_id,id,credential_id,membership_id,person_id,connection_id,lineage_id,rotated_from_session_id,authenticated_at,origin_at,expires_at,person_epoch,membership_epoch,connection_epoch,created_at,kind,csrf_token_hash) VALUES($1,$2,$3,$4,$5,NULLIF($6,''),$7,NULLIF($8,''),$9,$10,$11,$12,$13,$14,$15,$16,$17)`, v.TenantID.String(), v.ID.String(), v.CredentialID.String(), v.MembershipID.String(), v.PersonID.String(), v.ConnectionID.String(), v.LineageID.String(), v.RotatedFromSessionID.String(), v.AuthenticatedAt, v.OriginAt, v.ExpiresAt, v.PersonEpoch, v.MembershipEpoch, v.ConnectionEpoch, v.CreatedAt, v.Kind, v.CSRFTokenHash); err != nil {
		return err
	}
	return appendTenantAudit(ctx, tx, v.TenantID.String(), ports.AuditEntry{Actor: actor, Action: "identity.session_created", Target: v.ID.String(), At: now, Metadata: map[string]string{"person_id": v.PersonID.String(), "kind": v.Kind}})
}
