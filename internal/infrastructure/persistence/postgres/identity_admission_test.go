package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestIdentityAdmissionLoginRequiresApprovedAuthenticator(t *testing.T) {
	f := newIdentityFixture(t)
	now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	f.tenants(t, "admission-login")
	f.declare(t, "admission-login")
	person := f.newPerson(t, "admission-login-person")
	membership, err := f.store.AddMembership(context.Background(), "admission-login", person, "Member", user.RoleMember, "platform", now)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionConnection(t, f, "admission-login", membership, "admission-login-connection", "approved-subject", now)
	if _, err = f.store.AdmitIdentity(context.Background(), admissionCommand("admission-login", "admission-login-connection", "unknown-subject", ports.IdentityAuthorizationLogin, now)); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("unknown subject admitted: %v", err)
	}
	result, err := f.store.AdmitIdentity(context.Background(), admissionCommand("admission-login", "admission-login-connection", "approved-subject", ports.IdentityAuthorizationLogin, now))
	if err != nil {
		t.Fatal(err)
	}
	if result.PersonID != person || result.Membership.ID != membership.ID || result.Session.ConnectionEpoch != 1 {
		t.Fatalf("approved session binding = %+v", result)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_sessions WHERE tenant_id='admission-login'`); n != 1 {
		t.Fatalf("sessions = %d, want 1", n)
	}
}

func TestIdentityAdmissionLinkAndStepUpRequireCurrentApprovedSource(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, f *identityFixture, tenant string, source identity.EnterpriseSession)
	}{
		{"revoked source", func(t *testing.T, f *identityFixture, tenant string, source identity.EnterpriseSession) {
			if err := f.runtimeExec(tenant, `UPDATE identity_sessions SET revoked_at=$3 WHERE tenant_id=$1 AND id=$2`, tenant, source.ID.String(), source.CreatedAt.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
		}},
		{"stale membership epoch", func(t *testing.T, f *identityFixture, tenant string, source identity.EnterpriseSession) {
			if err := f.runtimeExec(tenant, `UPDATE identity_memberships SET role='readonly' WHERE tenant_id=$1 AND id=$2`, tenant, source.MembershipID.String()); err != nil {
				t.Fatal(err)
			}
		}},
		{"stale source connection epoch", func(t *testing.T, f *identityFixture, tenant string, source identity.EnterpriseSession) {
			if err := f.runtimeExec(tenant, `UPDATE identity_connections SET enabled=false WHERE tenant_id=$1 AND id=$2`, tenant, source.ConnectionID.String()); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newIdentityFixture(t)
			now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
			tenant := "admission-link-" + identityRandomHex(t, 3)
			f.tenants(t, tenant)
			f.declare(t, tenant)
			person := f.newPerson(t, tenant+"-person")
			membership, err := f.store.AddMembership(context.Background(), shared.ID(tenant), person, "Member", user.RoleMember, "platform", now)
			if err != nil {
				t.Fatal(err)
			}
			seedSessionConnection(t, f, tenant, membership, "admission-source", "source-subject", now)
			if err = f.runtimeExec(tenant, `INSERT INTO identity_connections(tenant_id,id,protocol,trust_namespace,display_name,enabled) VALUES($1,'admission-target','oidc','https://target.example','Target',true)`, tenant); err != nil {
				t.Fatal(err)
			}
			if err = f.runtimeExec(tenant, `INSERT INTO identity_connection_revisions(tenant_id,connection_id,revision,settings,actor,created_at) VALUES($1,'admission-target',1,'{}','test',$2)`, tenant, now); err != nil {
				t.Fatal(err)
			}
			if err = f.runtimeExec(tenant, `INSERT INTO identity_connection_tests(tenant_id,id,connection_id,revision,state,tested_at,expires_at) VALUES($1,'admission-target-test','admission-target',1,'passed',$2,$3)`, tenant, now, now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			sourceDigest := identityDigest("source-" + tenant)
			source := enterpriseSession("admission-source-session", shared.ID(tenant), membership.ID, person, "admission-source", now)
			if err = f.store.CreateEnterpriseSession(context.Background(), ports.IdentitySessionIssue{Session: source, CredentialDigest: sourceDigest}, "actor", now); err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, f, tenant, source)
			command := admissionCommand(shared.ID(tenant), "admission-target", "link-subject", ports.IdentityAuthorizationLink, now)
			command.ExpectedPersonID, command.SourceSessionID, command.SourceCredentialDigest = person, source.ID, sourceDigest
			if _, err = f.store.AdmitIdentity(context.Background(), command); !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("%s admitted: %v", tc.name, err)
			}
		})
	}
}

func TestIdentityAdmissionRejectsStalePersonEpochWithoutMutatingSource(t *testing.T) {
	for _, purpose := range []ports.IdentityAuthorizationPurpose{ports.IdentityAuthorizationLink, ports.IdentityAuthorizationStepUp} {
		t.Run(string(purpose), func(t *testing.T) {
			f := newIdentityFixture(t)
			now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
			tenant := "admission-stale-person-" + identityRandomHex(t, 3)
			f.tenants(t, tenant)
			f.declare(t, tenant)
			person := f.newPerson(t, tenant+"-person")
			membership, err := f.store.AddMembership(context.Background(), shared.ID(tenant), person, "Member", user.RoleMember, "platform", now)
			if err != nil {
				t.Fatal(err)
			}
			seedSessionConnection(t, f, tenant, membership, "admission-stale-source", "source-subject", now)
			seedSessionConnection(t, f, tenant, membership, "admission-stale-target", "target-subject", now)
			sourceDigest := identityDigest("stale-person-source-" + tenant)
			source := enterpriseSession("admission-stale-person-session", shared.ID(tenant), membership.ID, person, "admission-stale-source", now)
			if err = f.store.CreateEnterpriseSession(context.Background(), ports.IdentitySessionIssue{Session: source, CredentialDigest: sourceDigest}, "actor", now); err != nil {
				t.Fatal(err)
			}
			if _, err = f.platform.ApplyPersonCommand(context.Background(), person, ports.IdentityPersonSessionsRevoked, "platform", "lost device"); err != nil {
				t.Fatal(err)
			}

			command := admissionCommand(shared.ID(tenant), "admission-stale-target", "target-subject", purpose, now)
			command.ExpectedPersonID, command.SourceSessionID, command.SourceCredentialDigest = person, source.ID, sourceDigest
			if _, err = f.store.AdmitIdentity(context.Background(), command); !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("stale person epoch admitted %s: %v", purpose, err)
			}
			if sessions := f.adminCount(t, `SELECT count(*) FROM identity_sessions WHERE tenant_id=$1`, tenant); sessions != 1 {
				t.Fatalf("stale person epoch created or revoked sessions: %d", sessions)
			}
			if active := f.adminCount(t, `SELECT count(*) FROM identity_sessions WHERE tenant_id=$1 AND revoked_at IS NULL`, tenant); active != 1 {
				t.Fatalf("stale person epoch revoked its source session: %d active", active)
			}
			if active := f.adminCount(t, `SELECT count(*) FROM identity_credentials WHERE tenant_id=$1 AND state='active'`, tenant); active != 1 {
				t.Fatalf("stale person epoch changed credentials: %d active", active)
			}
			if authenticators := f.adminCount(t, `SELECT count(*) FROM identity_authenticators WHERE tenant_id=$1`, tenant); authenticators != 2 {
				t.Fatalf("stale person epoch changed authenticators: %d", authenticators)
			}
		})
	}
}

func TestIdentityAdmissionAllowsOptionalSwitchSourceForLinkAndStepUp(t *testing.T) {
	for _, purpose := range []ports.IdentityAuthorizationPurpose{ports.IdentityAuthorizationLink, ports.IdentityAuthorizationStepUp} {
		t.Run(string(purpose), func(t *testing.T) {
			f := newIdentityFixture(t)
			now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
			f.tenants(t, "optional-admission-origin", "optional-admission-destination")
			f.declare(t, "optional-admission-origin")
			f.declare(t, "optional-admission-destination")
			person := f.newPerson(t, "optional-admission-person")
			originMembership, err := f.store.AddMembership(context.Background(), "optional-admission-origin", person, "Origin", user.RoleMember, "platform", now)
			if err != nil {
				t.Fatal(err)
			}
			destinationMembership, err := f.store.AddMembership(context.Background(), "optional-admission-destination", person, "Destination", user.RoleMember, "platform", now)
			if err != nil {
				t.Fatal(err)
			}
			seedSessionConnection(t, f, "optional-admission-origin", originMembership, "optional-admission-origin-connection", "origin-subject", now)
			sourceDigest := identityDigest("optional-admission-origin-" + string(purpose))
			source := enterpriseSession("optional-admission-origin-session-"+string(purpose), "optional-admission-origin", originMembership.ID, person, "optional-admission-origin-connection", now)
			if err = f.store.CreateEnterpriseSession(context.Background(), ports.IdentitySessionIssue{Session: source, CredentialDigest: sourceDigest}, "actor", now); err != nil {
				t.Fatal(err)
			}
			replacement := enterpriseSession("optional-admission-destination-session-"+string(purpose), "optional-admission-destination", destinationMembership.ID, person, "", now)
			replacement.CredentialID, replacement.ConnectionEpoch = shared.ID("optional-admission-destination-credential-"+string(purpose)), 0
			switched, err := f.store.SwitchEnterpriseSession(context.Background(), ports.IdentitySessionSwitch{
				SourceCredentialDigest:  sourceDigest,
				DestinationTenantID:     "optional-admission-destination",
				DestinationMembershipID: destinationMembership.ID,
				Replacement:             ports.IdentitySessionIssue{Session: replacement, CredentialDigest: identityDigest("optional-admission-destination-" + string(purpose))},
				RetryKey:                "optional-admission-retry-" + string(purpose),
				RetryPayloadHash:        identityDigest("optional-admission-payload-" + string(purpose)),
				RetryCiphertext:         "ciphertext",
				Now:                     now,
			}, "actor")
			if err != nil {
				t.Fatal(err)
			}
			if !switched.Session.ConnectionID.IsZero() || switched.Session.ConnectionEpoch != 0 {
				t.Fatalf("switch did not create optional source: %+v", switched.Session)
			}
			seedSessionConnection(t, f, "optional-admission-destination", destinationMembership, "optional-admission-target", "target-subject", now)
			targetSubject := "target-subject"
			if purpose == ports.IdentityAuthorizationLink {
				targetSubject = "linked-subject"
			}
			command := admissionCommand("optional-admission-destination", "optional-admission-target", targetSubject, purpose, now)
			command.ExpectedPersonID, command.SourceSessionID = person, switched.Session.ID
			command.SourceCredentialDigest = identityDigest("optional-admission-destination-" + string(purpose))
			result, err := f.store.AdmitIdentity(context.Background(), command)
			if err != nil {
				t.Fatalf("optional switch source did not admit %s: %v", purpose, err)
			}
			if result.Session.RotatedFromSessionID != switched.Session.ID || result.Session.PersonID != person {
				t.Fatalf("optional source %s result = %+v", purpose, result)
			}
		})
	}
}

func TestIdentityAdmissionStepUpRequiresApprovedAuthenticatorForSamePerson(t *testing.T) {
	f := newIdentityFixture(t)
	now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	f.tenants(t, "admission-step-up")
	f.declare(t, "admission-step-up")
	person := f.newPerson(t, "admission-step-up-person")
	membership, err := f.store.AddMembership(context.Background(), "admission-step-up", person, "Member", user.RoleMember, "platform", now)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionConnection(t, f, "admission-step-up", membership, "admission-step-up-connection", "approved-step-up", now)
	sourceDigest := identityDigest("admission-step-up-source")
	source := enterpriseSession("admission-step-up-source-session", "admission-step-up", membership.ID, person, "admission-step-up-connection", now)
	if err = f.store.CreateEnterpriseSession(context.Background(), ports.IdentitySessionIssue{Session: source, CredentialDigest: sourceDigest}, "actor", now); err != nil {
		t.Fatal(err)
	}
	command := admissionCommand("admission-step-up", "admission-step-up-connection", "unapproved-step-up", ports.IdentityAuthorizationStepUp, now)
	command.ExpectedPersonID, command.SourceSessionID, command.SourceCredentialDigest = person, source.ID, sourceDigest
	if _, err = f.store.AdmitIdentity(context.Background(), command); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("unapproved step-up admitted: %v", err)
	}
	command.Subject = "approved-step-up"
	result, err := f.store.AdmitIdentity(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if result.PersonID != person || result.Session.RotatedFromSessionID != source.ID {
		t.Fatalf("step-up result = %+v", result)
	}
}

func TestIdentityAdmissionInvitationProofsAndConcurrentAcceptance(t *testing.T) {
	t.Run("normalized verified mailbox", func(t *testing.T) {
		f, tenant, now, invitation := admissionInvitation(t, "invite-mailbox", "member@example.com")
		command := admissionInvitationCommand(tenant, "invite-mailbox-connection", invitation, "mailbox-subject", "member@Example.COM", "invite-mailbox-person", now)
		result, err := f.store.AdmitIdentity(context.Background(), command)
		if err != nil {
			t.Fatal(err)
		}
		if result.PersonID != "invite-mailbox-person" || f.adminCount(t, `SELECT count(*) FROM identity_invitations WHERE tenant_id=$1 AND state='accepted'`, tenant) != 1 {
			t.Fatalf("normalized mailbox admission = %+v", result)
		}
	})

	for _, name := range []string{"wrong proof", "revoked", "expired"} {
		t.Run(name, func(t *testing.T) {
			f, tenant, now, invitation := admissionInvitation(t, "invite-"+identityRandomHex(t, 3), "member@example.com")
			challenge := identityDigest("challenge-" + name)
			person := shared.ID("invite-person-" + identityRandomHex(t, 3))
			if err := f.store.CreateMailboxChallenge(context.Background(), tenant, invitation.ID, invitation.Version, "challenge-subject", person, challenge, now.Add(time.Hour), now); err != nil {
				t.Fatal(err)
			}
			if name == "revoked" {
				if err := f.runtimeExec(tenant.String(), `UPDATE identity_invitations SET state='revoked' WHERE tenant_id=$1 AND id=$2`, tenant.String(), invitation.ID.String()); err != nil {
					t.Fatal(err)
				}
			}
			command := admissionInvitationCommand(tenant, shared.ID("invite-"+tenant.String()+"-connection"), invitation, "challenge-subject", "wrong@example.com", person, now)
			command.ChallengeDigest = challenge
			if name == "wrong proof" {
				command.ChallengeDigest = identityDigest("wrong")
			}
			if name == "expired" {
				command.Now = now.Add(2 * time.Hour)
			}
			if _, err := f.store.AdmitIdentity(context.Background(), command); !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("%s invitation admitted: %v", name, err)
			}
			if n := f.adminCount(t, `SELECT count(*) FROM identity_memberships WHERE tenant_id=$1`, tenant); n != 0 {
				t.Fatalf("%s created %d memberships", name, n)
			}
		})
	}

	t.Run("concurrent acceptors create one membership person and audit", func(t *testing.T) {
		f, tenant, now, invitation := admissionInvitation(t, "invite-race", "member@example.com")
		commands := []ports.IdentityAdmissionCommand{
			admissionInvitationCommand(tenant, "invite-race-connection", invitation, "race-subject-a", "member@example.com", "invite-race-person-a", now),
			admissionInvitationCommand(tenant, "invite-race-connection", invitation, "race-subject-b", "member@example.com", "invite-race-person-b", now),
		}
		var wg sync.WaitGroup
		errs := make([]error, len(commands))
		for i := range commands {
			wg.Add(1)
			go func(i int) { defer wg.Done(); _, errs[i] = f.store.AdmitIdentity(context.Background(), commands[i]) }(i)
		}
		wg.Wait()
		wins := 0
		for _, err := range errs {
			if err == nil {
				wins++
			} else if !errors.Is(err, shared.ErrForbidden) && !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("concurrent admission error = %v", err)
			}
		}
		if wins != 1 || f.adminCount(t, `SELECT count(*) FROM identity_invitations WHERE tenant_id=$1 AND state='accepted'`, tenant) != 1 || f.adminCount(t, `SELECT count(*) FROM identity_memberships WHERE tenant_id=$1`, tenant) != 1 || f.adminCount(t, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='identity.invitation_accepted'`, tenant) != 1 {
			t.Fatalf("race wins=%d invitation=%d memberships=%d audits=%d", wins, f.adminCount(t, `SELECT count(*) FROM identity_invitations WHERE tenant_id=$1 AND state='accepted'`, tenant), f.adminCount(t, `SELECT count(*) FROM identity_memberships WHERE tenant_id=$1`, tenant), f.adminCount(t, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='identity.invitation_accepted'`, tenant))
		}
	})
}

func TestIdentityInvitationExactCodeRouteAndChallengeRefusesInactiveInvitation(t *testing.T) {
	f, tenant, now, invitation := admissionInvitation(t, "invite-route", "member@example.com")
	route, err := f.store.ResolveIdentityInvitationCode(context.Background(), identityDigest("invitation-invite-route"))
	if err != nil || route.TenantID != tenant || route.InvitationID != invitation.ID {
		t.Fatalf("exact invitation route = %+v, %v", route, err)
	}
	if _, err = f.store.ResolveIdentityInvitationCode(context.Background(), identityDigest("unknown-invitation")); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown invitation route = %v", err)
	}
	if err = f.runtimeExec(tenant.String(), `UPDATE identity_invitations SET state='revoked' WHERE tenant_id=$1 AND id=$2`, tenant.String(), invitation.ID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.ResolveIdentityInvitationCode(context.Background(), identityDigest("invitation-invite-route")); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("revoked invitation route = %v", err)
	}
	if err = f.store.CreateMailboxChallenge(context.Background(), tenant, invitation.ID, invitation.Version, "subject", "person", identityDigest("challenge"), now.Add(time.Minute), now); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("inactive invitation created a challenge: %v", err)
	}
}

func TestIdentityInvitationAcceptanceRetriesOnlyForSamePersonSubjectAndCode(t *testing.T) {
	f, tenant, now, invitation := admissionInvitation(t, "invite-idempotent", "member@example.com")
	first := admissionInvitationCommand(tenant, "invite-idempotent-connection", invitation, "subject", "member@example.com", "invite-idempotent-person", now)
	if _, err := f.store.AdmitIdentity(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	retry := first
	retry.Now = now.Add(time.Second)
	if _, err := f.store.AdmitIdentity(context.Background(), retry); err != nil {
		t.Fatalf("same invitation retry: %v", err)
	}
	changed := retry
	changed.Issue.Session.ID = "changed-session"
	changed.Issue.CredentialDigest = identityDigest("changed-token")
	if _, err := f.store.AdmitIdentity(context.Background(), changed); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("changed payload retry=%v", err)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_sessions WHERE tenant_id=$1`, tenant); n != 1 {
		t.Fatalf("retry created %d sessions", n)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='identity.session_created'`, tenant); n != 1 {
		t.Fatalf("retry created %d session audits", n)
	}
	wrongPerson := retry
	wrongPerson.NewPersonID = "another-person"
	wrongPerson.Issue.Session.ID, wrongPerson.Issue.Session.CredentialID = "wrong-person-session", "wrong-person-credential"
	if _, err := f.store.AdmitIdentity(context.Background(), wrongPerson); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("different person retry: %v", err)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_memberships WHERE tenant_id=$1`, tenant); n != 1 {
		t.Fatalf("memberships after retry = %d", n)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='identity.invitation_accepted'`, tenant); n != 1 {
		t.Fatalf("acceptance audits after retry = %d", n)
	}
}

func TestIdentityInvitationExistingPersonCrossTenantSourceIsFencedAndRotated(t *testing.T) {
	f := newIdentityFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	f.tenants(t, "invite-source", "invite-destination")
	f.declare(t, "invite-source")
	f.declare(t, "invite-destination")
	person := f.newPerson(t, "invite-cross-person")
	sourceMember, err := f.store.AddMembership(context.Background(), "invite-source", person, "Source", user.RoleMember, "platform", now)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionConnection(t, f, "invite-source", sourceMember, "invite-source-connection", "source-subject", now)
	sourceDigest := identityDigest("invite-cross-source")
	source := enterpriseSession("invite-cross-source-session", "invite-source", sourceMember.ID, person, "invite-source-connection", now)
	if err = f.store.CreateEnterpriseSession(context.Background(), ports.IdentitySessionIssue{Session: source, CredentialDigest: sourceDigest}, "actor", now); err != nil {
		t.Fatal(err)
	}
	if err = f.runtimeExec("invite-destination", `INSERT INTO identity_connections(tenant_id,id,protocol,trust_namespace,display_name,enabled) VALUES('invite-destination','invite-destination-connection','oidc','https://destination.example','Destination',true)`); err != nil {
		t.Fatal(err)
	}
	if err = f.runtimeExec("invite-destination", `INSERT INTO identity_connection_revisions(tenant_id,connection_id,revision,settings,actor,created_at) VALUES('invite-destination','invite-destination-connection',1,'{}','test',$1)`, now); err != nil {
		t.Fatal(err)
	}
	if err = f.runtimeExec("invite-destination", `INSERT INTO identity_connection_tests(tenant_id,id,connection_id,revision,state,tested_at,expires_at) VALUES('invite-destination','invite-destination-test','invite-destination-connection',1,'passed',$1,$2)`, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	invitation := ports.IdentityInvitation{ID: "invite-cross", TenantID: "invite-destination", Recipient: "member@example.com", Role: user.RoleMember, State: "pending", Version: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err = f.store.CreateIdentityInvitation(context.Background(), ports.IdentityInvitationCreate{Invitation: invitation, CodeDigest: identityDigest("invite-cross-code"), Actor: "bootstrap"}, bootstrapConnectionProof("invite-destination", now)); err != nil {
		t.Fatal(err)
	}
	command := admissionCommand("invite-destination", "invite-destination-connection", "destination-subject", ports.IdentityAuthorizationInvitation, now)
	command.InvitationID, command.InvitationVersion, command.InvitationCodeDigest = invitation.ID, invitation.Version, identityDigest("invite-cross-code")
	command.VerifiedMailbox, command.ExpectedPersonID, command.SourceSessionID, command.SourceCredentialDigest, command.DisplayName = "member@example.com", person, source.ID, sourceDigest, "Destination"
	result, err := f.store.AdmitIdentity(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if result.PersonID != person || result.Session.LineageID != source.LineageID || !result.Session.RotatedFromSessionID.IsZero() {
		t.Fatalf("cross-tenant invitation result = %+v", result)
	}
	if _, err = f.store.AuthenticateEnterpriseSession(context.Background(), sourceDigest, now); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("source session remained active: %v", err)
	}
}

func admissionInvitation(t *testing.T, suffix, recipient string) (*identityFixture, shared.ID, time.Time, ports.IdentityInvitation) {
	t.Helper()
	f := newIdentityFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	tenant := shared.ID(suffix)
	f.tenants(t, tenant.String())
	f.declare(t, tenant.String())
	connection := suffix + "-connection"
	if err := f.runtimeExec(tenant.String(), `INSERT INTO identity_connections(tenant_id,id,protocol,trust_namespace,display_name,enabled) VALUES($1,$2,'oidc',$3,'Invitation',true)`, tenant.String(), connection, "https://"+connection+".example"); err != nil {
		t.Fatal(err)
	}
	if err := f.runtimeExec(tenant.String(), `INSERT INTO identity_connection_revisions(tenant_id,connection_id,revision,settings,actor,created_at) VALUES($1,$2,1,'{}','test',$3)`, tenant.String(), connection, now); err != nil {
		t.Fatal(err)
	}
	if err := f.runtimeExec(tenant.String(), `INSERT INTO identity_connection_tests(tenant_id,id,connection_id,revision,state,tested_at,expires_at) VALUES($1,$2,$3,1,'passed',$4,$5)`, tenant.String(), suffix+"-connection-test", connection, now, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	invitation := ports.IdentityInvitation{ID: shared.ID(suffix + "-invitation"), TenantID: tenant, Recipient: recipient, Role: user.RoleMember, State: "pending", Version: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := f.store.CreateIdentityInvitation(context.Background(), ports.IdentityInvitationCreate{Invitation: invitation, CodeDigest: identityDigest("invitation-" + suffix), Actor: "bootstrap"}, bootstrapConnectionProof(tenant.String(), now)); err != nil {
		t.Fatal(err)
	}
	return f, tenant, now, invitation
}

func admissionInvitationCommand(tenant, connection shared.ID, invitation ports.IdentityInvitation, subject, mailbox string, person shared.ID, now time.Time) ports.IdentityAdmissionCommand {
	command := admissionCommand(tenant, connection, subject, ports.IdentityAuthorizationInvitation, now)
	command.InvitationID, command.InvitationVersion, command.InvitationCodeDigest = invitation.ID, invitation.Version, identityDigest("invitation-"+tenant.String())
	command.VerifiedMailbox, command.NewPersonID, command.DisplayName = mailbox, person, "Invited"
	return command
}

func admissionCommand(tenant, connection shared.ID, subject string, purpose ports.IdentityAuthorizationPurpose, now time.Time) ports.IdentityAdmissionCommand {
	id := shared.ID("session-" + subject)
	return ports.IdentityAdmissionCommand{Purpose: purpose, TenantID: tenant, ConnectionID: connection, ConnectionRevision: 1, Subject: subject, AuthenticatedAt: now, Actor: "identity-callback", Now: now, Issue: ports.IdentitySessionIssue{CredentialDigest: identityDigest("credential-" + subject + "-" + now.String()), Session: identity.EnterpriseSession{ID: id, CredentialID: shared.ID("credential-" + id.String()), Kind: identity.EnterpriseSessionKindBrowser, LineageID: shared.ID("lineage-" + id.String()), AuthenticatedAt: now, OriginAt: now, ExpiresAt: now.Add(time.Hour), CSRFTokenHash: identityDigest("csrf-" + id.String()), CreatedAt: now}}}
}
