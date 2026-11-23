package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// This fixture models an invited person who already holds a membership and an
// independent source session. Mailbox proof is therefore the only recipient proof
// available to the invitation, which is the path used when an OIDC provider does
// not assert email_verified.
type mailboxAdmissionFixture struct {
	f            *identityFixture
	tenant       shared.ID
	now          time.Time
	invitation   ports.IdentityInvitation
	membership   ports.IdentityMembership
	sourceDigest string
	sourceID     shared.ID
	command      ports.IdentityAdmissionCommand
}

type manualContactSnapshot struct {
	id         string
	value      string
	verifiedAt time.Time
	createdAt  time.Time
	updatedAt  time.Time
	version    int
}

type mailboxAdmissionCounts struct {
	contacts         int
	authenticators   int
	sessions         int
	contactAudits    int
	acceptanceAudits int
	sessionAudits    int
}

func TestIdentityAdmissionMailboxChallengePreservesExistingContacts(t *testing.T) {
	t.Run("additive mailbox admission preserves legacy contact", func(t *testing.T) {
		fixture := newMailboxAdmissionFixture(t, "mailbox-contact-collision", "new@example.test")
		legacyID := legacyIdentityID("contact_mailbox_", fixture.tenant, fixture.membership.ID)
		fixture.seedManualContact(t, legacyID, "old@example.test", fixture.now.Add(-time.Minute))
		old := fixture.contact(t, "old@example.test")
		before := fixture.counts(t)
		beforeMembers := fixture.f.adminCount(t, `SELECT count(*) FROM identity_memberships WHERE tenant_id=$1`, fixture.tenant.String())
		beforePeople := fixture.f.adminCount(t, `SELECT count(*) FROM identity_persons`)

		result, err := fixture.f.store.AdmitIdentity(context.Background(), fixture.command)
		if err != nil {
			// The pre-fix failure happens after consuming the mailbox proof in the
			// transaction. Its rollback is part of the safety invariant: a caller
			// can retry only after the storage conflict has been repaired.
			requireSQLState(t, err, "23505")
			fixture.assertPendingAndUnconsumed(t)
			fixture.assertCounts(t, before)
			fixture.assertContact(t, old)
			t.Fatalf("mailbox admission with a legacy membership contact failed: %v", err)
		}
		if result.PersonID != fixture.membership.PersonID || result.Membership.ID != fixture.membership.ID || result.Membership.Role != fixture.membership.Role {
			t.Fatalf("admission changed existing membership: %+v", result)
		}
		if members := fixture.f.adminCount(t, `SELECT count(*) FROM identity_memberships WHERE tenant_id=$1`, fixture.tenant.String()); members != beforeMembers {
			t.Fatalf("admission created memberships: got %d, want %d", members, beforeMembers)
		}
		if people := fixture.f.adminCount(t, `SELECT count(*) FROM identity_persons`); people != beforePeople {
			t.Fatalf("admission created people: got %d, want %d", people, beforePeople)
		}

		fixture.assertContact(t, old)
		newContact := fixture.contact(t, "new@example.test")
		if newContact.id == old.id || newContact.verifiedAt.IsZero() {
			t.Fatalf("new verified mailbox contact = %+v, old = %+v", newContact, old)
		}
		fixture.assertAcceptedAndConsumed(t)
		fixture.assertCounts(t, mailboxAdmissionCounts{
			contacts:         before.contacts + 1,
			authenticators:   before.authenticators + 1,
			sessions:         before.sessions + 1,
			contactAudits:    before.contactAudits + 1,
			acceptanceAudits: before.acceptanceAudits + 1,
			sessionAudits:    before.sessionAudits + 1,
		})
	})

	t.Run("audit failure rolls back contact proof and source", func(t *testing.T) {
		fixture := newMailboxAdmissionFixture(t, "mailbox-contact-audit", "rollback@example.test")
		before := fixture.counts(t)
		fixture.failVerifiedContactAudit(t)

		if _, err := fixture.f.store.AdmitIdentity(context.Background(), fixture.command); err == nil {
			t.Fatal("mailbox admission committed despite user contact audit failure")
		}
		fixture.assertPendingAndUnconsumed(t)
		fixture.assertSourceActive(t)
		fixture.assertContactAbsent(t, "rollback@example.test")
		fixture.assertCounts(t, before)
		fixture.clearVerifiedContactAudit(t)

		if _, err := fixture.f.store.AdmitIdentity(context.Background(), fixture.command); err != nil {
			t.Fatalf("mailbox admission did not retry after audit failure: %v", err)
		}
		fixture.assertAcceptedAndConsumed(t)
		fixture.assertCounts(t, mailboxAdmissionCounts{
			contacts:         before.contacts + 1,
			authenticators:   before.authenticators + 1,
			sessions:         before.sessions + 1,
			contactAudits:    before.contactAudits + 1,
			acceptanceAudits: before.acceptanceAudits + 1,
			sessionAudits:    before.sessionAudits + 1,
		})
	})

	t.Run("existing recipient retains its contact ID for audit", func(t *testing.T) {
		fixture := newMailboxAdmissionFixture(t, "mailbox-contact-existing", "existing@example.test")
		const existingID = "manual-contact-created-before-admission"
		fixture.seedManualContact(t, existingID, "existing@example.test", fixture.now)
		before := fixture.counts(t)

		if _, err := fixture.f.store.AdmitIdentity(context.Background(), fixture.command); err != nil {
			t.Fatalf("admit with existing mailbox contact: %v", err)
		}
		contact := fixture.contact(t, "existing@example.test")
		if contact.id != existingID {
			t.Fatalf("existing recipient got replacement contact ID %q, want %q", contact.id, existingID)
		}
		if n := fixture.f.adminCount(t, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='user_contact.verified' AND target=$2`, fixture.tenant.String(), existingID); n != 1 {
			t.Fatalf("verified contact audit target count = %d, want 1", n)
		}
		fixture.assertCounts(t, mailboxAdmissionCounts{
			contacts:         before.contacts,
			authenticators:   before.authenticators + 1,
			sessions:         before.sessions + 1,
			contactAudits:    before.contactAudits + 1,
			acceptanceAudits: before.acceptanceAudits + 1,
			sessionAudits:    before.sessionAudits + 1,
		})
	})

	t.Run("concurrent first admissions with legacy contact create one effect", func(t *testing.T) {
		fixture := newMailboxAdmissionFixture(t, "mailbox-contact-retry", "retry@example.test")
		fixture.seedManualContact(t, legacyIdentityID("contact_mailbox_", fixture.tenant, fixture.membership.ID), "old@example.test", fixture.now.Add(-time.Minute))
		old := fixture.contact(t, "old@example.test")
		before := fixture.counts(t)

		var group sync.WaitGroup
		results := make([]ports.IdentityAdmissionResult, 2)
		errs := make([]error, 2)
		start := make(chan struct{})
		for i := range results {
			group.Add(1)
			go func(i int) {
				defer group.Done()
				<-start
				results[i], errs[i] = fixture.f.store.AdmitIdentity(context.Background(), fixture.command)
			}(i)
		}
		close(start)
		group.Wait()
		var winner ports.IdentityAdmissionResult
		wins := 0
		for i, err := range errs {
			if err == nil {
				if wins == 0 {
					winner = results[i]
				} else if results[i].Session.ID != winner.Session.ID {
					t.Fatalf("concurrent admissions returned different sessions: %+v %+v", winner.Session, results[i].Session)
				}
				wins++
			} else if !errors.Is(err, shared.ErrForbidden) && !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("concurrent admission %d: %v", i, err)
			}
		}
		if wins == 0 {
			t.Fatalf("concurrent first admissions had no winner: %v", errs)
		}
		retry, err := fixture.f.store.AdmitIdentity(context.Background(), fixture.command)
		if err != nil {
			t.Fatalf("exact retry after concurrent admission: %v", err)
		}
		if retry.Session.ID != winner.Session.ID {
			t.Fatalf("exact retry session=%q, winner=%q", retry.Session.ID, winner.Session.ID)
		}
		fixture.assertContact(t, old)
		fixture.assertAcceptedAndConsumed(t)
		fixture.assertCounts(t, mailboxAdmissionCounts{contacts: before.contacts + 1, authenticators: before.authenticators + 1, sessions: before.sessions + 1, contactAudits: before.contactAudits + 1, acceptanceAudits: before.acceptanceAudits + 1, sessionAudits: before.sessionAudits + 1})
	})
}

func newMailboxAdmissionFixture(t *testing.T, suffix, recipient string) mailboxAdmissionFixture {
	t.Helper()
	f, tenant, now, invitation := admissionInvitation(t, suffix, recipient)
	person := f.newPerson(t, suffix+"-person")
	membership, err := f.store.AddMembership(context.Background(), tenant, person, "Existing", user.RoleMember, "platform", now)
	if err != nil {
		t.Fatal(err)
	}
	sourceConnection := shared.ID(suffix + "-source-connection")
	seedSessionConnection(t, f, tenant.String(), membership, sourceConnection.String(), "source-subject", now)
	sourceDigest := identityDigest(suffix + "-source-credential")
	source := enterpriseSession(suffix+"-source-session", tenant, membership.ID, person, sourceConnection, now)
	if err := f.store.CreateEnterpriseSession(context.Background(), ports.IdentitySessionIssue{Session: source, CredentialDigest: sourceDigest}, "identity-callback", now); err != nil {
		t.Fatal(err)
	}
	command := admissionInvitationCommand(tenant, shared.ID(suffix+"-connection"), invitation, "mailbox-subject", "", person, now)
	command.NewPersonID = ""
	command.ExpectedPersonID = person
	command.SourceSessionID = source.ID
	command.SourceCredentialDigest = sourceDigest
	command.ChallengeDigest = identityDigest(suffix + "-mailbox-code")
	if err := f.store.CreateMailboxChallenge(context.Background(), tenant, invitation.ID, invitation.Version, command.Subject, person, command.ChallengeDigest, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	return mailboxAdmissionFixture{f: f, tenant: tenant, now: now, invitation: invitation, membership: membership, sourceDigest: sourceDigest, sourceID: source.ID, command: command}
}

func (f mailboxAdmissionFixture) seedManualContact(t *testing.T, id shared.ID, value string, at time.Time) {
	t.Helper()
	if err := f.f.runtimeExec(f.tenant.String(), `INSERT INTO user_contacts(tenant_id,id,user_id,kind,source,value,verified_at,version,created_at,updated_at) VALUES($1,$2,$3,'email','manual',$4,$5,1,$5,$5)`, f.tenant.String(), id.String(), f.membership.LegacyUserID.String(), value, at); err != nil {
		t.Fatal(err)
	}
}

func (f mailboxAdmissionFixture) contact(t *testing.T, value string) manualContactSnapshot {
	t.Helper()
	var got manualContactSnapshot
	if err := f.f.admin.QueryRow(context.Background(), `SELECT id,value,verified_at,created_at,updated_at,version FROM user_contacts WHERE tenant_id=$1 AND user_id=$2 AND kind='email' AND source='manual' AND value=$3`, f.tenant.String(), f.membership.LegacyUserID.String(), value).Scan(&got.id, &got.value, &got.verifiedAt, &got.createdAt, &got.updatedAt, &got.version); err != nil {
		t.Fatalf("read manual contact %q: %v", value, err)
	}
	return got
}

func (f mailboxAdmissionFixture) assertContact(t *testing.T, want manualContactSnapshot) {
	t.Helper()
	got := f.contact(t, want.value)
	if got.id != want.id || got.value != want.value || got.version != want.version || !got.verifiedAt.Equal(want.verifiedAt) || !got.createdAt.Equal(want.createdAt) || !got.updatedAt.Equal(want.updatedAt) {
		t.Fatalf("manual contact changed: got %+v, want %+v", got, want)
	}
}

func (f mailboxAdmissionFixture) assertContactAbsent(t *testing.T, value string) {
	t.Helper()
	if n := f.f.adminCount(t, `SELECT count(*) FROM user_contacts WHERE tenant_id=$1 AND user_id=$2 AND kind='email' AND source='manual' AND value=$3`, f.tenant.String(), f.membership.LegacyUserID.String(), value); n != 0 {
		t.Fatalf("mailbox contact %q rows = %d, want 0", value, n)
	}
}

func (f mailboxAdmissionFixture) assertSourceActive(t *testing.T) {
	t.Helper()
	auth, err := f.f.store.AuthenticateEnterpriseSession(context.Background(), f.sourceDigest, f.now)
	if err != nil || auth.Session.ID != f.sourceID {
		t.Fatalf("source session changed after rollback: %+v, %v", auth.Session, err)
	}
}

func (f mailboxAdmissionFixture) failVerifiedContactAudit(t *testing.T) {
	t.Helper()
	f.f.exec(t, `CREATE FUNCTION test_fail_mailbox_contact_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='`+f.tenant.String()+`' AND NEW.action='user_contact.verified' THEN RAISE EXCEPTION 'injected mailbox contact audit failure'; END IF; RETURN NEW; END $$`)
	f.f.exec(t, `CREATE TRIGGER test_fail_mailbox_contact_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION test_fail_mailbox_contact_audit()`)
	t.Cleanup(func() { f.clearVerifiedContactAudit(t) })
}

func (f mailboxAdmissionFixture) clearVerifiedContactAudit(t *testing.T) {
	t.Helper()
	f.f.exec(t, `DROP TRIGGER IF EXISTS test_fail_mailbox_contact_audit ON audit_log`)
	f.f.exec(t, `DROP FUNCTION IF EXISTS test_fail_mailbox_contact_audit()`)
}

func (f mailboxAdmissionFixture) counts(t *testing.T) mailboxAdmissionCounts {
	t.Helper()
	return mailboxAdmissionCounts{
		contacts:         f.f.adminCount(t, `SELECT count(*) FROM user_contacts WHERE tenant_id=$1`, f.tenant.String()),
		authenticators:   f.f.adminCount(t, `SELECT count(*) FROM identity_authenticators WHERE tenant_id=$1`, f.tenant.String()),
		sessions:         f.f.adminCount(t, `SELECT count(*) FROM identity_sessions WHERE tenant_id=$1`, f.tenant.String()),
		contactAudits:    f.f.adminCount(t, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='user_contact.verified'`, f.tenant.String()),
		acceptanceAudits: f.f.adminCount(t, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='identity.invitation_accepted'`, f.tenant.String()),
		sessionAudits:    f.f.adminCount(t, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='identity.session_created'`, f.tenant.String()),
	}
}

func (f mailboxAdmissionFixture) assertCounts(t *testing.T, want mailboxAdmissionCounts) {
	t.Helper()
	if got := f.counts(t); got != want {
		t.Fatalf("admission rows/audits = %+v, want %+v", got, want)
	}
}

func (f mailboxAdmissionFixture) assertPendingAndUnconsumed(t *testing.T) {
	t.Helper()
	var state string
	var consumedAt *time.Time
	if err := f.f.admin.QueryRow(context.Background(), `SELECT i.state,c.consumed_at FROM identity_invitations i JOIN identity_invitation_challenges c ON c.tenant_id=i.tenant_id AND c.invitation_id=i.id AND c.invitation_version=i.version WHERE i.tenant_id=$1 AND i.id=$2`, f.tenant.String(), f.invitation.ID.String()).Scan(&state, &consumedAt); err != nil {
		t.Fatal(err)
	}
	if state != "pending" || consumedAt != nil {
		t.Fatalf("failed admission mutated invitation/challenge: state=%q consumed_at=%v", state, consumedAt)
	}
}

func (f mailboxAdmissionFixture) assertAcceptedAndConsumed(t *testing.T) {
	t.Helper()
	var state string
	var consumedAt *time.Time
	if err := f.f.admin.QueryRow(context.Background(), `SELECT i.state,c.consumed_at FROM identity_invitations i JOIN identity_invitation_challenges c ON c.tenant_id=i.tenant_id AND c.invitation_id=i.id AND c.invitation_version=i.version WHERE i.tenant_id=$1 AND i.id=$2`, f.tenant.String(), f.invitation.ID.String()).Scan(&state, &consumedAt); err != nil {
		t.Fatal(err)
	}
	if state != "accepted" || consumedAt == nil {
		t.Fatalf("successful admission state=%q consumed_at=%v", state, consumedAt)
	}
}
