package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestIdentityMailboxChallengeRetryReplacesUndeliveredProof(t *testing.T) {
	for _, changedPerson := range []bool{false, true} {
		name := "same person"
		if changedPerson {
			name = "new anonymous attempt"
		}
		t.Run(name, func(t *testing.T) {
			f, tenant, now, invitation := admissionInvitation(t, "mailbox-retry", "member@example.com")
			ctx := context.Background()
			firstPerson := shared.ID("mailbox-person")
			nextPerson := firstPerson
			if changedPerson {
				nextPerson = "mailbox-retry-person"
			}
			firstDigest, nextDigest := identityDigest("undelivered-code"), identityDigest("delivered-code")
			if err := f.store.CreateMailboxChallenge(ctx, tenant, invitation.ID, invitation.Version, "mailbox-subject", firstPerson, firstDigest, now.Add(10*time.Minute), now); err != nil {
				t.Fatal(err)
			}
			retriedAt := now.Add(time.Minute)
			if err := f.store.CreateMailboxChallenge(ctx, tenant, invitation.ID, invitation.Version, "mailbox-subject", nextPerson, nextDigest, retriedAt.Add(10*time.Minute), retriedAt); err != nil {
				t.Fatalf("retry after failed mail delivery: %v", err)
			}
			old := admissionInvitationCommand(tenant, "mailbox-retry-connection", invitation, "mailbox-subject", "", firstPerson, retriedAt)
			old.ChallengeDigest = firstDigest
			if _, err := f.store.AdmitIdentity(ctx, old); !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("superseded mailbox code admitted: %v", err)
			}
			if changedPerson {
				old.ChallengeDigest = nextDigest
				if _, err := f.store.AdmitIdentity(ctx, old); !errors.Is(err, shared.ErrForbidden) {
					t.Fatalf("new code admitted old prospective person: %v", err)
				}
			}
			current := admissionInvitationCommand(tenant, "mailbox-retry-connection", invitation, "mailbox-subject", "", nextPerson, retriedAt)
			current.ChallengeDigest = nextDigest
			result, err := f.store.AdmitIdentity(ctx, current)
			if err != nil {
				t.Fatalf("current mailbox proof refused: %v", err)
			}
			if result.PersonID != nextPerson || f.adminCount(t, `SELECT count(*) FROM identity_memberships WHERE tenant_id=$1`, tenant) != 1 {
				t.Fatalf("retry did not admit exactly the current person: %+v", result)
			}
			if err := f.store.CreateMailboxChallenge(ctx, tenant, invitation.ID, invitation.Version, "mailbox-subject", nextPerson, identityDigest("after-acceptance"), retriedAt.Add(10*time.Minute), retriedAt); !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("accepted invitation issued a new challenge: %v", err)
			}
		})
	}
}

func TestIdentityMailboxChallengeRetryGuards(t *testing.T) {
	for _, mode := range []string{"expired proof", "consumed proof", "same digest", "revoked invitation", "expired invitation", "stale version"} {
		t.Run(mode, func(t *testing.T) {
			f, tenant, now, invitation := admissionInvitation(t, "mailbox-guard", "member@example.test")
			ctx := context.Background()
			person := shared.ID("mailbox-person")
			first := identityDigest("first-code")
			if err := f.store.CreateMailboxChallenge(ctx, tenant, invitation.ID, 1, "subject", person, first, now.Add(time.Minute), now); err != nil {
				t.Fatal(err)
			}
			next, version, at := identityDigest("next-code"), 1, now.Add(2*time.Minute)
			switch mode {
			case "consumed proof":
				if err := f.runtimeExec(tenant.String(), `UPDATE identity_invitation_challenges SET consumed_at=$2 WHERE tenant_id=$1`, tenant.String(), now); err != nil {
					t.Fatal(err)
				}
			case "same digest":
				next = first
			case "revoked invitation":
				if err := f.store.RevokeIdentityInvitation(ctx, tenant, invitation.ID, 1, bootstrapConnectionProof(tenant.String(), now), now); err != nil {
					t.Fatal(err)
				}
			case "expired invitation":
				at = invitation.ExpiresAt
			case "stale version":
				version = 2
			}
			err := f.store.CreateMailboxChallenge(ctx, tenant, invitation.ID, version, "subject", "next-person", next, at.Add(10*time.Minute), at)
			if mode == "expired proof" {
				if err != nil {
					t.Fatalf("expired unused proof cannot be renewed: %v", err)
				}
				c := admissionInvitationCommand(tenant, "mailbox-guard-connection", invitation, "subject", "", "next-person", at)
				c.ChallengeDigest = next
				if _, err := f.store.AdmitIdentity(ctx, c); err != nil {
					t.Fatalf("renewed proof rejected: %v", err)
				}
			} else {
				if !errors.Is(err, shared.ErrForbidden) {
					t.Fatalf("unsafe renewal allowed: %v", err)
				}
				if n := f.adminCount(t, `SELECT count(*) FROM identity_invitation_challenges WHERE tenant_id=$1 AND prospective_person_id=$2 AND challenge_digest=$3 AND expires_at=$4`, tenant.String(), person.String(), first, now.Add(time.Minute)); n != 1 {
					t.Fatal("rejected renewal changed original proof")
				}
			}
		})
	}
}

func TestIdentityMailboxConcurrentRetriesLeaveOneUsableProof(t *testing.T) {
	f, tenant, now, invitation := admissionInvitation(t, "mailbox-concurrent", "member@example.test")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const attempts = 6
	start, results := make(chan struct{}), make(chan error, attempts)
	var workers sync.WaitGroup
	for i := range attempts {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			results <- f.store.CreateMailboxChallenge(ctx, tenant, invitation.ID, 1, "subject", shared.ID(fmt.Sprintf("person-%d", i)), identityDigest(fmt.Sprintf("code-%d", i)), now.Add(10*time.Minute), now)
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_invitation_challenges WHERE tenant_id=$1`, tenant.String()); n != 1 {
		t.Fatalf("proof rows = %d", n)
	}
	accepted := 0
	for i := range attempts {
		c := admissionInvitationCommand(tenant, "mailbox-concurrent-connection", invitation, "subject", "", shared.ID(fmt.Sprintf("person-%d", i)), now)
		c.ChallengeDigest = identityDigest(fmt.Sprintf("code-%d", i))
		if _, err := f.store.AdmitIdentity(ctx, c); err == nil {
			accepted++
		} else if !errors.Is(err, shared.ErrForbidden) && !errors.Is(err, shared.ErrConflict) {
			t.Fatal(err)
		}
	}
	if accepted != 1 {
		t.Fatalf("usable proofs = %d, want 1", accepted)
	}
}

func TestIdentityMailboxRetrySerializesWithAdmissionAndRevocation(t *testing.T) {
	for _, action := range []string{"admit", "revoke"} {
		t.Run(action, func(t *testing.T) {
			f, tenant, now, invitation := admissionInvitation(t, "mailbox-race", "member@example.test")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			first, next := identityDigest("first-code"), identityDigest("next-code")
			if err := f.store.CreateMailboxChallenge(ctx, tenant, invitation.ID, 1, "subject", "person", first, now.Add(time.Minute), now); err != nil {
				t.Fatal(err)
			}
			start, retryResult, actionResult := make(chan struct{}), make(chan error, 1), make(chan error, 1)
			go func() {
				<-start
				retryResult <- f.store.CreateMailboxChallenge(ctx, tenant, invitation.ID, 1, "subject", "person", next, now.Add(10*time.Minute), now)
			}()
			go func() {
				<-start
				if action == "revoke" {
					actionResult <- f.store.RevokeIdentityInvitation(ctx, tenant, invitation.ID, 1, bootstrapConnectionProof(tenant.String(), now), now)
					return
				}
				c := admissionInvitationCommand(tenant, "mailbox-race-connection", invitation, "subject", "", "person", now)
				c.ChallengeDigest = first
				_, err := f.store.AdmitIdentity(ctx, c)
				actionResult <- err
			}()
			close(start)
			retryErr, actionErr := <-retryResult, <-actionResult
			if retryErr != nil && !errors.Is(retryErr, shared.ErrForbidden) {
				t.Fatal(retryErr)
			}
			if action == "revoke" {
				if actionErr != nil {
					t.Fatal(actionErr)
				}
				if err := f.store.CreateMailboxChallenge(ctx, tenant, invitation.ID, 1, "subject", "person", identityDigest("after-revoke"), now.Add(10*time.Minute), now); !errors.Is(err, shared.ErrForbidden) {
					t.Fatalf("revocation bypassed: %v", err)
				}
			} else if actionErr == nil {
				if !errors.Is(retryErr, shared.ErrForbidden) {
					t.Fatalf("proof renewed after consumption: %v", retryErr)
				}
			} else {
				if !errors.Is(actionErr, shared.ErrForbidden) || retryErr != nil {
					t.Fatalf("invalid serialized result: admission=%v retry=%v", actionErr, retryErr)
				}
				c := admissionInvitationCommand(tenant, "mailbox-race-connection", invitation, "subject", "", "person", now)
				c.ChallengeDigest = next
				if _, err := f.store.AdmitIdentity(ctx, c); err != nil {
					t.Fatalf("winning retry unusable: %v", err)
				}
			}
		})
	}
}
