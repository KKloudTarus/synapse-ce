package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/oidc"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identitysessions"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestEnterpriseSwitchReplayAndLogoutInvalidation(t *testing.T) {
	f := newIdentityFixture(t)
	now := time.Now().UTC()
	f.tenants(t, "switch-a", "switch-b")
	f.declare(t, "switch-a")
	f.declare(t, "switch-b")
	person := f.newPerson(t, "switch-person")
	source, err := f.store.AddMembership(context.Background(), "switch-a", person, "Source", "member", "platform", now)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := f.store.AddMembership(context.Background(), "switch-b", person, "Destination", "member", "platform", now)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionConnection(t, f, "switch-a", source, "conn-a", "subject-a", now)
	seedSessionConnection(t, f, "switch-b", destination, "conn-b", "subject-b", now)
	sourceDigest := identityDigest("switch-source")
	sourceSession := enterpriseSession("source-session", "switch-a", source.ID, person, "conn-a", now)
	if err = f.store.CreateEnterpriseSession(context.Background(), ports.IdentitySessionIssue{Session: sourceSession, CredentialDigest: sourceDigest}, "actor", now); err != nil {
		t.Fatal(err)
	}
	replacement := enterpriseSession("destination-session", "switch-b", destination.ID, person, "conn-b", now)
	replacement.CredentialID = "destination-credential"
	command := ports.IdentitySessionSwitch{SourceCredentialDigest: sourceDigest, DestinationTenantID: "switch-b", DestinationMembershipID: destination.ID, DestinationConnectionID: "conn-b", DestinationSubject: "subject-b", DestinationRevision: 1, DestinationAuthenticatedAt: now, Replacement: ports.IdentitySessionIssue{Session: replacement, CredentialDigest: identityDigest("switch-destination")}, RetryKey: "retry-key", RetryPayloadHash: identityDigest("payload"), RetryCiphertext: "encrypted", Now: now}
	if _, err = f.store.SwitchEnterpriseSession(context.Background(), command, "actor"); err != nil {
		t.Fatal(err)
	}
	retained, err := f.store.ReplayEnterpriseSessionSwitch(context.Background(), ports.IdentitySessionSwitchReplay{SourceCredentialDigest: sourceDigest, SourceCSRFTokenHash: sourceSession.CSRFTokenHash, RetryKey: command.RetryKey, PayloadHash: command.RetryPayloadHash, Now: now})
	if err != nil || !retained.Replayed || retained.RetryCiphertext != "encrypted" || retained.Session.ID != replacement.ID {
		t.Fatalf("explicit replay=%+v err=%v", retained, err)
	}
	if _, err := f.store.ReplayEnterpriseSessionSwitch(context.Background(), ports.IdentitySessionSwitchReplay{SourceCredentialDigest: sourceDigest, SourceCSRFTokenHash: identityDigest("wrong-csrf"), RetryKey: command.RetryKey, PayloadHash: command.RetryPayloadHash, Now: now}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("replay with wrong source CSRF=%v", err)
	}
	// Response-loss replay finds the retained record even though source digest was revoked.
	replay, err := f.store.SwitchEnterpriseSession(context.Background(), command, "actor")
	if err != nil || !replay.Replayed || replay.RetryCiphertext != "encrypted" {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	changed := command
	changed.RetryPayloadHash = identityDigest("changed")
	if _, err = f.store.SwitchEnterpriseSession(context.Background(), changed, "actor"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("changed payload=%v", err)
	}
	if err = f.store.LogoutEnterpriseSession(context.Background(), identityDigest("switch-destination"), "actor", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.SwitchEnterpriseSession(context.Background(), command, "actor"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("replay after logout=%v", err)
	}
}

func TestEnterpriseSwitchSameKeyConcurrentReplayAndDestinationFence(t *testing.T) {
	f := newIdentityFixture(t)
	now := time.Now().UTC()
	f.tenants(t, "race-a", "race-b")
	f.declare(t, "race-a")
	f.declare(t, "race-b")
	person := f.newPerson(t, "race-person")
	source, _ := f.store.AddMembership(context.Background(), "race-a", person, "Source", "member", "platform", now)
	destination, _ := f.store.AddMembership(context.Background(), "race-b", person, "Destination", "member", "platform", now)
	seedSessionConnection(t, f, "race-a", source, "race-conn-a", "source", now)
	seedSessionConnection(t, f, "race-b", destination, "race-conn-b", "destination", now)
	digest := identityDigest("race-source")
	sourceSession := enterpriseSession("race-source-session", "race-a", source.ID, person, "race-conn-a", now)
	if err := f.store.CreateEnterpriseSession(context.Background(), ports.IdentitySessionIssue{Session: sourceSession, CredentialDigest: digest}, "actor", now); err != nil {
		t.Fatal(err)
	}
	repl := enterpriseSession("race-destination-session", "race-b", destination.ID, person, "race-conn-b", now)
	repl.CredentialID = "race-destination-credential"
	cmd := ports.IdentitySessionSwitch{SourceCredentialDigest: digest, DestinationTenantID: "race-b", DestinationMembershipID: destination.ID, DestinationConnectionID: "race-conn-b", DestinationSubject: "destination", DestinationRevision: 1, DestinationAuthenticatedAt: now, Replacement: ports.IdentitySessionIssue{Session: repl, CredentialDigest: identityDigest("race-dest")}, RetryKey: "same-key", RetryPayloadHash: identityDigest("same-payload"), RetryCiphertext: "ciphertext", Now: now}
	var wg sync.WaitGroup
	errs := make([]error, 4)
	out := make([]ports.IdentitySessionSwitchResult, 4)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out[i], errs[i] = f.store.SwitchEnterpriseSession(context.Background(), cmd, "actor")
		}(i)
	}
	wg.Wait()
	writes := 0
	for i := range errs {
		if errs[i] != nil || out[i].RetryCiphertext != "ciphertext" || out[i].Session.ID != repl.ID {
			t.Fatalf("same-key attempt %d out=%+v err=%v", i, out[i], errs[i])
		}
		if !out[i].Replayed {
			writes++
		}
	}
	if writes != 1 || f.adminCount(t, `SELECT count(*) FROM identity_sessions WHERE tenant_id='race-b'`) != 1 {
		t.Fatalf("same-key concurrent first attempts wrote %d replacement rows", writes)
	}
	changed := cmd
	changed.RetryPayloadHash = identityDigest("different")
	if _, err := f.store.SwitchEnterpriseSession(context.Background(), changed, "actor"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("changed payload: %v", err)
	}
	wrong := cmd
	wrong.DestinationSubject = "other"
	wrong.RetryKey = "new-key"
	wrong.RetryPayloadHash = identityDigest("new")
	if _, err := f.store.SwitchEnterpriseSession(context.Background(), wrong, "actor"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("revoked source accepted changed switch: %v", err)
	}
}

func TestEnterpriseSessionAuthenticationRejectsAuthoritativeEpochChanges(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, f *identityFixture, membership ports.IdentityMembership, person shared.ID)
	}{
		{"role", func(t *testing.T, f *identityFixture, membership ports.IdentityMembership, _ shared.ID) {
			if err := f.runtimeExec("fence-org", `UPDATE identity_memberships SET role='readonly' WHERE tenant_id=$1 AND id=$2`, "fence-org", membership.ID.String()); err != nil {
				t.Fatal(err)
			}
		}},
		{"removal", func(t *testing.T, f *identityFixture, membership ports.IdentityMembership, _ shared.ID) {
			if err := f.runtimeExec("fence-org", `UPDATE identity_memberships SET state='removed',suspension_source=NULL,last_transition_source='manual' WHERE tenant_id=$1 AND id=$2`, "fence-org", membership.ID.String()); err != nil {
				t.Fatal(err)
			}
		}},
		{"connection", func(t *testing.T, f *identityFixture, _ ports.IdentityMembership, _ shared.ID) {
			if err := f.runtimeExec("fence-org", `UPDATE identity_connections SET enabled=false WHERE tenant_id=$1 AND id='fence-connection'`, "fence-org"); err != nil {
				t.Fatal(err)
			}
		}},
		{"person", func(t *testing.T, f *identityFixture, _ ports.IdentityMembership, person shared.ID) {
			if _, err := f.platform.ApplyPersonCommand(context.Background(), person, ports.IdentityPersonSessionsRevoked, "platform", "test"); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newIdentityFixture(t)
			now := time.Now().UTC()
			f.tenants(t, "fence-org")
			f.declare(t, "fence-org")
			person := f.newPerson(t, "fence-person")
			membership, err := f.store.AddMembership(context.Background(), "fence-org", person, "Fence", "member", "platform", now)
			if err != nil {
				t.Fatal(err)
			}
			seedSessionConnection(t, f, "fence-org", membership, "fence-connection", "fence-subject", now)
			digest := identityDigest("fence-token")
			session := enterpriseSession("fence-session", "fence-org", membership.ID, person, "fence-connection", now)
			if err := f.store.CreateEnterpriseSession(context.Background(), ports.IdentitySessionIssue{Session: session, CredentialDigest: digest}, "actor", now); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.AuthenticateEnterpriseSession(context.Background(), digest, now); err != nil {
				t.Fatalf("authenticate active session: %v", err)
			}
			tc.mutate(t, f, membership, person)
			if _, err := f.store.AuthenticateEnterpriseSession(context.Background(), digest, now); !errors.Is(err, shared.ErrNotFound) {
				t.Fatalf("%s change authenticated stale session: %v", tc.name, err)
			}
		})
	}
}

func TestEnterpriseSwitchAllowsOptionalDestinationWithoutConnection(t *testing.T) {
	f := newIdentityFixture(t)
	now := time.Now().UTC()
	f.tenants(t, "optional-source", "optional-destination")
	f.declare(t, "optional-source")
	f.declare(t, "optional-destination")
	person := f.newPerson(t, "optional-person")
	sourceMembership, err := f.store.AddMembership(context.Background(), "optional-source", person, "Source", "member", "platform", now)
	if err != nil {
		t.Fatal(err)
	}
	destinationMembership, err := f.store.AddMembership(context.Background(), "optional-destination", person, "Destination", "member", "platform", now)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionConnection(t, f, "optional-source", sourceMembership, "optional-source-connection", "source", now)
	sourceDigest := identityDigest("optional-source-token")
	source := enterpriseSession("optional-source-session", "optional-source", sourceMembership.ID, person, "optional-source-connection", now)
	if err := f.store.CreateEnterpriseSession(context.Background(), ports.IdentitySessionIssue{Session: source, CredentialDigest: sourceDigest}, "actor", now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.platform.ApplyPersonCommand(context.Background(), person, ports.IdentityPersonSessionsRevoked, "platform", "fresh login"); err != nil {
		t.Fatal(err)
	}
	freshSource := enterpriseSession("optional-source-fresh-session", "optional-source", sourceMembership.ID, person, "optional-source-connection", now)
	freshSource.PersonEpoch = 2
	sourceDigest = identityDigest("optional-source-fresh-token")
	if err := f.store.CreateEnterpriseSession(context.Background(), ports.IdentitySessionIssue{Session: freshSource, CredentialDigest: sourceDigest}, "actor", now); err != nil {
		t.Fatal(err)
	}
	if err := f.runtimeExec("optional-destination", `UPDATE identity_memberships SET role='readonly' WHERE tenant_id=$1 AND id=$2`, "optional-destination", destinationMembership.ID.String()); err != nil {
		t.Fatal(err)
	}
	replacement := enterpriseSession("optional-destination-session", "optional-destination", destinationMembership.ID, person, "", now)
	replacement.ConnectionEpoch = 0
	replacement.CredentialID = "optional-destination-credential"
	result, err := f.store.SwitchEnterpriseSession(context.Background(), ports.IdentitySessionSwitch{
		SourceCredentialDigest: sourceDigest, DestinationTenantID: "optional-destination", DestinationMembershipID: destinationMembership.ID,
		Replacement: ports.IdentitySessionIssue{Session: replacement, CredentialDigest: identityDigest("optional-destination-token")},
		RetryKey:    "optional-key", RetryPayloadHash: identityDigest("optional-payload"), RetryCiphertext: "optional-ciphertext", Now: now,
	}, "actor")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Session.ConnectionID.IsZero() || result.Session.LineageID != freshSource.LineageID || !result.Session.AuthenticatedAt.Equal(freshSource.AuthenticatedAt.Truncate(time.Microsecond)) || result.Session.PersonEpoch != 2 || result.Session.MembershipEpoch != 2 || result.Session.ConnectionEpoch != 0 {
		t.Fatalf("optional switch did not preserve source lineage: %+v", result.Session)
	}
	if _, err := f.store.AuthenticateEnterpriseSession(context.Background(), identityDigest("optional-destination-token"), now); err != nil {
		t.Fatalf("optional switch did not use authoritative evolved epochs: %v", err)
	}
}

func TestEnterpriseSwitchUsesAuthoritativeEvolvedRequiredEpochs(t *testing.T) {
	f, _, source, command := switchTestSetup(t, "evolved-required")
	if _, err := f.platform.ApplyPersonCommand(context.Background(), source.PersonID, ports.IdentityPersonSessionsRevoked, "platform", "fresh login"); err != nil {
		t.Fatal(err)
	}
	fresh := enterpriseSession("evolved-required-fresh-source", source.TenantID, source.MembershipID, source.PersonID, source.ConnectionID, command.Now)
	fresh.PersonEpoch = 2
	sourceDigest := identityDigest("evolved-required-fresh-token")
	if err := f.store.CreateEnterpriseSession(context.Background(), ports.IdentitySessionIssue{Session: fresh, CredentialDigest: sourceDigest}, "actor", command.Now); err != nil {
		t.Fatal(err)
	}
	if err := f.runtimeExec(command.DestinationTenantID.String(), `UPDATE identity_memberships SET role='readonly' WHERE tenant_id=$1 AND id=$2`, command.DestinationTenantID.String(), command.DestinationMembershipID.String()); err != nil {
		t.Fatal(err)
	}
	command.SourceCredentialDigest = sourceDigest
	result, err := f.store.SwitchEnterpriseSession(context.Background(), command, "actor")
	if err != nil {
		t.Fatal(err)
	}
	if result.Session.PersonEpoch != 2 || result.Session.MembershipEpoch != 2 || result.Session.ConnectionEpoch != 1 {
		t.Fatalf("required switch epochs=%+v, want person=2 membership=2 connection=1", result.Session)
	}
	if _, err := f.store.AuthenticateEnterpriseSession(context.Background(), command.Replacement.CredentialDigest, command.Now); err != nil {
		t.Fatalf("required switch did not use authoritative evolved epochs: %v", err)
	}
}

func TestEnterpriseSessionMixedSwitchRotationReplayAndLogoutFinish(t *testing.T) {
	f, sourceDigest, source, command := switchTestSetup(t, "mixed-lock-order")
	rotation := enterpriseSession("mixed-lock-order-rotation", source.TenantID, source.MembershipID, source.PersonID, source.ConnectionID, command.Now)
	rotation.CredentialID = "mixed-lock-order-rotation-credential"
	rotation.LineageID = source.LineageID
	rotation.RotatedFromSessionID = source.ID
	rotation.AuthenticatedAt = source.AuthenticatedAt
	rotation.OriginAt = source.OriginAt

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results := make(chan error, 2)
	go func() {
		_, err := f.store.SwitchEnterpriseSession(ctx, command, "actor")
		results <- err
	}()
	go func() {
		results <- f.store.RotateEnterpriseSession(ctx, sourceDigest, ports.IdentitySessionIssue{Session: rotation, CredentialDigest: identityDigest("mixed-lock-order-rotation-token")}, "actor", command.Now)
	}()
	winners := 0
	for range 2 {
		err := <-results
		if err == nil {
			winners++
		} else if !errors.Is(err, shared.ErrNotFound) && !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("unexpected mixed switch/rotation error: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("mixed switch/rotation winners=%d, want one", winners)
	}
	if _, err := f.store.AuthenticateEnterpriseSession(ctx, sourceDigest, command.Now); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("source survived competing rotation/switch: %v", err)
	}
	active := 0
	for _, digest := range []string{command.Replacement.CredentialDigest, identityDigest("mixed-lock-order-rotation-token")} {
		if _, err := f.store.AuthenticateEnterpriseSession(ctx, digest, command.Now); err == nil {
			active++
		} else if !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("replacement authentication: %v", err)
		}
	}
	if active != 1 {
		t.Fatalf("active mixed-operation replacements=%d, want one", active)
	}

	// A successful switch retains an exact response-loss retry. Replay and destination logout lock
	// the same two policies before session or credential rows, so either may win without waiting in
	// opposing lock order.
	f, sourceDigest, _, command = switchTestSetup(t, "mixed-replay-logout")
	if _, err := f.store.SwitchEnterpriseSession(context.Background(), command, "actor"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results = make(chan error, 2)
	go func() {
		_, err := f.store.ReplayEnterpriseSessionSwitch(ctx, ports.IdentitySessionSwitchReplay{SourceCredentialDigest: sourceDigest, SourceCSRFTokenHash: identityDigest("mixed-replay-logout-source-session-csrf"), RetryKey: command.RetryKey, PayloadHash: command.RetryPayloadHash, Now: command.Now})
		results <- err
	}()
	go func() {
		results <- f.store.LogoutEnterpriseSession(ctx, command.Replacement.CredentialDigest, "actor", command.Now)
	}()
	for range 2 {
		if err := <-results; err != nil && !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("unexpected mixed replay/logout error: %v", err)
		}
	}
	if _, err := f.store.AuthenticateEnterpriseSession(ctx, command.Replacement.CredentialDigest, command.Now); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("destination survived logout: %v", err)
	}
	if _, err := f.store.ReplayEnterpriseSessionSwitch(ctx, ports.IdentitySessionSwitchReplay{SourceCredentialDigest: sourceDigest, SourceCSRFTokenHash: identityDigest("mixed-replay-logout-source-session-csrf"), RetryKey: command.RetryKey, PayloadHash: command.RetryPayloadHash, Now: command.Now}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("reply survived logout: %v", err)
	}
}

func TestEnterpriseSwitchRollsBackAfterAuditAndCredentialIndexFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		inject func(t *testing.T, f *identityFixture)
	}{
		{"audit", func(t *testing.T, f *identityFixture) {
			f.exec(t, `CREATE FUNCTION test_switch_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='identity.session_switched_out' THEN RAISE EXCEPTION 'injected switch audit failure'; END IF; RETURN NEW; END $$`)
			f.exec(t, `CREATE TRIGGER test_switch_audit_failure BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION test_switch_audit_failure()`)
			t.Cleanup(func() {
				f.exec(t, `DROP TRIGGER IF EXISTS test_switch_audit_failure ON audit_log`)
				f.exec(t, `DROP FUNCTION IF EXISTS test_switch_audit_failure()`)
			})
		}},
		{"credential index", func(t *testing.T, f *identityFixture) {
			f.exec(t, `CREATE FUNCTION test_switch_index_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected credential index failure'; END $$`)
			f.exec(t, `CREATE TRIGGER test_switch_index_failure BEFORE INSERT ON identity_credential_digests FOR EACH ROW EXECUTE FUNCTION test_switch_index_failure()`)
			t.Cleanup(func() {
				f.exec(t, `DROP TRIGGER IF EXISTS test_switch_index_failure ON identity_credential_digests`)
				f.exec(t, `DROP FUNCTION IF EXISTS test_switch_index_failure()`)
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, sourceDigest, source, command := switchTestSetup(t, "rollback-"+tc.name)
			tc.inject(t, f)
			if _, err := f.store.SwitchEnterpriseSession(context.Background(), command, "actor"); err == nil {
				t.Fatal("switch succeeded despite injected failure")
			}
			if _, err := f.store.AuthenticateEnterpriseSession(context.Background(), sourceDigest, command.Now); err != nil {
				t.Fatalf("source was not restored after rollback: %v", err)
			}
			if n := f.adminCount(t, `SELECT count(*) FROM identity_sessions WHERE tenant_id=$1 AND id=$2`, command.DestinationTenantID.String(), command.Replacement.Session.ID.String()); n != 0 {
				t.Fatalf("replacement sessions=%d, want 0", n)
			}
			if n := f.adminCount(t, `SELECT count(*) FROM identity_session_switch_retries WHERE tenant_id=$1 AND retry_key=$2`, source.TenantID.String(), command.RetryKey); n != 0 {
				t.Fatalf("retained retries=%d, want 0", n)
			}
		})
	}
}

func TestEnterpriseSwitchReplayRejectsTamperedCiphertext(t *testing.T) {
	f, sourceDigest, source, command := switchTestSetup(t, "tamper")
	if _, err := f.store.SwitchEnterpriseSession(context.Background(), command, "actor"); err != nil {
		t.Fatal(err)
	}
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	protector := oidc.NewSecretProtector(cipher)
	clock := browserClock{at: command.Now}
	service, err := identitysessions.NewService(f.store, sessionReplayProof{}, protector, clock, &browserIDs{})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := protector.Seal(context.Background(), []byte("replacement-token\nreplacement-csrf"), []byte("identity-session-switch:"+sourceDigest+":"+command.RetryKey+":"+command.RetryPayloadHash))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.runtimeExec(source.TenantID.String(), `UPDATE identity_session_switch_retries SET response_ciphertext=$3 WHERE tenant_id=$1 AND retry_key=$2`, source.TenantID.String(), command.RetryKey, sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Replay(context.Background(), identitysessions.ReplayInput{SourceToken: "tamper-source", SourceCSRFToken: "tamper-source-session-csrf", RetryKey: command.RetryKey, RetryPayload: "tamper-payload"}); err != nil {
		t.Fatalf("valid retained response replay=%v", err)
	}
	if err := f.runtimeExec(source.TenantID.String(), `UPDATE identity_session_switch_retries SET response_ciphertext='tampered' WHERE tenant_id=$1 AND retry_key=$2`, source.TenantID.String(), command.RetryKey); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Replay(context.Background(), identitysessions.ReplayInput{SourceToken: "tamper-source", SourceCSRFToken: "tamper-source-session-csrf", RetryKey: command.RetryKey, RetryPayload: "tamper-payload"}); err == nil {
		t.Fatal("tampered ciphertext replay succeeded")
	}
}

func TestEnterpriseSwitchDestinationFencesRejectBeforeIssuance(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, f *identityFixture, command ports.IdentitySessionSwitch)
	}{
		{"missing policy", func(t *testing.T, f *identityFixture, command ports.IdentitySessionSwitch) {
			if err := f.runtimeExec(command.DestinationTenantID.String(), `DELETE FROM identity_policies WHERE tenant_id=$1`, command.DestinationTenantID.String()); err != nil {
				t.Fatal(err)
			}
		}},
		{"disabled connection", func(t *testing.T, f *identityFixture, command ports.IdentitySessionSwitch) {
			if err := f.runtimeExec(command.DestinationTenantID.String(), `UPDATE identity_connections SET enabled=false WHERE tenant_id=$1 AND id=$2`, command.DestinationTenantID.String(), command.DestinationConnectionID.String()); err != nil {
				t.Fatal(err)
			}
		}},
		{"removed membership", func(t *testing.T, f *identityFixture, command ports.IdentitySessionSwitch) {
			if err := f.runtimeExec(command.DestinationTenantID.String(), `UPDATE identity_memberships SET state='removed',suspension_source=NULL,last_transition_source='manual' WHERE tenant_id=$1 AND id=$2`, command.DestinationTenantID.String(), command.DestinationMembershipID.String()); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, sourceDigest, source, command := switchTestSetup(t, "fence-"+tc.name)
			tc.mutate(t, f, command)
			if _, err := f.store.SwitchEnterpriseSession(context.Background(), command, "actor"); err == nil {
				t.Fatal("switch issued despite destination fence")
			}
			if _, err := f.store.AuthenticateEnterpriseSession(context.Background(), sourceDigest, command.Now); err != nil {
				t.Fatalf("source lost before rejected callback: %v", err)
			}
			if n := f.adminCount(t, `SELECT count(*) FROM identity_sessions WHERE tenant_id=$1 AND id=$2`, command.DestinationTenantID.String(), command.Replacement.Session.ID.String()); n != 0 {
				t.Fatalf("replacement sessions=%d, want 0", n)
			}
			if n := f.adminCount(t, `SELECT count(*) FROM identity_session_switch_retries WHERE tenant_id=$1 AND retry_key=$2`, source.TenantID.String(), command.RetryKey); n != 0 {
				t.Fatalf("retained retries=%d, want 0", n)
			}
		})
	}
}

type sessionReplayProof struct{}

func (sessionReplayProof) VerifyDestinationProof(context.Context, shared.ID, shared.ID, shared.ID, string, int, time.Time) error {
	return nil
}

func TestEnterpriseSessionRetryCleanupIsBoundedAcrossWorkers(t *testing.T) {
	f, _, source, command := switchTestSetup(t, "retry-cleanup")
	if _, err := f.store.SwitchEnterpriseSession(context.Background(), command, "actor"); err != nil {
		t.Fatal(err)
	}
	for i, key := range []string{"retry-cleanup-copy-1", "retry-cleanup-copy-2"} {
		extra := enterpriseSession("retry-cleanup-extra-"+string(rune('1'+i)), source.TenantID, source.MembershipID, source.PersonID, source.ConnectionID, command.Now)
		extraDigest := identityDigest("retry-cleanup-extra-" + string(rune('1'+i)))
		if err := f.store.CreateEnterpriseSession(context.Background(), ports.IdentitySessionIssue{Session: extra, CredentialDigest: extraDigest}, "actor", command.Now); err != nil {
			t.Fatal(err)
		}
		if err := f.runtimeExec(source.TenantID.String(), `INSERT INTO identity_session_switch_retries(tenant_id,retry_key,payload_hash,source_credential_id,source_digest,destination_tenant_id,destination_session_id,response_ciphertext,expires_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,'authenticated-ciphertext',$8)`, source.TenantID.String(), key, command.RetryPayloadHash, extra.CredentialID.String(), extraDigest, command.DestinationTenantID.String(), command.Replacement.Session.ID.String(), command.Now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	now := command.Now.Add(time.Minute)
	if err := f.runtimeExec(source.TenantID.String(), `UPDATE identity_session_switch_retries SET created_at=$2,expires_at=$3 WHERE tenant_id=$1`, source.TenantID.String(), now.Add(-2*time.Minute), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	stores := []*IdentityFoundationStore{{pool: f.runtime}, {pool: f.runtime}}
	counts := make([]int, len(stores))
	errs := make([]error, len(stores))
	var wg sync.WaitGroup
	for i, store := range stores {
		wg.Add(1)
		go func(i int, store *IdentityFoundationStore) {
			defer wg.Done()
			counts[i], errs[i] = store.CleanupEnterpriseSessionRetries(context.Background(), source.TenantID, now, 1)
		}(i, store)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || counts[0]+counts[1] != 2 || f.adminCount(t, `SELECT count(*) FROM identity_session_switch_retries WHERE tenant_id=$1`, source.TenantID.String()) != 1 {
		t.Fatalf("cleanup counts=%v errs=%v", counts, errs)
	}
}

func TestEnterpriseSessionIssuanceAndSwitchUseLatestConnectionTest(t *testing.T) {
	t.Run("aged passed activation remains usable", func(t *testing.T) {
		f, _, source, command := switchTestSetup(t, "aged-activation")
		agedConnection := shared.ID("aged-activation-connection")
		seedSessionConnection(t, f, command.DestinationTenantID.String(), ports.IdentityMembership{ID: command.DestinationMembershipID, PersonID: source.PersonID}, agedConnection.String(), "aged-destination", command.Now.Add(-48*time.Hour))
		command.DestinationConnectionID = agedConnection
		command.DestinationSubject = "aged-destination"
		command.Replacement.Session.ConnectionID = agedConnection
		issue := enterpriseSession("aged-activation-issued", command.DestinationTenantID, command.DestinationMembershipID, source.PersonID, agedConnection, command.Now)
		if err := f.store.CreateEnterpriseSession(context.Background(), ports.IdentitySessionIssue{Session: issue, CredentialDigest: identityDigest("aged-activation-issued")}, "actor", command.Now); err != nil {
			t.Fatalf("issuance with unchanged aged passed activation=%v", err)
		}
		if _, err := f.store.SwitchEnterpriseSession(context.Background(), command, "actor"); err != nil {
			t.Fatalf("switch with unchanged aged passed activation=%v", err)
		}
	})

	t.Run("newer failed activation denies issuance and switch", func(t *testing.T) {
		f, sourceDigest, source, command := switchTestSetup(t, "failed-activation")
		if err := f.runtimeExec(command.DestinationTenantID.String(), `INSERT INTO identity_connection_tests(tenant_id,id,connection_id,revision,state,tested_at,expires_at) VALUES($1,'newer-failed',$2,1,'failed',$3,$4)`, command.DestinationTenantID.String(), command.DestinationConnectionID.String(), command.Now.Add(time.Microsecond), command.Now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		issue := enterpriseSession("failed-activation-issued", command.DestinationTenantID, command.DestinationMembershipID, source.PersonID, command.DestinationConnectionID, command.Now)
		if err := f.store.CreateEnterpriseSession(context.Background(), ports.IdentitySessionIssue{Session: issue, CredentialDigest: identityDigest("failed-activation-issued")}, "actor", command.Now); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("issuance with newer failed activation=%v, want not found", err)
		}
		if _, err := f.store.SwitchEnterpriseSession(context.Background(), command, "actor"); !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("switch with newer failed activation=%v, want forbidden", err)
		}
		if _, err := f.store.AuthenticateEnterpriseSession(context.Background(), sourceDigest, command.Now); err != nil {
			t.Fatalf("source was revoked before failed destination switch: %v", err)
		}
	})
}

func switchTestSetup(t *testing.T, prefix string) (*identityFixture, string, identity.EnterpriseSession, ports.IdentitySessionSwitch) {
	t.Helper()
	f := newIdentityFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	sourceTenant, destinationTenant := shared.ID(prefix+"-a"), shared.ID(prefix+"-b")
	f.tenants(t, sourceTenant.String(), destinationTenant.String())
	f.declare(t, sourceTenant.String())
	f.declare(t, destinationTenant.String())
	person := f.newPerson(t, prefix+"-person")
	sourceMembership, err := f.store.AddMembership(context.Background(), sourceTenant, person, "Source", "member", "platform", now)
	if err != nil {
		t.Fatal(err)
	}
	destinationMembership, err := f.store.AddMembership(context.Background(), destinationTenant, person, "Destination", "member", "platform", now)
	if err != nil {
		t.Fatal(err)
	}
	sourceConnection, destinationConnection := shared.ID(prefix+"-conn-a"), shared.ID(prefix+"-conn-b")
	seedSessionConnection(t, f, sourceTenant.String(), sourceMembership, sourceConnection.String(), "source", now)
	seedSessionConnection(t, f, destinationTenant.String(), destinationMembership, destinationConnection.String(), "destination", now)
	sourceDigest := identityDigest(prefix + "-source")
	source := enterpriseSession(prefix+"-source-session", sourceTenant, sourceMembership.ID, person, sourceConnection, now)
	if err := f.store.CreateEnterpriseSession(context.Background(), ports.IdentitySessionIssue{Session: source, CredentialDigest: sourceDigest}, "actor", now); err != nil {
		t.Fatal(err)
	}
	replacement := enterpriseSession(prefix+"-destination-session", destinationTenant, destinationMembership.ID, person, destinationConnection, now)
	replacement.CredentialID = shared.ID(prefix + "-destination-credential")
	return f, sourceDigest, source, ports.IdentitySessionSwitch{SourceCredentialDigest: sourceDigest, DestinationTenantID: destinationTenant, DestinationMembershipID: destinationMembership.ID, DestinationConnectionID: destinationConnection, DestinationSubject: "destination", DestinationRevision: 1, DestinationAuthenticatedAt: now, Replacement: ports.IdentitySessionIssue{Session: replacement, CredentialDigest: identityDigest(prefix + "-destination")}, RetryKey: prefix + "-retry", RetryPayloadHash: identityDigest(prefix + "-payload"), RetryCiphertext: "authenticated-ciphertext", Now: now}
}

func enterpriseSession(id string, tenant, membership, person, connection shared.ID, now time.Time) identity.EnterpriseSession {
	return identity.EnterpriseSession{ID: shared.ID(id), TenantID: tenant, CredentialID: shared.ID(id + "-credential"), MembershipID: membership, PersonID: person, ConnectionID: connection, Kind: identity.EnterpriseSessionKindBrowser, LineageID: shared.ID(id + "-lineage"), AuthenticatedAt: now, OriginAt: now, ExpiresAt: now.Add(time.Hour), PersonEpoch: 1, MembershipEpoch: 1, ConnectionEpoch: 1, CSRFTokenHash: identityDigest(id + "-csrf"), CreatedAt: now}
}

func seedSessionConnection(t *testing.T, f *identityFixture, tenant string, m ports.IdentityMembership, connection, subject string, now time.Time) {
	t.Helper()
	if err := f.runtimeExec(tenant, `INSERT INTO identity_connections(tenant_id,id,protocol,trust_namespace,display_name,enabled) VALUES($1,$2,'oidc',$3,'Test',true)`, tenant, connection, "https://"+connection); err != nil {
		t.Fatal(err)
	}
	if err := f.runtimeExec(tenant, `INSERT INTO identity_connection_revisions(tenant_id,connection_id,revision,settings,actor,created_at) VALUES($1,$2,1,'{}','test',$3)`, tenant, connection, now); err != nil {
		t.Fatal(err)
	}
	if err := f.runtimeExec(tenant, `INSERT INTO identity_connection_tests(tenant_id,id,connection_id,revision,state,tested_at,expires_at) VALUES($1,$2,$3,1,'passed',$4,$5)`, tenant, "test-"+connection, connection, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := f.runtimeExec(tenant, `INSERT INTO identity_authenticators(tenant_id,id,connection_id,protocol_subject,membership_id,person_id,state,approved_by,source,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'approved','test','native',$7,$7)`, tenant, "auth-"+connection, connection, subject, m.ID.String(), m.PersonID.String(), now); err != nil {
		t.Fatal(err)
	}
}
