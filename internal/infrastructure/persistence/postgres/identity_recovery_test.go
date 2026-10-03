package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	identityrecovery "github.com/KKloudTarus/synapse-ce/internal/usecase/identityrecovery"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type recoveryPostgresClock struct{ now time.Time }

func (c *recoveryPostgresClock) Now() time.Time { return c.now }

type recoveryPostgresIDs struct{ n int }

func (i *recoveryPostgresIDs) NewID() shared.ID {
	i.n++
	return shared.ID("recovery-pg-" + string(rune('0'+i.n)))
}

type recoveryPostgresMailer struct {
	result ports.NotificationSendResult
	sent   int
}

func (m *recoveryPostgresMailer) SendIdentityRecoveryAlert(_ context.Context, _ string, _ shared.ID) ports.NotificationSendResult {
	m.sent++
	return m.result
}

func TestIdentityRecoveryReadinessAndSingleUseActivation(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	tenant := shared.ID("recovery")
	f.tenants(t, tenant.String())
	f.declare(t, tenant.String())
	person := f.newPerson(t, "recovery-person")
	m, err := f.store.AddMembership(ctx, tenant, person, "Admin", "admin", "platform", now)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionConnection(t, f, tenant.String(), m, "recovery-conn", "recovery-subject", now)
	proof := bootstrapConnectionProof(tenant.String(), now)
	// Required policy refuses caller-supplied readiness until server operations persist it.
	var policyVersion int
	if err := f.admin.QueryRow(ctx, `SELECT version FROM identity_policies WHERE tenant_id=$1`, tenant.String()).Scan(&policyVersion); err != nil {
		t.Fatal(err)
	}
	policy := ports.IdentityRecoveryPolicy{TenantID: tenant, Organization: authz.OrganizationPolicy{Requirement: authz.SSORequired}, ExpectedVersion: policyVersion, UpdatedAt: now}
	if _, err = f.store.SaveIdentityRecoveryPolicy(ctx, policy, proof); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("required without evidence=%v", err)
	}
	if err = f.store.RehearseIdentityRecovery(ctx, tenant, proof, now); err != nil {
		t.Fatal(err)
	}
	if err = f.store.RecordIdentityRecoveryAlertTest(ctx, tenant, proof, now); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.SaveIdentityRecoveryPolicy(ctx, policy, proof); err != nil {
		t.Fatal(err)
	}

	activation := ports.IdentityRecoveryActivation{ID: "activation", TenantID: tenant, MembershipID: m.ID, PersonID: person, SecretDigest: identityDigest("one-use"), CreatedAt: now, ExpiresAt: now.Add(time.Hour), CreatedBy: "operator"}
	if err = f.store.CreateIdentityRecoveryActivation(ctx, activation, proof); err != nil {
		t.Fatal(err)
	}
	consume := func(id string) ports.IdentityRecoveryConsume {
		v := identity.EnterpriseSession{ID: shared.ID(id), CredentialID: shared.ID(id + "-credential"), Kind: identity.EnterpriseSessionKindBreakGlass, LineageID: shared.ID(id + "-lineage"), AuthenticatedAt: now, OriginAt: now, ExpiresAt: now.Add(10 * time.Minute), CSRFTokenHash: identityDigest(id + "-csrf"), CreatedAt: now}
		return ports.IdentityRecoveryConsume{SecretDigest: activation.SecretDigest, Issue: ports.IdentitySessionIssue{Session: v, CredentialDigest: identityDigest(id + "-token")}, Actor: "recovery", Now: now}
	}
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = f.store.ConsumeIdentityRecoveryActivation(ctx, consume("session-"+string(rune('a'+i))))
		}(i)
	}
	wg.Wait()
	success := 0
	for _, err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("single-use successes=%d errors=%v", success, results)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_recovery_alerts WHERE tenant_id=$1 AND state='pending'`, tenant.String()); n != 1 {
		t.Fatalf("retained alert obligations=%d", n)
	}
	alerts, err := f.store.ClaimIdentityRecoveryAlerts(ctx, tenant, now, 10)
	if err != nil || len(alerts) != 1 {
		t.Fatalf("claim=%v err=%v", alerts, err)
	}
	again, err := f.store.ClaimIdentityRecoveryAlerts(ctx, tenant, now, 10)
	if err != nil || len(again) != 0 {
		t.Fatalf("lease claim=%v err=%v", again, err)
	}
	if err = f.store.CompleteIdentityRecoveryAlert(ctx, tenant, alerts[0].ID, false, "smtp down", now); err != nil {
		t.Fatal(err)
	}
	listed, err := f.store.ListIdentityRecoveryAlerts(ctx, tenant, 10)
	if err != nil || len(listed) != 1 || listed[0].Attempts != 1 || listed[0].State != "pending" {
		t.Fatalf("alert status=%+v err=%v", listed, err)
	}
}

func TestIdentityRecoveryActivationAuditFaultRollsBackAtomically(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	tenant := shared.ID("recovery-audit-fault")
	f.tenants(t, tenant.String())
	f.declare(t, tenant.String())
	person := f.newPerson(t, "recovery-audit-person")
	m, err := f.store.AddMembership(ctx, tenant, person, "Admin", "admin", "platform", now)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionConnection(t, f, tenant.String(), m, "recovery-audit-conn", "recovery-audit-subject", now)
	proof := bootstrapConnectionProof(tenant.String(), now)
	if err = f.store.RehearseIdentityRecovery(ctx, tenant, proof, now); err != nil {
		t.Fatal(err)
	}
	if err = f.store.RecordIdentityRecoveryAlertTest(ctx, tenant, proof, now); err != nil {
		t.Fatal(err)
	}
	var version int
	if err = f.admin.QueryRow(ctx, `SELECT version FROM identity_policies WHERE tenant_id=$1`, tenant.String()).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.SaveIdentityRecoveryPolicy(ctx, ports.IdentityRecoveryPolicy{TenantID: tenant, Organization: authz.OrganizationPolicy{Requirement: authz.SSORequired}, ExpectedVersion: version, UpdatedAt: now}, proof); err != nil {
		t.Fatal(err)
	}
	activation := ports.IdentityRecoveryActivation{ID: "audit-fault-activation", TenantID: tenant, MembershipID: m.ID, PersonID: person, SecretDigest: identityDigest("audit-fault-secret"), CreatedAt: now, ExpiresAt: now.Add(time.Hour), CreatedBy: "operator"}
	if err = f.store.CreateIdentityRecoveryActivation(ctx, activation, proof); err != nil {
		t.Fatal(err)
	}
	consume := ports.IdentityRecoveryConsume{SecretDigest: activation.SecretDigest, Issue: ports.IdentitySessionIssue{Session: identity.EnterpriseSession{ID: "audit-fault-session", CredentialID: "audit-fault-credential", Kind: identity.EnterpriseSessionKindBreakGlass, LineageID: "audit-fault-lineage", AuthenticatedAt: now, OriginAt: now, ExpiresAt: now.Add(10 * time.Minute), CSRFTokenHash: identityDigest("audit-fault-csrf"), CreatedAt: now}, CredentialDigest: identityDigest("audit-fault-token")}, Actor: "recovery", Now: now}
	f.exec(t, `CREATE FUNCTION test_fail_recovery_activation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = 'identity.recovery_activated' THEN RAISE EXCEPTION 'injected recovery audit fault'; END IF; RETURN NEW; END $$`)
	f.exec(t, `CREATE TRIGGER test_fail_recovery_activation_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION test_fail_recovery_activation_audit()`)
	t.Cleanup(func() { f.exec(t, `DROP TRIGGER IF EXISTS test_fail_recovery_activation_audit ON audit_log`) })
	if _, err = f.store.ConsumeIdentityRecoveryActivation(ctx, consume); err == nil {
		t.Fatal("recovery activation committed despite audit fault")
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_sessions WHERE tenant_id=$1 AND id=$2`, tenant.String(), consume.Issue.Session.ID.String()); n != 0 {
		t.Fatalf("session committed without audit: %d", n)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_recovery_activations WHERE tenant_id=$1 AND id=$2 AND consumed_at IS NOT NULL`, tenant.String(), activation.ID.String()); n != 0 {
		t.Fatalf("activation consumed despite audit fault: %d", n)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_recovery_alerts WHERE tenant_id=$1 AND session_id=$2`, tenant.String(), consume.Issue.Session.ID.String()); n != 0 {
		t.Fatalf("alert obligation committed without audit: %d", n)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='identity.recovery_activated' AND target=$2`, tenant.String(), consume.Issue.Session.ID.String()); n != 0 {
		t.Fatalf("activation audit unexpectedly persisted: %d", n)
	}
}

func TestIdentityRecoveryAlertPersistsAcrossRestartAndNeverStoresRawSecret(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	tenant := shared.ID("recovery-alert-restart")
	f.tenants(t, tenant.String())
	f.declare(t, tenant.String())
	person := f.newPerson(t, "recovery-alert-person")
	m, err := f.store.AddMembership(ctx, tenant, person, "Admin", "admin", "platform", now)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionConnection(t, f, tenant.String(), m, "recovery-alert-conn", "recovery-alert-subject", now)
	if err = f.runtimeExec(tenant.String(), `INSERT INTO user_contacts(tenant_id,id,user_id,kind,value,source,verified_at,created_at,updated_at) VALUES($1,'recovery-alert-contact',$2,'email','admin@example.test','manual',$3,$3,$3)`, tenant.String(), m.LegacyUserID.String(), now); err != nil {
		t.Fatal(err)
	}
	proof := bootstrapConnectionProof(tenant.String(), now)
	if err = f.store.RehearseIdentityRecovery(ctx, tenant, proof, now); err != nil {
		t.Fatal(err)
	}
	if err = f.store.RecordIdentityRecoveryAlertTest(ctx, tenant, proof, now); err != nil {
		t.Fatal(err)
	}
	var version int
	if err = f.admin.QueryRow(ctx, `SELECT version FROM identity_policies WHERE tenant_id=$1`, tenant.String()).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.SaveIdentityRecoveryPolicy(ctx, ports.IdentityRecoveryPolicy{TenantID: tenant, Organization: authz.OrganizationPolicy{Requirement: authz.SSORequired}, ExpectedVersion: version, UpdatedAt: now}, proof); err != nil {
		t.Fatal(err)
	}
	clock := &recoveryPostgresClock{now: now}
	service, err := identityrecovery.NewService(f.store, clock, &recoveryPostgresIDs{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := service.CreateActivation(ctx, tenant, m.ID, person, proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Activate(ctx, identityrecovery.ActivateInput{Secret: raw}); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		name  string
		query string
	}{
		{"activations", `SELECT count(*) FROM identity_recovery_activations WHERE secret_digest=$1`},
		{"alerts", `SELECT count(*) FROM identity_recovery_alerts WHERE id=$1 OR session_id=$1 OR last_error=$1`},
		{"audit", `SELECT count(*) FROM audit_log WHERE actor=$1 OR target=$1 OR metadata::text LIKE '%' || $1 || '%'`},
		{"jobs", `SELECT count(*) FROM jobs WHERE convert_from(payload,'UTF8') LIKE '%' || $1 || '%'`},
		{"notification outbox", `SELECT count(*) FROM notification_events WHERE data::text LIKE '%' || $1 || '%'`},
	} {
		if n := f.adminCount(t, check.query, raw); n != 0 {
			t.Fatalf("raw recovery secret persisted in %s: %d", check.name, n)
		}
	}
	failing := &recoveryPostgresMailer{result: ports.NotificationSendResult{StatusCode: 503, ErrorCode: "smtp-down", Retryable: true}}
	service.SetAlertMailer(failing)
	if err = service.DeliverAlerts(ctx, tenant, 10); err != nil {
		t.Fatal(err)
	}
	alerts, err := f.store.ListIdentityRecoveryAlerts(ctx, tenant, 10)
	if err != nil || len(alerts) != 1 || alerts[0].State != "pending" || alerts[0].Attempts != 1 || failing.sent != 1 {
		t.Fatalf("failed delivery status=%+v sent=%d err=%v", alerts, failing.sent, err)
	}
	clock.now = alerts[0].NextAttemptAt
	restartedStore, err := NewIdentityFoundationStore(f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := identityrecovery.NewService(restartedStore, clock, &recoveryPostgresIDs{})
	if err != nil {
		t.Fatal(err)
	}
	success := &recoveryPostgresMailer{result: ports.NotificationSendResult{StatusCode: 202}}
	restarted.SetAlertMailer(success)
	if err = restarted.DeliverAlerts(ctx, tenant, 10); err != nil {
		t.Fatal(err)
	}
	alerts, err = restartedStore.ListIdentityRecoveryAlerts(ctx, tenant, 10)
	if err != nil || len(alerts) != 1 || alerts[0].State != "delivered" || alerts[0].Attempts != 2 || success.sent != 1 {
		t.Fatalf("restarted delivery status=%+v sent=%d err=%v", alerts, success.sent, err)
	}
}
