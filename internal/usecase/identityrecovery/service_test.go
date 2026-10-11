package identityrecovery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type recoveryClock struct{ now time.Time }

func (c recoveryClock) Now() time.Time { return c.now }

type recoveryIDs struct{ n int }

func (i *recoveryIDs) NewID() shared.ID { i.n++; return shared.ID("recovery-" + string(rune('0'+i.n))) }

type recoveryStore struct {
	activation  ports.IdentityRecoveryActivation
	consume     ports.IdentityRecoveryConsume
	policy      ports.IdentityRecoveryPolicy
	err         error
	alerts      []ports.IdentityRecoveryAlert
	claimLimits []int
	completed   []shared.ID
	recipients  []string
	delivered   bool
}

func (*recoveryStore) GetIdentityRecoveryPolicy(context.Context, shared.ID) (ports.IdentityRecoveryPolicy, error) {
	return ports.IdentityRecoveryPolicy{}, nil
}
func (s *recoveryStore) SaveIdentityRecoveryPolicy(_ context.Context, p ports.IdentityRecoveryPolicy, _ ports.IdentityAdminProof) (ports.IdentityRecoveryPolicy, error) {
	s.policy = p
	return p, nil
}
func (*recoveryStore) RehearseIdentityRecovery(context.Context, shared.ID, ports.IdentityAdminProof, time.Time) error {
	return nil
}
func (*recoveryStore) RecordIdentityRecoveryAlertTest(context.Context, shared.ID, ports.IdentityAdminProof, time.Time) error {
	return nil
}
func (s *recoveryStore) CreateIdentityRecoveryActivation(_ context.Context, a ports.IdentityRecoveryActivation, _ ports.IdentityAdminProof) error {
	s.activation = a
	return s.err
}
func (s *recoveryStore) ResolveIdentityRecoveryActivationTenant(_ context.Context, secretDigest string) (shared.ID, error) {
	if secretDigest != s.activation.SecretDigest {
		return "", shared.ErrNotFound
	}
	return s.activation.TenantID, s.err
}
func (s *recoveryStore) ConsumeIdentityRecoveryActivation(_ context.Context, c ports.IdentityRecoveryConsume) (identity.EnterpriseSession, error) {
	s.consume = c
	if s.err != nil {
		return identity.EnterpriseSession{}, s.err
	}
	v := c.Issue.Session
	v.TenantID = "tenant"
	v.MembershipID = "membership"
	v.PersonID = "person"
	return v, nil
}
func (s *recoveryStore) ClaimIdentityRecoveryAlerts(_ context.Context, _ shared.ID, _ time.Time, limit int) ([]ports.IdentityRecoveryAlert, error) {
	s.claimLimits = append(s.claimLimits, limit)
	if len(s.alerts) == 0 {
		return nil, nil
	}
	if limit > len(s.alerts) {
		limit = len(s.alerts)
	}
	claimed := s.alerts[:limit]
	s.alerts = s.alerts[limit:]
	return claimed, nil
}
func (s *recoveryStore) CompleteIdentityRecoveryAlert(ctx context.Context, _ shared.ID, id shared.ID, delivered bool, _ string, _ time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return shared.ErrValidation
	}
	s.completed = append(s.completed, id)
	s.delivered = delivered
	return nil
}
func (*recoveryStore) ListIdentityRecoveryAlerts(context.Context, shared.ID, int) ([]ports.IdentityRecoveryAlert, error) {
	return nil, nil
}
func (s *recoveryStore) IdentityRecoveryAlertRecipients(context.Context, shared.ID, shared.ID) ([]string, error) {
	if len(s.recipients) > 0 {
		return s.recipients, nil
	}
	return []string{"admin@example.test"}, nil
}

type cancelRecoveryMailer struct{ cancel context.CancelFunc }

func (m cancelRecoveryMailer) SendIdentityRecoveryAlert(context.Context, string, shared.ID) ports.NotificationSendResult {
	m.cancel()
	return ports.NotificationSendResult{StatusCode: 200}
}

func TestDeliverAlertsDoesNotLeaseLaterAlertsAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := &recoveryStore{alerts: []ports.IdentityRecoveryAlert{{ID: "first"}, {ID: "later"}}, recipients: []string{"first@example.test", "second@example.test"}}
	svc, err := NewService(st, recoveryClock{time.Now().UTC()}, &recoveryIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetAlertMailer(cancelRecoveryMailer{cancel})
	if err := svc.DeliverAlerts(ctx, "tenant", 100); !errors.Is(err, context.Canceled) {
		t.Fatalf("delivery error=%v", err)
	}
	if len(st.claimLimits) != 1 || st.claimLimits[0] != 1 || len(st.alerts) != 1 || st.alerts[0].ID != "later" {
		t.Fatalf("leased unattempted alerts: limits=%v remaining=%v", st.claimLimits, st.alerts)
	}
	if len(st.completed) != 1 || st.delivered {
		t.Fatalf("canceled partial delivery was not recorded as a failed attempt: completed=%v delivered=%v", st.completed, st.delivered)
	}
}

func freshAdmin(now time.Time) ports.IdentityAdminProof {
	return ports.IdentityAdminProof{Principal: authz.Principal{ActorID: "admin", TenantID: "tenant", Role: user.RoleAdmin, Credential: authz.Credential{Kind: authz.KindBrowserSession}, AuthenticatedAt: now}}
}

func TestCreateActivationStoresDigestAndNeverRawSecret(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st := &recoveryStore{}
	svc, _ := NewService(st, recoveryClock{now}, &recoveryIDs{})
	raw, err := svc.CreateActivation(context.Background(), "tenant", "membership", "person", freshAdmin(now))
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" || st.activation.SecretDigest == raw || st.activation.SecretDigest != digest(raw) {
		t.Fatalf("activation secret was not digest-only: %+v", st.activation)
	}
	if !st.activation.ExpiresAt.Equal(now.Add(ActivationLifetime)) {
		t.Fatal("activation expiry not bounded")
	}
}

func TestActivateAlwaysIssuesShortBreakGlassSession(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st := &recoveryStore{}
	svc, _ := NewService(st, recoveryClock{now}, &recoveryIDs{})
	out, err := svc.Activate(context.Background(), ActivateInput{Secret: "high-entropy"})
	if err != nil {
		t.Fatal(err)
	}
	if st.consume.Issue.Session.Kind != identity.EnterpriseSessionKindBreakGlass || !out.Session.ExpiresAt.Equal(now.Add(MaxSessionLifetime)) {
		t.Fatalf("issued session = %+v", out.Session)
	}
	if st.consume.SecretDigest != digest("high-entropy") {
		t.Fatal("raw activation reached store")
	}
}

func TestConfigureDoesNotTrustCallerReadinessFields(t *testing.T) {
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	st := &recoveryStore{}
	svc, _ := NewService(st, recoveryClock{now}, &recoveryIDs{})
	_, err := svc.Configure(context.Background(), ports.IdentityRecoveryPolicy{TenantID: "tenant", Organization: authz.OrganizationPolicy{Requirement: authz.SSORequired}, AlertConfigured: true, LastRehearsedAt: now}, freshAdmin(now))
	if err != nil {
		t.Fatal(err)
	}
	if !st.policy.LastRehearsedAt.IsZero() || st.policy.AlertConfigured {
		t.Fatalf("caller readiness reached store: %+v", st.policy)
	}
}
