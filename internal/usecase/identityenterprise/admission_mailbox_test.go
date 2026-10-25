package identityenterprise

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type mailboxAdmissionStore struct {
	ports.IdentityAdmissionStore
	digests []string
}

func (s *mailboxAdmissionStore) GetIdentityInvitation(context.Context, shared.ID, shared.ID) (ports.IdentityInvitation, error) {
	return ports.IdentityInvitation{ID: "invitation", State: "pending", Version: 1, Recipient: "member@example.test"}, nil
}

func (s *mailboxAdmissionStore) CreateMailboxChallenge(_ context.Context, _, _ shared.ID, _ int, _ string, _ shared.ID, digest string, _, _ time.Time) error {
	s.digests = append(s.digests, digest)
	return nil
}

type mailboxDelivery struct {
	fail  bool
	codes []string
}

func (m *mailboxDelivery) SendContactVerification(_ context.Context, _ string, code string, _ shared.ID) ports.NotificationSendResult {
	m.codes = append(m.codes, code)
	if m.fail {
		return ports.NotificationSendResult{ErrorCode: "smtp_unavailable"}
	}
	return ports.NotificationSendResult{}
}

func TestMailboxDeliveryFailureIsUnavailableAndRetryIssuesFreshProof(t *testing.T) {
	store, mailer := &mailboxAdmissionStore{}, &mailboxDelivery{fail: true}
	s := &AdmissionService{store: store, mailer: mailer, clock: authClock{now: time.Now()}}
	route := ports.IdentityInvitationRoute{TenantID: "tenant", InvitationID: "invitation"}
	if err := s.SendMailboxChallenge(context.Background(), route, "subject", "person"); !errors.Is(err, authz.ErrAuthenticationUnavailable) {
		t.Fatalf("delivery failure classification = %v", err)
	}
	mailer.fail = false
	if err := s.SendMailboxChallenge(context.Background(), route, "subject", "person"); err != nil {
		t.Fatal(err)
	}
	if len(store.digests) != 2 || len(mailer.codes) != 2 || store.digests[0] == store.digests[1] {
		t.Fatal("retry did not issue two distinct mailbox proofs")
	}
	for i, code := range mailer.codes {
		if admissionDigest(code) != store.digests[i] {
			t.Fatal("delivered proof does not match stored digest")
		}
	}
}
