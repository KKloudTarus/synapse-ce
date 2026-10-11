package identitysessions

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type testClock struct{ now time.Time }

func (c testClock) Now() time.Time { return c.now }

type testIDs struct{ n int }

func (g *testIDs) NewID() shared.ID { g.n++; return shared.ID("id-" + string(rune('0'+g.n))) }

type testProtector struct{}

func (testProtector) Seal(_ context.Context, p, a []byte) (string, error) {
	return string(a) + "|" + string(p), nil
}
func (testProtector) Open(_ context.Context, c string, a []byte) ([]byte, error) {
	p := string(a) + "|"
	if len(c) < len(p) || c[:len(p)] != p {
		return nil, errors.New("bad aad")
	}
	return []byte(c[len(p):]), nil
}

type testStore struct {
	auth     ports.IdentitySessionAuthentication
	switched bool
	rotated  ports.IdentitySessionIssue
	replay   ports.IdentitySessionSwitchResult
	replayed ports.IdentitySessionSwitchReplay
}

func (s *testStore) AuthenticateEnterpriseSession(context.Context, string, time.Time) (ports.IdentitySessionAuthentication, error) {
	return s.auth, nil
}
func (*testStore) CreateEnterpriseSession(context.Context, ports.IdentitySessionIssue, string, time.Time) error {
	return nil
}
func (s *testStore) RotateEnterpriseSession(_ context.Context, _ string, issue ports.IdentitySessionIssue, _ string, _ time.Time) error {
	s.rotated = issue
	return nil
}
func (*testStore) LogoutEnterpriseSession(context.Context, string, string, time.Time) error {
	return nil
}
func (s *testStore) SwitchEnterpriseSession(_ context.Context, c ports.IdentitySessionSwitch, _ string) (ports.IdentitySessionSwitchResult, error) {
	s.switched = true
	return ports.IdentitySessionSwitchResult{Session: c.Replacement.Session}, nil
}
func (s *testStore) ReplayEnterpriseSessionSwitch(_ context.Context, replay ports.IdentitySessionSwitchReplay) (ports.IdentitySessionSwitchResult, error) {
	s.replayed = replay
	return s.replay, nil
}
func (*testStore) CleanupEnterpriseSessionRetries(context.Context, shared.ID, time.Time, int) (int, error) {
	return 0, nil
}

type failingProof struct{}

func (failingProof) VerifyDestinationProof(context.Context, shared.ID, shared.ID, shared.ID, string, int, time.Time) error {
	return errors.New("no proof")
}

func TestAuthenticateRejectsCSRFAfterAuthoritativeSessionRead(t *testing.T) {
	now := time.Now().UTC()
	st := &testStore{auth: ports.IdentitySessionAuthentication{Session: identity.EnterpriseSession{CSRFTokenHash: digest("right")}}}
	svc, err := NewService(st, failingProof{}, testProtector{}, testClock{now}, &testIDs{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Authenticate(context.Background(), "token", "wrong", true); !errors.Is(err, authz.ErrCSRFInvalid) {
		t.Fatalf("CSRF error=%v", err)
	}
}

func TestSwitchProofFailureDoesNotCallStore(t *testing.T) {
	now := time.Now().UTC()
	st := &testStore{}
	svc, _ := NewService(st, failingProof{}, testProtector{}, testClock{now}, &testIDs{})
	_, err := svc.Switch(context.Background(), SwitchInput{SourceToken: "source", DestinationTenantID: "b", DestinationMembershipID: "m", DestinationConnectionID: "c", DestinationSubject: "subject", DestinationRevision: 1, PersonID: "p", Kind: identity.EnterpriseSessionKindBrowser, ExpiresAt: now.Add(time.Hour), PersonEpoch: 1, MembershipEpoch: 1, ConnectionEpoch: 1, RetryKey: "key", RetryPayload: "payload"}, "actor")
	if err == nil || st.switched {
		t.Fatalf("proof failure switched=%v err=%v", st.switched, err)
	}
}

func TestRotatePreservesOriginAndUpstreamAuthenticationTime(t *testing.T) {
	now := time.Now().UTC()
	earlier := now.Add(-time.Hour)
	st := &testStore{}
	svc, _ := NewService(st, failingProof{}, testProtector{}, testClock{now}, &testIDs{})
	previous := identity.EnterpriseSession{ID: "old", TenantID: "t", CredentialID: "oldc", MembershipID: "m", PersonID: "p", ConnectionID: "conn", ConnectionEpoch: 1, Kind: identity.EnterpriseSessionKindBrowser, LineageID: "lineage", AuthenticatedAt: earlier, OriginAt: earlier, ExpiresAt: now.Add(time.Hour), PersonEpoch: 1, MembershipEpoch: 1, CSRFTokenHash: "old", CreatedAt: earlier}
	got, err := svc.Rotate(context.Background(), "source", previous, "actor", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if st.rotated.Session.OriginAt != earlier || st.rotated.Session.AuthenticatedAt != earlier || st.rotated.Session.LineageID != previous.LineageID || got.Session.RotatedFromSessionID != previous.ID {
		t.Fatalf("rotation lost immutable lineage: %+v", st.rotated.Session)
	}
}

func TestReplayUsesSourceBoundAADAndCSRFProof(t *testing.T) {
	now := time.Now().UTC()
	sourceDigest := digest("source")
	payloadHash := digest("payload")
	stored := ports.IdentitySessionSwitchResult{Session: identity.EnterpriseSession{ID: "replacement"}, RetryCiphertext: switchReplayAAD(sourceDigest, "key", payloadHash) + "|token\ncsrf"}
	st := &testStore{replay: stored}
	svc, err := NewService(st, failingProof{}, testProtector{}, testClock{now}, &testIDs{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.Replay(context.Background(), ReplayInput{SourceToken: "source", SourceCSRFToken: "source-csrf", RetryKey: "key", RetryPayload: "payload"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "token" || got.CSRFToken != "csrf" || st.replayed.SourceCredentialDigest != sourceDigest || st.replayed.SourceCSRFTokenHash != digest("source-csrf") {
		t.Fatalf("replay result=%+v command=%+v", got, st.replayed)
	}
}

func TestReplayRejectsOversizedLocatorBeforeStore(t *testing.T) {
	now := time.Now().UTC()
	st := &testStore{}
	svc, _ := NewService(st, failingProof{}, testProtector{}, testClock{now}, &testIDs{})
	if _, err := svc.Replay(context.Background(), ReplayInput{SourceToken: "source", SourceCSRFToken: "csrf", RetryKey: string(make([]byte, maxSwitchRetryKeyLength+1)), RetryPayload: "payload"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversized replay key error=%v", err)
	}
	if st.replayed.SourceCredentialDigest != "" {
		t.Fatal("store received invalid replay locator")
	}
}
