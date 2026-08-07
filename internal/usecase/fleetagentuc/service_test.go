package fleetagentuc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/agenttoken"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

type fakeIDs struct{ n int }

func (g *fakeIDs) NewID() shared.ID { g.n++; return shared.ID(fmt.Sprintf("ag-%d", g.n)) }

type fakeAudit struct{ n int }

func (a *fakeAudit) Record(context.Context, ports.AuditEntry) error { a.n++; return nil }

func newSvc(t *testing.T) *Service {
	t.Helper()
	svc, err := NewService(memory.NewFleetAgentStore(), &fakeAudit{}, fakeClock{t: time.Unix(1000, 0).UTC()}, &fakeIDs{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc
}

func TestEnrolAndAuthenticate(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()

	enrolTok, err := svc.MintEnrolToken(ctx, "op", "t1", time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	agent, agentTok, _, err := svc.Enrol(ctx, enrolTok, EnrolInput{Name: "agent-1", Platform: "linux"})
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if agent.TenantID != "t1" {
		t.Fatalf("agent tenant should come from the enrol token, got %q", agent.TenantID)
	}

	// The single-use enrol token cannot be used again.
	if _, _, _, err := svc.Enrol(ctx, enrolTok, EnrolInput{Name: "agent-2"}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("re-using an enrol token must fail unauthenticated, got %v", err)
	}

	// The agent credential authenticates.
	got, err := svc.Authenticate(ctx, agentTok)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got.ID != agent.ID {
		t.Fatalf("authenticated the wrong agent: %q vs %q", got.ID, agent.ID)
	}
}

func TestAuthenticateRejectsTamperedAndMalformed(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	enrolTok, _ := svc.MintEnrolToken(ctx, "op", "t1", time.Hour)
	_, agentTok, _, err := svc.Enrol(ctx, enrolTok, EnrolInput{Name: "a"})
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}

	for _, bad := range []string{"", "garbage", "fa.only.three", agentTok + "x", "et." + strings.TrimPrefix(agentTok, "fa.")} {
		if _, err := svc.Authenticate(ctx, bad); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("malformed/tampered token %q must be unauthenticated, got %v", bad, err)
		}
	}

	// Tamper the tenant prefix: re-mint the routable parts for another tenant but keep the secret.
	kind, _, id, secret, ok := agenttoken.Parse(agentTok)
	if !ok {
		t.Fatalf("parse own token failed")
	}
	forged := kind + "." + b64("t2") + "." + b64(id) + "." + secret
	if _, err := svc.Authenticate(ctx, forged); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("cross-tenant forged token must be unauthenticated, got %v", err)
	}
}

func TestAuthenticateRevoked(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	enrolTok, _ := svc.MintEnrolToken(ctx, "op", "t1", time.Hour)
	agent, agentTok, _, err := svc.Enrol(ctx, enrolTok, EnrolInput{Name: "a"})
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if err := svc.Revoke(ctx, "op", "t1", agent.ID, "test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.Authenticate(ctx, agentTok); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked agent must return ErrRevoked, got %v", err)
	}
}

func TestExpiredEnrolTokenRejected(t *testing.T) {
	svc := newSvc(t)
	ctx := context.Background()
	enrolTok, err := svc.MintEnrolToken(ctx, "op", "t1", time.Nanosecond)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	// fakeClock is fixed, but the token expiry is now+1ns; advance the service clock past it.
	svc.clock = fakeClock{t: time.Unix(1000, 0).UTC().Add(time.Hour)}
	if _, _, _, err := svc.Enrol(ctx, enrolTok, EnrolInput{Name: "a"}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired enrol token must fail, got %v", err)
	}
}

func b64(s string) string { return agenttoken.B64(s) }

// fakeCA is an in-file ports.CertificateIssuer for #408 tests: deterministic fingerprint per agent.
type fakeCA struct{ issued int }

func (c *fakeCA) Issue(_ []byte, agentID, tenantID string, _ time.Time) ([]byte, string, error) {
	c.issued++
	return []byte("CERT:" + agentID), "fp-" + tenantID + "-" + agentID, nil
}

// fakeCanceller implements ports.WorkOrderStore; only CancelForAgent is exercised here.
type fakeCanceller struct{ cancelled int }

func (f *fakeCanceller) Issue(context.Context, *workorder.WorkOrder) (*workorder.WorkOrder, error) {
	return nil, nil
}
func (f *fakeCanceller) GetByID(context.Context, shared.ID, shared.ID) (*workorder.WorkOrder, error) {
	return nil, shared.ErrNotFound
}
func (f *fakeCanceller) Claim(context.Context, shared.ID, shared.ID, int, time.Time) ([]*workorder.WorkOrder, error) {
	return nil, nil
}
func (f *fakeCanceller) Transition(context.Context, shared.ID, shared.ID, workorder.State, string, workorder.State, time.Time) error {
	return nil
}
func (f *fakeCanceller) CancelForAgent(_ context.Context, _, _ shared.ID, _ string, _ time.Time) (int, error) {
	f.cancelled++
	return 3, nil
}

var _ ports.WorkOrderStore = (*fakeCanceller)(nil)

func TestEnrolIssuesCertificateAndAuthenticates(t *testing.T) {
	svc := newSvc(t)
	svc.SetCA(&fakeCA{})
	ctx := context.Background()
	enrolTok, _ := svc.MintEnrolToken(ctx, "op", "t1", time.Hour)
	agent, _, certPEM, err := svc.Enrol(ctx, enrolTok, EnrolInput{Name: "a", CSRPEM: []byte("csr")})
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if len(certPEM) == 0 {
		t.Fatalf("enrol with a CSR + CA must return a certificate")
	}
	if agent.Fingerprint == "" {
		t.Fatalf("agent must record its certificate fingerprint")
	}
	// Certificate identity authenticates with the matching fingerprint.
	got, err := svc.AuthenticateCertificate(ctx, "t1", agent.ID, agent.Fingerprint)
	if err != nil || got.ID != agent.ID {
		t.Fatalf("cert auth should succeed: got=%v err=%v", got, err)
	}
	// A wrong fingerprint is unauthenticated.
	if _, err := svc.AuthenticateCertificate(ctx, "t1", agent.ID, "fp-wrong"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("wrong fingerprint must be unauthenticated, got %v", err)
	}
	// A revoked agent's certificate no longer authenticates.
	if err := svc.Revoke(ctx, "op", "t1", agent.ID, "test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.AuthenticateCertificate(ctx, "t1", agent.ID, agent.Fingerprint); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked cert must return ErrRevoked, got %v", err)
	}
}

func TestEnrolWithoutCANoCertificate(t *testing.T) {
	svc := newSvc(t) // no CA wired
	ctx := context.Background()
	enrolTok, _ := svc.MintEnrolToken(ctx, "op", "t1", time.Hour)
	_, tok, certPEM, err := svc.Enrol(ctx, enrolTok, EnrolInput{Name: "a", CSRPEM: []byte("csr")})
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if tok == "" {
		t.Fatalf("bearer token should still be issued")
	}
	if len(certPEM) != 0 {
		t.Fatalf("no CA configured: no certificate should be issued")
	}
}

func TestRevokeCancelsInFlightOrders(t *testing.T) {
	svc := newSvc(t)
	canceller := &fakeCanceller{}
	svc.SetWorkOrders(canceller)
	ctx := context.Background()
	enrolTok, _ := svc.MintEnrolToken(ctx, "op", "t1", time.Hour)
	agent, _, _, err := svc.Enrol(ctx, enrolTok, EnrolInput{Name: "a"})
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if err := svc.Revoke(ctx, "op", "t1", agent.ID, "compromised"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if canceller.cancelled != 1 {
		t.Fatalf("revoke must cancel the agent's in-flight orders, calls=%d", canceller.cancelled)
	}
}

type failCA struct{}

func (failCA) Issue([]byte, string, string, time.Time) ([]byte, string, error) {
	return nil, "", errors.New("bad csr")
}

func TestBadCSRDoesNotBurnEnrolToken(t *testing.T) {
	svc := newSvc(t)
	svc.SetCA(failCA{})
	ctx := context.Background()
	enrolTok, _ := svc.MintEnrolToken(ctx, "op", "t1", time.Hour)
	// A bad CSR fails as a validation error, with no side effect (token not consumed).
	if _, _, _, err := svc.Enrol(ctx, enrolTok, EnrolInput{Name: "a", CSRPEM: []byte("bad")}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad CSR should be a validation error, got %v", err)
	}
	// The same enrol token still works afterwards (it was not burned).
	svc.SetCA(&fakeCA{})
	if _, _, _, err := svc.Enrol(ctx, enrolTok, EnrolInput{Name: "a"}); err != nil {
		t.Fatalf("enrol token must survive a failed CSR, got %v", err)
	}
}
