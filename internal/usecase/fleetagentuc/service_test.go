package fleetagentuc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
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
	agent, agentTok, err := svc.Enrol(ctx, enrolTok, EnrolInput{Name: "agent-1", Platform: "linux"})
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if agent.TenantID != "t1" {
		t.Fatalf("agent tenant should come from the enrol token, got %q", agent.TenantID)
	}

	// The single-use enrol token cannot be used again.
	if _, _, err := svc.Enrol(ctx, enrolTok, EnrolInput{Name: "agent-2"}); !errors.Is(err, ErrUnauthenticated) {
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
	_, agentTok, err := svc.Enrol(ctx, enrolTok, EnrolInput{Name: "a"})
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
	agent, agentTok, err := svc.Enrol(ctx, enrolTok, EnrolInput{Name: "a"})
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if err := svc.Revoke(ctx, "op", "t1", agent.ID); err != nil {
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
	if _, _, err := svc.Enrol(ctx, enrolTok, EnrolInput{Name: "a"}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired enrol token must fail, got %v", err)
	}
}

func b64(s string) string { return agenttoken.B64(s) }
