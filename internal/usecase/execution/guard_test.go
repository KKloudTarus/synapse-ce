package execution

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// --- fakes ---

type fakeEngRepo struct {
	eng *engagement.Engagement
	err error
}

func (f *fakeEngRepo) Create(context.Context, *engagement.Engagement) error { return nil }
func (f *fakeEngRepo) Update(context.Context, *engagement.Engagement) error { return nil }
func (f *fakeEngRepo) Delete(context.Context, shared.ID) error              { return nil }
func (f *fakeEngRepo) GetByID(context.Context, shared.ID) (*engagement.Engagement, error) {
	return f.eng, f.err
}
func (f *fakeEngRepo) GetByIDInTenant(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error) {
	return f.eng, f.err
}
func (f *fakeEngRepo) List(context.Context, shared.ID) ([]*engagement.Engagement, error) {
	return nil, nil
}

type fakeClock struct{ now time.Time }

func (c fakeClock) Now() time.Time { return c.now }

type fakeAudit struct{ entries []ports.AuditEntry }

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

// engAt builds an active engagement whose authorization window brackets `now`
// (or, when expired=true, sits entirely in the past), with one in-scope domain.
func engAt(now time.Time, expired bool) *engagement.Engagement {
	e, _ := engagement.New(shared.ID("eng-1"), shared.ID(""), "Acme", "Acme", now)
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	if expired {
		from, to = now.Add(-2*time.Hour), now.Add(-time.Hour)
	}
	_ = e.SetAuthorizationWindow(&from, &to, "UTC", now)
	e.Scope = engagement.Scope{
		InScope:    []engagement.Target{{Kind: engagement.TargetDomain, Value: "app.acme.io"}},
		OutOfScope: []engagement.Target{{Kind: engagement.TargetDomain, Value: "secret.acme.io"}},
	}
	return e
}

func newReq(host string) Request {
	return Request{
		Actor:        "tester",
		EngagementID: shared.ID("eng-1"),
		Action:       "recon.subfinder",
		Target:       engagement.Target{Kind: engagement.TargetDomain, Value: host},
		Metadata:     map[string]string{"engagement": "eng-1"},
	}
}

func TestNewGuardValidatesDeps(t *testing.T) {
	if _, err := NewGuard(nil, fakeClock{}, &fakeAudit{}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("nil engagements: want ErrValidation, got %v", err)
	}
	if _, err := NewGuard(&fakeEngRepo{}, nil, &fakeAudit{}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("nil clock: want ErrValidation, got %v", err)
	}
	if _, err := NewGuard(&fakeEngRepo{}, fakeClock{}, nil); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("nil audit: want ErrValidation, got %v", err)
	}
}

func TestAuthorizeAllows(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	audit := &fakeAudit{}
	g, err := NewGuard(&fakeEngRepo{eng: engAt(now, false)}, fakeClock{now}, audit)
	if err != nil {
		t.Fatal(err)
	}
	at, err := g.Authorize(context.Background(), newReq("api.acme.io")) // wildcard-free exact host in scope? no – exact "app.acme.io" only
	if !errors.Is(err, shared.ErrForbidden) {
		// "api.acme.io" is NOT in scope (only app.acme.io is), so it must be denied.
		t.Fatalf("expected out-of-scope denial for api.acme.io, got at=%v err=%v", at, err)
	}

	at, err = g.Authorize(context.Background(), newReq("app.acme.io"))
	if err != nil {
		t.Fatalf("in-scope, in-window must be allowed: %v", err)
	}
	if !at.Equal(now) {
		t.Errorf("decision time = %v, want %v", at, now)
	}
	// The last audit entry is the allow (the api.acme.io denial precedes it).
	last := audit.entries[len(audit.entries)-1]
	if last.Action != "recon.subfinder" || last.Target != "app.acme.io" {
		t.Errorf("allow audit = %+v, want action=recon.subfinder target=app.acme.io", last)
	}
	if _, isDenied := last.Metadata["reason"]; isDenied {
		t.Errorf("allow audit must not carry a deny reason: %+v", last.Metadata)
	}
}

func TestAuthorizeDeniesOutOfWindow(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	audit := &fakeAudit{}
	g, _ := NewGuard(&fakeEngRepo{eng: engAt(now, true)}, fakeClock{now}, audit)

	_, err := g.Authorize(context.Background(), newReq("app.acme.io"))
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("expired window must be forbidden, got %v", err)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(audit.entries))
	}
	e := audit.entries[0]
	if e.Action != "recon.subfinder.denied" || e.Metadata["reason"] != "expired_window" {
		t.Errorf("deny audit = %+v, want action=recon.subfinder.denied reason=expired_window", e)
	}
}

func TestAuthorizeDeniesOutOfScope(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	audit := &fakeAudit{}
	g, _ := NewGuard(&fakeEngRepo{eng: engAt(now, false)}, fakeClock{now}, audit)

	// In-window, but carved-out subdomain => out-of-scope wins.
	_, err := g.Authorize(context.Background(), newReq("secret.acme.io"))
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("out-of-scope must be forbidden, got %v", err)
	}
	e := audit.entries[len(audit.entries)-1]
	if e.Action != "recon.subfinder.denied" || e.Metadata["reason"] != "out_of_scope" {
		t.Errorf("deny audit = %+v, want action=recon.subfinder.denied reason=out_of_scope", e)
	}
}

func TestAuthorizeDeniesTerminalEngagement(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	// In-window and in-scope, but a completed/archived engagement is over: deny.
	for _, st := range []engagement.Status{engagement.StatusCompleted, engagement.StatusArchived} {
		audit := &fakeAudit{}
		eng := engAt(now, false)
		eng.Status = st
		g, _ := NewGuard(&fakeEngRepo{eng: eng}, fakeClock{now}, audit)

		if _, err := g.Authorize(context.Background(), newReq("app.acme.io")); !errors.Is(err, shared.ErrForbidden) {
			t.Errorf("status %q must be forbidden, got %v", st, err)
		}
		e := audit.entries[len(audit.entries)-1]
		if e.Action != "recon.subfinder.denied" || e.Metadata["reason"] != "engagement_inactive" {
			t.Errorf("status %q: deny audit = %+v, want reason=engagement_inactive", st, e)
		}
	}
}

func TestAuthorizeRoEDenies(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	// In-window, in-scope, active – but RoE blocks the recon tool class.
	t.Run("tool class not allowed", func(t *testing.T) {
		audit := &fakeAudit{}
		eng := engAt(now, false)
		eng.RoE = engagement.RoE{AllowedToolClasses: []engagement.ToolClass{"sca"}}
		g, _ := NewGuard(&fakeEngRepo{eng: eng}, fakeClock{now}, audit)
		if _, err := g.Authorize(context.Background(), newReq("app.acme.io")); !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("recon must be forbidden when only sca is allowed, got %v", err)
		}
		e := audit.entries[len(audit.entries)-1]
		if e.Metadata["reason"] != "tool_not_allowed" {
			t.Errorf("deny reason = %q, want tool_not_allowed", e.Metadata["reason"])
		}
	})
	t.Run("blackout window", func(t *testing.T) {
		audit := &fakeAudit{}
		eng := engAt(now, false)
		eng.RoE = engagement.RoE{Blackouts: []engagement.Blackout{{From: now.Add(-time.Hour), To: now.Add(time.Hour)}}}
		g, _ := NewGuard(&fakeEngRepo{eng: eng}, fakeClock{now}, audit)
		if _, err := g.Authorize(context.Background(), newReq("app.acme.io")); !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("must be forbidden inside a blackout, got %v", err)
		}
		e := audit.entries[len(audit.entries)-1]
		if e.Metadata["reason"] != "blackout_window" {
			t.Errorf("deny reason = %q, want blackout_window", e.Metadata["reason"])
		}
	})
}

func TestAuthorizePropagatesLoadError(t *testing.T) {
	g, _ := NewGuard(&fakeEngRepo{err: shared.ErrNotFound}, fakeClock{}, &fakeAudit{})
	if _, err := g.Authorize(context.Background(), newReq("app.acme.io")); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("want ErrNotFound propagated, got %v", err)
	}
}
