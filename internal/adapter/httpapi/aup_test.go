package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aup"
	aupuc "github.com/KKloudTarus/synapse-ce/internal/usecase/aup"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// fakeAUPStore / fakeAudit keep adapter tests free of infrastructure imports
// (preserves the dependency rule).
type fakeAUPStore struct{ accepted map[string]aup.Acceptance }

func newFakeAUPStore() *fakeAUPStore { return &fakeAUPStore{accepted: map[string]aup.Acceptance{}} }

func (f *fakeAUPStore) Accepted(_ context.Context, v string) (bool, error) {
	_, ok := f.accepted[v]
	return ok, nil
}
func (f *fakeAUPStore) Save(_ context.Context, a aup.Acceptance) error {
	f.accepted[a.Version] = a
	return nil
}

type fakeAudit struct{ entries []ports.AuditEntry }

func (f *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	f.entries = append(f.entries, e)
	return nil
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newTestAUP(store ports.AUPStore, audit ports.AuditLogger) *aupuc.Service {
	return aupuc.NewService(store, audit, fixedClock{t: time.Unix(0, 0).UTC()}, "1.0")
}

func TestRequireAUPGate(t *testing.T) {
	store := newFakeAUPStore()
	rt := &Router{log: discardLog(), aup: newTestAUP(store, &fakeAudit{})}
	exempt := map[string]bool{"/api/v1/aup": true}

	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	h := rt.requireAUP(exempt, next)

	// exempt path passes regardless of acceptance
	nextCalled = false
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/aup", nil))
	if !nextCalled {
		t.Fatal("exempt path should pass through")
	}

	// protected path blocked when not accepted
	nextCalled = false
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/engagements", nil))
	if rec.Code != http.StatusForbidden || nextCalled {
		t.Fatalf("want 403 and no next, got code=%d next=%v", rec.Code, nextCalled)
	}

	// accept, then protected path passes
	store.accepted["1.0"] = aup.Acceptance{Version: "1.0"}
	nextCalled = false
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/engagements", nil))
	if rec.Code != http.StatusOK || !nextCalled {
		t.Fatalf("want 200 and next, got code=%d next=%v", rec.Code, nextCalled)
	}
}

func aupRequestWithPrincipal(body string, p HumanPrincipal) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/aup/accept", strings.NewReader(body))
	return req.WithContext(context.WithValue(req.Context(), principalKey, p))
}

func TestAcceptAUPHandler(t *testing.T) {
	store := newFakeAUPStore()
	audit := &fakeAudit{}
	rt := &Router{log: discardLog(), aup: newTestAUP(store, audit)}

	// Missing principal must not be silently attributed to the bootstrap operator.
	rec := httptest.NewRecorder()
	rt.acceptAUP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/aup/accept", strings.NewReader(`{"version":"1.0"}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing principal: want 401, got %d", rec.Code)
	}
	if len(audit.entries) != 0 || len(store.accepted) != 0 {
		t.Fatalf("missing principal mutated AUP state: audit=%+v accepted=%+v", audit.entries, store.accepted)
	}

	operator := HumanPrincipal{ID: PrincipalOperator, Name: "Operator", Role: "admin"}

	// wrong version → 400 validation, with an explicitly authenticated actor
	rec = httptest.NewRecorder()
	rt.acceptAUP(rec, aupRequestWithPrincipal(`{"version":"9.9"}`, operator))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong version: want 400, got %d", rec.Code)
	}

	// correct version → 200 + recorded + audited
	rec = httptest.NewRecorder()
	rt.acceptAUP(rec, aupRequestWithPrincipal(`{"version":"1.0"}`, operator))
	if rec.Code != http.StatusOK {
		t.Fatalf("correct version: want 200, got %d", rec.Code)
	}
	if _, ok := store.accepted["1.0"]; !ok {
		t.Fatal("acceptance was not recorded in the store")
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "aup.accept" || audit.entries[0].Actor != PrincipalOperator {
		t.Fatalf("want one explicitly attributed aup.accept audit entry, got %+v", audit.entries)
	}
}
