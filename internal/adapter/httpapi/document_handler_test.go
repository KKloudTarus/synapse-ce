package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	documentuc "github.com/KKloudTarus/synapse-ce/internal/usecase/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type documentHTTPFake struct {
	publishCalls int
	resumeCalls  int
	resumeErr    error
	tenant       shared.ID
	actor        ports.DocumentActor
	input        documentuc.PublishInput
	linksTenant  shared.ID
}

func (f *documentHTTPFake) Publish(_ context.Context, tenant shared.ID, actor ports.DocumentActor, input documentuc.PublishInput) (documentuc.ReleaseResult, error) {
	f.publishCalls++
	f.tenant, f.actor, f.input = tenant, actor, input
	return documentuc.ReleaseResult{Intent: &docpublish.Intent{ID: "intent-1", State: "pending", Action: docpublish.Create, Version: 1, CreatedAt: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)}}, nil
}

func (f *documentHTTPFake) Unpublish(context.Context, shared.ID, ports.DocumentActor, shared.ID, string) (documentuc.ReleaseResult, error) {
	return documentuc.ReleaseResult{}, nil
}

func (f *documentHTTPFake) ResumePreparedPublication(_ context.Context, tenant shared.ID, actor ports.DocumentActor, id shared.ID, version int) (docpublish.Intent, error) {
	f.resumeCalls++
	f.tenant, f.actor = tenant, actor
	if f.resumeErr != nil {
		return docpublish.Intent{}, f.resumeErr
	}
	return docpublish.Intent{ID: id, State: "pending", Action: docpublish.Create, Version: version + 1, CreatedAt: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)}, nil
}

func (f *documentHTTPFake) Links(_ context.Context, tenant shared.ID, _ docpublish.Scope, _ shared.ID) ([]docpublish.Link, error) {
	f.linksTenant = tenant
	return nil, nil
}

func (f *documentHTTPFake) Intent(context.Context, shared.ID, shared.ID) (docpublish.Intent, error) {
	return docpublish.Intent{}, nil
}

func documentRequest(method, target, body, role, tenant string) *http.Request {
	r := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	ctx := context.WithValue(shared.WithTenant(r.Context(), shared.ID(tenant)), principalKey, Principal{ID: "user-1", MembershipID: "membership-1", PersonID: "person-1", Role: role, TenantID: tenant})
	return r.WithContext(ctx)
}

func TestPublishDocumentUsesServerActorAndRejectsClientAuthority(t *testing.T) {
	fake := &documentHTTPFake{}
	router := &Router{log: discardLog(), documentPublishing: fake}

	valid := documentRequest(http.MethodPost, "/api/v1/document-publications", `{"integration_id":"connection-1","source_kind":"engagement_report","scope_id":"engagement-1","source_ref":"engagement:engagement-1","request_key":"request-1"}`, "reviewer", "tenant-a")
	validRecorder := httptest.NewRecorder()
	router.authz(userdom.PermReview, router.publishDocument)(validRecorder, valid)
	if validRecorder.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", validRecorder.Code, validRecorder.Body.String())
	}
	if fake.publishCalls != 1 || fake.tenant != "tenant-a" || fake.actor.UserID != "user-1" || fake.actor.MembershipID != "membership-1" || fake.actor.PersonID != "person-1" {
		t.Fatalf("server identity or tenant not forwarded: calls=%d tenant=%q actor=%+v", fake.publishCalls, fake.tenant, fake.actor)
	}
	if fake.input.SourceRef != "engagement:engagement-1" || fake.input.IntegrationID != "connection-1" {
		t.Fatalf("publish input=%+v", fake.input)
	}
	var response map[string]any
	if err := json.Unmarshal(validRecorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if _, found := response["actor"]; found {
		t.Fatalf("response exposed actor: %s", validRecorder.Body.String())
	}

	hostile := documentRequest(http.MethodPost, "/api/v1/document-publications", `{"integration_id":"connection-1","source_kind":"engagement_report","scope_id":"engagement-1","source_ref":"engagement:engagement-1","request_key":"request-2","actor":{"user_id":"attacker"},"tenant_id":"tenant-b"}`, "reviewer", "tenant-a")
	hostileRecorder := httptest.NewRecorder()
	router.authz(userdom.PermReview, router.publishDocument)(hostileRecorder, hostile)
	if hostileRecorder.Code != http.StatusBadRequest || fake.publishCalls != 1 {
		t.Fatalf("hostile status=%d calls=%d body=%s", hostileRecorder.Code, fake.publishCalls, hostileRecorder.Body.String())
	}
}

func TestDocumentPublishingRoutesRequireHumanReviewerAndKeepReadTenantScoped(t *testing.T) {
	fake := &documentHTTPFake{}
	router := &Router{log: discardLog(), documentPublishing: fake}
	for _, role := range []string{"readonly", "consultant", "agent", ""} {
		t.Run(role, func(t *testing.T) {
			r := documentRequest(http.MethodPost, "/api/v1/document-publications", `{}`, role, "tenant-a")
			w := httptest.NewRecorder()
			router.authz(userdom.PermReview, router.publishDocument)(w, r)
			if w.Code != http.StatusForbidden || fake.publishCalls != 0 {
				t.Fatalf("role %q status=%d calls=%d", role, w.Code, fake.publishCalls)
			}
		})
	}

	request := documentRequest(http.MethodGet, "/api/v1/engagements/engagement-1/documents", "", "readonly", "tenant-b")
	recorder := httptest.NewRecorder()
	router.authz(userdom.PermView, func(w http.ResponseWriter, r *http.Request) {
		router.documentLinks(w, r, docpublish.Engagement, "engagement-1")
	})(recorder, request)
	if recorder.Code != http.StatusOK || fake.linksTenant != "tenant-b" {
		t.Fatalf("read status=%d tenant=%q", recorder.Code, fake.linksTenant)
	}
}

func TestResumePreparedDocumentPublicationRequiresReviewPermissionAndUsesServerActor(t *testing.T) {
	fake := &documentHTTPFake{}
	router := &Router{log: discardLog(), documentPublishing: fake}
	valid := documentRequest(http.MethodPost, "/api/v1/document-publications/intent-1/resume", `{"version":4}`, "reviewer", "tenant-a")
	w := httptest.NewRecorder()
	router.authz(userdom.PermReview, router.resumePreparedDocumentPublication)(w, valid)
	if w.Code != http.StatusAccepted || fake.resumeCalls != 1 || fake.tenant != "tenant-a" || fake.actor.UserID != "user-1" {
		t.Fatalf("resume status=%d calls=%d tenant=%q actor=%+v body=%s", w.Code, fake.resumeCalls, fake.tenant, fake.actor, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["version"] != float64(5) || body["state"] != "pending" {
		t.Fatalf("resume response=%s err=%v", w.Body.String(), err)
	}

	for _, role := range []string{"readonly", "consultant", "agent", ""} {
		t.Run(role, func(t *testing.T) {
			r := documentRequest(http.MethodPost, "/api/v1/document-publications/intent-1/resume", `{"version":4}`, role, "tenant-a")
			recorder := httptest.NewRecorder()
			router.authz(userdom.PermReview, router.resumePreparedDocumentPublication)(recorder, r)
			if recorder.Code != http.StatusForbidden || fake.resumeCalls != 1 {
				t.Fatalf("role %q status=%d calls=%d", role, recorder.Code, fake.resumeCalls)
			}
		})
	}
}

func TestResumePreparedDocumentPublicationReturnsSafeAccessRefusal(t *testing.T) {
	fake := &documentHTTPFake{resumeErr: &ports.DocumentProviderError{Status: 403, Code: "public_sharing_unverifiable"}}
	router := &Router{log: discardLog(), documentPublishing: fake}
	r := documentRequest(http.MethodPost, "/api/v1/document-publications/intent-1/resume", `{"version":4}`, "reviewer", "tenant-a")
	w := httptest.NewRecorder()
	router.authz(userdom.PermReview, router.resumePreparedDocumentPublication)(w, r)
	var body errorBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusConflict || body.Error != "Destination access or restricted sharing could not be verified. Correct access before resuming." || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d body=%+v cache=%q", w.Code, body, w.Header().Get("Cache-Control"))
	}
}
