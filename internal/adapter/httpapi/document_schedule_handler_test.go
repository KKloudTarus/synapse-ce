package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	documentuc "github.com/KKloudTarus/synapse-ce/internal/usecase/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type documentScheduleHTTPFake struct {
	savedTenant shared.ID
	savedActor  ports.DocumentActor
	saved       documentuc.ScheduleInput
	deleted     struct {
		tenant  shared.ID
		actor   ports.DocumentActor
		id      shared.ID
		version int
	}
	listTenant shared.ID
}

func (f *documentScheduleHTTPFake) SaveSchedule(_ context.Context, tenant shared.ID, actor ports.DocumentActor, in documentuc.ScheduleInput) (docpublish.Schedule, error) {
	f.savedTenant, f.savedActor, f.saved = tenant, actor, in
	return docpublish.Schedule{ID: in.ID, TenantID: tenant, Source: in.Source, Destination: in.Destination, IntegrationID: in.IntegrationID, EmailChannelID: in.EmailChannelID, Timezone: in.Timezone, Frequency: in.Frequency, Weekday: in.Weekday, Day: in.Day, Hour: in.Hour, Minute: in.Minute, Enabled: in.Enabled, Version: 1, NextDueAt: time.Date(2026, 10, 20, 2, 0, 0, 0, time.UTC), CreatedAt: time.Date(2026, 10, 17, 2, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 10, 17, 2, 0, 0, 0, time.UTC)}, nil
}

func (f *documentScheduleHTTPFake) ListSchedules(_ context.Context, tenant shared.ID, _ docpublish.Scope, _ shared.ID) ([]docpublish.Schedule, error) {
	f.listTenant = tenant
	return nil, nil
}

func (f *documentScheduleHTTPFake) DeleteSchedule(_ context.Context, tenant shared.ID, actor ports.DocumentActor, id shared.ID, version int) error {
	f.deleted.tenant, f.deleted.actor, f.deleted.id, f.deleted.version = tenant, actor, id, version
	return nil
}

func (*documentScheduleHTTPFake) EmailDestinations(context.Context, shared.ID, ports.DocumentActor) ([]documentuc.ScheduleEmailDestination, error) {
	return []documentuc.ScheduleEmailDestination{{ID: "mail-1", Name: "Security reports", RecipientCount: 2}}, nil
}

type documentScheduleHTTPIDs struct{}

func (documentScheduleHTTPIDs) NewID() shared.ID { return "schedule-server-id" }

type documentScheduleHistoryHTTPFake struct {
	tenant shared.ID
	id     shared.ID
}

func (f *documentScheduleHistoryHTTPFake) RunHistory(_ context.Context, tenant, id shared.ID) ([]ports.DocumentScheduleRunView, error) {
	f.tenant, f.id = tenant, id
	return []ports.DocumentScheduleRunView{{ID: "run-1", DueAt: time.Date(2026, 10, 20, 2, 0, 0, 0, time.UTC), State: docpublish.OccurrenceUncertain, ContentHash: strings.Repeat("a", 64), RemotePageID: "page-1", RemoteVersion: 2, UncertainCount: 1, UpdatedAt: time.Date(2026, 10, 20, 2, 1, 0, 0, time.UTC)}}, nil
}

func TestDocumentScheduleHandlersDeriveActorTenantAndRejectAuthorityFields(t *testing.T) {
	fake := &documentScheduleHTTPFake{}
	router := &Router{log: discardLog()}
	router.SetDocumentScheduling(fake, documentScheduleHTTPIDs{})
	valid := documentRequest(http.MethodPost, "/api/v1/document-schedules", `{"source_kind":"engagement_report","source_ref":"engagement:eng-1","scope_id":"eng-1","destination":"confluence","integration_id":"confluence-1","timezone":"Asia/Ho_Chi_Minh","frequency":"weekly","weekday":1,"hour":9,"minute":30,"enabled":true}`, "reviewer", "tenant-a")
	recorder := httptest.NewRecorder()
	router.authz(userdom.PermReview, router.saveDocumentSchedule)(recorder, valid)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if fake.savedTenant != "tenant-a" || fake.savedActor.UserID != "user-1" || fake.saved.ID != "schedule-server-id" || fake.saved.Source.Scope != docpublish.Engagement {
		t.Fatalf("server identity/source not derived: tenant=%q actor=%+v input=%+v", fake.savedTenant, fake.savedActor, fake.saved)
	}
	if strings.Contains(recorder.Body.String(), "owner_user_id") || strings.Contains(recorder.Body.String(), "actor") {
		t.Fatalf("schedule response leaked identity: %s", recorder.Body.String())
	}
	hostile := documentRequest(http.MethodPost, "/api/v1/document-schedules", `{"source_kind":"engagement_report","source_ref":"engagement:eng-1","scope_id":"eng-1","destination":"confluence","integration_id":"confluence-1","timezone":"Asia/Ho_Chi_Minh","frequency":"weekly","weekday":1,"hour":9,"minute":30,"enabled":true,"tenant_id":"tenant-b","actor":{"user_id":"attacker"}}`, "reviewer", "tenant-a")
	hostileRecorder := httptest.NewRecorder()
	router.authz(userdom.PermReview, router.saveDocumentSchedule)(hostileRecorder, hostile)
	if hostileRecorder.Code != http.StatusBadRequest {
		t.Fatalf("hostile status=%d body=%s", hostileRecorder.Code, hostileRecorder.Body.String())
	}
}

func TestDocumentScheduleHandlersRequireReviewAndPreserveCAS(t *testing.T) {
	fake := &documentScheduleHTTPFake{}
	router := &Router{log: discardLog()}
	router.SetDocumentScheduling(fake, documentScheduleHTTPIDs{})
	denied := documentRequest(http.MethodPost, "/api/v1/document-schedules", `{}`, "readonly", "tenant-a")
	deniedRecorder := httptest.NewRecorder()
	router.authz(userdom.PermReview, router.saveDocumentSchedule)(deniedRecorder, denied)
	if deniedRecorder.Code != http.StatusForbidden {
		t.Fatalf("readonly save status=%d", deniedRecorder.Code)
	}
	deleteRequest := documentRequest(http.MethodDelete, "/api/v1/document-schedules/schedule-1", `{"expected_version":4}`, "reviewer", "tenant-b")
	deleteRequest.SetPathValue("id", "schedule-1")
	deleteRecorder := httptest.NewRecorder()
	router.authz(userdom.PermReview, router.disableDocumentSchedule)(deleteRecorder, deleteRequest)
	if deleteRecorder.Code != http.StatusNoContent || fake.deleted.tenant != "tenant-b" || fake.deleted.actor.UserID != "user-1" || fake.deleted.id != "schedule-1" || fake.deleted.version != 4 {
		t.Fatalf("delete=%d values=%+v", deleteRecorder.Code, fake.deleted)
	}
	listRequest := documentRequest(http.MethodGet, "/api/v1/document-schedules?scope=project&scope_id=project-1", "", "readonly", "tenant-b")
	listRecorder := httptest.NewRecorder()
	router.authz(userdom.PermView, router.listDocumentSchedules)(listRecorder, listRequest)
	if listRecorder.Code != http.StatusOK || fake.listTenant != "tenant-b" {
		t.Fatalf("list=%d tenant=%q", listRecorder.Code, fake.listTenant)
	}
	emailRequest := documentRequest(http.MethodGet, "/api/v1/document-schedules/email-destinations", "", "reviewer", "tenant-b")
	emailRecorder := httptest.NewRecorder()
	router.authz(userdom.PermReview, router.documentScheduleEmailDestinations)(emailRecorder, emailRequest)
	if emailRecorder.Code != http.StatusOK || strings.Contains(emailRecorder.Body.String(), "recipient") && strings.Contains(emailRecorder.Body.String(), "@") {
		t.Fatalf("email destinations=%d body=%s", emailRecorder.Code, emailRecorder.Body.String())
	}
}

func TestDocumentScheduleRunsAreTenantScopedReadOnlyView(t *testing.T) {
	history := &documentScheduleHistoryHTTPFake{}
	router := &Router{log: discardLog()}
	router.SetDocumentScheduleHistory(history)
	request := documentRequest(http.MethodGet, "/api/v1/document-schedules/schedule-1/runs", "", "readonly", "tenant-a")
	request.SetPathValue("id", "schedule-1")
	recorder := httptest.NewRecorder()
	router.authz(userdom.PermView, router.documentScheduleRuns)(recorder, request)
	if recorder.Code != http.StatusOK || history.tenant != "tenant-a" || history.id != "schedule-1" {
		t.Fatalf("status=%d tenant=%q id=%q", recorder.Code, history.tenant, history.id)
	}
	for _, forbidden := range []string{"recipient", "owner", "error_code", "artifact"} {
		if strings.Contains(recorder.Body.String(), forbidden) {
			t.Fatalf("run response leaked %q: %s", forbidden, recorder.Body.String())
		}
	}
}
