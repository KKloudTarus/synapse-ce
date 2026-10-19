package httpapi

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	ticketuc "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

type observationHTTPFake struct {
	ticketWorkflow
	calls  int
	tenant shared.ID
}

func (f *observationHTTPFake) GetFindingTickets(_ context.Context, _ shared.ID, _, finding shared.ID) (ticketuc.FindingTickets, error) {
	if finding != "finding" {
		return ticketuc.FindingTickets{}, shared.ErrNotFound
	}
	return ticketuc.FindingTickets{}, nil
}
func (f *observationHTTPFake) ListTicketObservations(_ context.Context, tenant, _, _ shared.ID) (ports.TicketInboundView, error) {
	f.calls++
	f.tenant = tenant
	return ports.TicketInboundView{Comments: []ticketing.ExternalTicketComment{{ID: "comment", Body: "external literal", AuthorID: "private-provider-author"}}}, nil
}

func TestTicketObservationsRequireTenantFindingAndViewPermission(t *testing.T) {
	repo := newEngRepoFake()
	service := enguc.NewService(repo, fixedClock{t: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)}, engIDs{}, &fakeAudit{})
	if _, err := service.Create(context.Background(), enguc.CreateInput{TenantID: "tenant-a", Name: "Test", Client: "Test"}); err != nil {
		t.Fatal(err)
	}
	fake := &observationHTTPFake{}
	rt := &Router{log: discardLog(), eng: service}
	rt.SetTicketing(fake)
	for _, tc := range []struct {
		tenant, role, finding string
		code, calls           int
	}{
		{"foreign", "readonly", "finding", 404, 0},
		{"tenant-a", "agent", "finding", 403, 0},
		{"tenant-a", "mcp", "finding", 403, 0},
		{"tenant-a", "readonly", "foreign-finding", 404, 0},
		{"tenant-a", "readonly", "finding", 200, 1},
	} {
		r := httptest.NewRequest("GET", "/api/v1/engagements/eng-1/findings/"+tc.finding+"/ticket-observations", nil)
		r = r.WithContext(context.WithValue(r.Context(), principalKey, Principal{ID: "reader", Role: tc.role, TenantID: tc.tenant}))
		out := httptest.NewRecorder()
		rt.routes().ServeHTTP(out, r)
		if out.Code != tc.code || fake.calls != tc.calls {
			t.Fatalf("tenant=%s role=%s status=%d calls=%d", tc.tenant, tc.role, out.Code, fake.calls)
		}
		if out.Code == 200 && (!strings.Contains(out.Body.String(), `"origin":"external"`) || strings.Contains(out.Body.String(), "private-provider-author") || fake.tenant != "tenant-a") {
			t.Fatalf("unsafe view: %s", out.Body.String())
		}
	}
}
