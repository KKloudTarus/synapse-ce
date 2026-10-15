package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type userPickerHandlerFake struct {
	assignees []ports.UserChoice
	mentions  []ports.UserChoice
	assignee  int
	mention   int
	tenantID  shared.ID
}

func (f *userPickerHandlerFake) ListUserChoices(_ context.Context, tenantID, _ shared.ID, _ string, _ shared.ID, _ int) ([]ports.UserChoice, error) {
	f.assignee++
	f.tenantID = tenantID
	return f.assignees, nil
}

func (f *userPickerHandlerFake) ListMentionChoices(_ context.Context, tenantID, _ shared.ID, _ string, _ shared.ID, _ int) ([]ports.UserChoice, error) {
	f.mention++
	f.tenantID = tenantID
	return f.mentions, nil
}

type legacyUserPickerFake struct{ assignee int }

func (f *legacyUserPickerFake) ListUserChoices(_ context.Context, _ shared.ID, _ shared.ID, _ string, _ shared.ID, _ int) ([]ports.UserChoice, error) {
	f.assignee++
	return nil, nil
}

func pickerRequest(path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	ctx := context.WithValue(req.Context(), principalKey, testPrincipal("triager", "consultant", "tenant-picker"))
	return req.WithContext(ctx)
}

func TestUserPickerPurposeSelectsMentionReaderWithoutChangingDefault(t *testing.T) {
	fake := &userPickerHandlerFake{
		assignees: []ports.UserChoice{{ID: "assignee", Name: "Assignee"}},
		mentions:  []ports.UserChoice{{ID: "readonly", Name: "Read only"}},
	}
	rt := &Router{log: discardLog(), userPicker: fake}

	for _, test := range []struct {
		name         string
		path         string
		wantID       string
		wantAssignee int
		wantMention  int
	}{
		{name: "default assignee purpose", path: "/api/v1/users/picker", wantID: "assignee", wantAssignee: 1},
		{name: "explicit mention purpose", path: "/api/v1/users/picker?purpose=mention", wantID: "readonly", wantAssignee: 1, wantMention: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			rt.routes().ServeHTTP(rec, pickerRequest(test.path))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
			}
			var body struct {
				Items []ports.UserChoice `json:"items"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if len(body.Items) != 1 || body.Items[0].ID != shared.ID(test.wantID) {
				t.Fatalf("items = %+v", body.Items)
			}
			if fake.assignee != test.wantAssignee || fake.mention != test.wantMention {
				t.Fatalf("calls: assignee=%d mention=%d", fake.assignee, fake.mention)
			}
			if fake.tenantID != "tenant-picker" {
				t.Fatalf("tenant = %q", fake.tenantID)
			}
		})
	}
}

func TestUserPickerPurposeRejectsUnknownAndFailsClosedWhenMentionReaderIsUnavailable(t *testing.T) {
	legacy := &legacyUserPickerFake{}
	rt := &Router{log: discardLog(), userPicker: legacy}

	for _, test := range []struct {
		name string
		path string
		want int
	}{
		{name: "unknown purpose", path: "/api/v1/users/picker?purpose=assignee", want: http.StatusBadRequest},
		{name: "unavailable mention reader", path: "/api/v1/users/picker?purpose=mention", want: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			rt.routes().ServeHTTP(rec, pickerRequest(test.path))
			if rec.Code != test.want {
				t.Fatalf("status = %d, want %d, body=%s", rec.Code, test.want, rec.Body.String())
			}
			if legacy.assignee != 0 {
				t.Fatalf("reader must not be called: assignee=%d", legacy.assignee)
			}
		})
	}
}
