package jira

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTransitionTicketIncludesLiteralCommentForCloudAndDC(t *testing.T) {
	for _, cloud := range []bool{true, false} {
		t.Run(map[bool]string{true: "cloud", false: "dc"}[cloud], func(t *testing.T) {
			calls := 0
			a := testAdapter(t, cloud, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/issue/SEC-9/transitions") {
					t.Fatalf("unexpected transition: %s %s", r.Method, r.URL.Path)
				}
				body, _ := io.ReadAll(r.Body)
				var envelope struct {
					Transition map[string]string `json:"transition"`
					Update     struct {
						Comment []struct {
							Add struct {
								Body json.RawMessage `json:"body"`
							} `json:"add"`
						} `json:"comment"`
					} `json:"update"`
				}
				if json.Unmarshal(body, &envelope) != nil || envelope.Transition["id"] != "31" || len(envelope.Update.Comment) != 1 {
					t.Fatalf("invalid transition body: %s", body)
				}
				comment := envelope.Update.Comment[0].Add.Body
				if !strings.Contains(string(comment), "Đã khắc phục") || strings.Contains(string(comment), `"type":"mention"`) {
					t.Fatalf("unsafe/missing comment: %s", comment)
				}
				if cloud != strings.HasPrefix(string(comment), "{") {
					t.Fatalf("wrong comment representation: %s", comment)
				}
				return response(204, "", nil), nil
			})
			if err := a.TransitionTicket(context.Background(), "SEC-9", "31", "Đã khắc phục [~admin] {panel}"); err != nil || calls != 1 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestTransitionRefusesSecretsAndRetainsUncertainWrites(t *testing.T) {
	a := testAdapter(t, false, func(*http.Request) (*http.Response, error) {
		t.Fatal("secret reached provider")
		return nil, nil
	})
	if err := a.TransitionTicket(context.Background(), "SEC-1", "31", "secret-token"); err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("secret result: %v", err)
	}
	a = testAdapter(t, true, func(*http.Request) (*http.Response, error) {
		return nil, errors.New("secret-token lost acknowledgement")
	})
	err := a.TransitionTicket(context.Background(), "SEC-1", "31", "Resolved")
	var classified *ports.TicketProviderError
	if !errors.As(err, &classified) || !classified.Ambiguous || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("lost acknowledgement: %v", err)
	}
}

func TestGetTicketUsesStatusCategoryAndNeverResolutionAsState(t *testing.T) {
	for _, tc := range []struct{ category, resolution string }{
		{"new", `{"name":"Fixed"}`},
		{"indeterminate", `{"name":"Unresolved"}`},
		{"done", "null"},
	} {
		t.Run(tc.category, func(t *testing.T) {
			a := testAdapter(t, true, func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet || r.URL.Query().Get("fields") != "status,updated,resolution,created,creator" || r.URL.Query().Get("expand") != "changelog" {
					t.Fatal("unexpected read")
				}
				return response(200, `{"key":"SEC-1","fields":{"updated":"2026-10-17T11:11:11.123+0700","status":{"statusCategory":{"key":"`+tc.category+`"}},"resolution":`+tc.resolution+`}}`, nil), nil
			})
			observation, err := a.GetTicket(context.Background(), "SEC-1")
			if err != nil || observation.StatusCategory != tc.category || observation.UpdatedAt.IsZero() || observation.Deleted {
				t.Fatalf("observation=%+v err=%v", observation, err)
			}
		})
	}
}

func TestGetTicketMarks404AndRejectsMalformedOrUnsafeFacts(t *testing.T) {
	for _, tc := range []struct {
		status  int
		body    string
		deleted bool
		wantErr bool
	}{
		{404, `{}`, true, false},
		{403, `{}`, false, true},
		{200, `{"key":"OTHER-1"}`, false, true},
		{200, `{"key":"SEC-1","fields":{"updated":"2026-10-17T00:00:00Z","status":{"statusCategory":{"key":"resolved"}}}}`, false, true},
		{200, `{"key":"SEC-1","fields":{"updated":"bad","status":{"statusCategory":{"key":"done"}}}}`, false, true},
		{200, `{"key":"SEC-1","fields":{"updated":"2026-10-17T00:00:00Z","status":{"statusCategory":{"key":"done"}},"resolution":{"name":"secret-token"}}}`, false, true},
	} {
		a := testAdapter(t, false, func(*http.Request) (*http.Response, error) { return response(tc.status, tc.body, nil), nil })
		got, err := a.GetTicket(context.Background(), "SEC-1")
		if (err != nil) != tc.wantErr || got.Deleted != tc.deleted || err != nil && strings.Contains(err.Error(), "secret-token") {
			t.Fatalf("observation=%+v err=%v", got, err)
		}
	}
}

func TestGetTicketAttributesStatusChangeInsteadOfLatestComment(t *testing.T) {
	for _, cloud := range []bool{true, false} {
		a := testAdapter(t, cloud, func(r *http.Request) (*http.Response, error) {
			return response(200, `{"key":"SEC-1","fields":{"updated":"2026-10-17T10:00:00Z","status":{"id":"100","statusCategory":{"key":"done"}}},"changelog":{"total":300,"histories":[{"created":"2026-10-17T10:00:00Z","author":{"accountId":"human-commenter","name":"human-commenter"},"items":[{"field":"comment"}]},{"created":"2026-10-17T09:00:00Z","author":{"accountId":"integration-cloud","name":"integration-dc"},"items":[{"fieldId":"status","to":"100"}]}]}}`, nil), nil
		})
		out, err := a.GetTicket(context.Background(), "SEC-1")
		want := "integration-dc"
		if cloud {
			want = "integration-cloud"
		}
		if err != nil || out.AuthorID != want || out.StatusChangedAt.Format("15:04") != "09:00" {
			t.Fatalf("observation=%+v err=%v", out, err)
		}
	}
}

func TestGetTicketDefersUnknownOrAmbiguousStatusAuthor(t *testing.T) {
	for _, history := range []string{
		`{"total":300,"histories":[{"created":"2026-10-17T10:00:00Z","author":{"accountId":"commenter"},"items":[{"field":"comment"}]}]}`,
		`{"total":1,"histories":[{"created":"2026-10-17T09:00:00Z","author":{"accountId":"user"},"items":[{"field":"status","to":"different-status"}]}]}`,
		`{"total":2,"histories":[{"created":"bad","author":{"accountId":"user"},"items":[{"field":"status","to":"100"}]},{"created":"2026-10-17T09:00:00Z","author":{"accountId":"older"},"items":[{"field":"status","to":"100"}]}]}`,
	} {
		a := testAdapter(t, true, func(*http.Request) (*http.Response, error) {
			return response(200, `{"key":"SEC-1","fields":{"updated":"2026-10-17T10:00:00Z","status":{"id":"100","statusCategory":{"key":"done"}}},"changelog":`+history+`}`, nil), nil
		})
		out, err := a.GetTicket(context.Background(), "SEC-1")
		if err != nil || out.AuthorID != "" || out.StatusCategory != "done" {
			t.Fatalf("observation=%+v err=%v", out, err)
		}
	}
}

func TestGetTicketUsesCreatorOnlyWhenNoHistoryExists(t *testing.T) {
	a := testAdapter(t, true, func(*http.Request) (*http.Response, error) {
		return response(200, `{"key":"SEC-1","fields":{"created":"2026-10-17T09:00:00Z","updated":"2026-10-17T09:00:00Z","creator":{"accountId":"integration"},"status":{"id":"100","statusCategory":{"key":"done"}}},"changelog":{"total":0,"histories":[]}}`, nil), nil
	})
	out, err := a.GetTicket(context.Background(), "SEC-1")
	if err != nil || out.AuthorID != "integration" || out.StatusChangedAt.IsZero() {
		t.Fatalf("observation=%+v err=%v", out, err)
	}
}
