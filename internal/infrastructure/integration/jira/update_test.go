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

func TestUpdateTicketUsesExistingIssueForCloudAndDC(t *testing.T) {
	for _, cloud := range []bool{true, false} {
		t.Run(map[bool]string{true: "cloud", false: "dc"}[cloud], func(t *testing.T) {
			calls := 0
			payload := json.RawMessage(`{"fields":{"summary":"Phát hiện cần khắc phục","labels":["synapse-group"]}}`)
			a := testAdapter(t, cloud, func(r *http.Request) (*http.Response, error) {
				calls++
				prefix := "/jira/rest/api/2"
				if cloud {
					prefix = "/rest/api/3"
				}
				if r.Method != http.MethodPut || r.URL.Path != prefix+"/issue/SEC-123" {
					t.Fatalf("unexpected target: %s %s", r.Method, r.URL.Path)
				}
				body, _ := io.ReadAll(r.Body)
				if string(body) != string(payload) {
					t.Fatal("update changed approved payload")
				}
				return response(http.StatusNoContent, "", nil), nil
			})
			if err := a.UpdateTicket(context.Background(), "SEC-123", payload); err != nil || calls != 1 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestUpdateTicketRefusesUnsafeTargetsAndPayloadsBeforeHTTP(t *testing.T) {
	for _, tc := range []struct{ key, payload string }{
		{"SEC-1/../../other", `{"fields":{"summary":"safe"}}`},
		{"SEC-1", `{"fields":{"summary":"secret-token"}}`},
		{"SEC-1", `{"fields":{"project":{"key":"OTHER"}}}`},
		{"SEC-1", `{"fields":{"issuetype":{"id":"10002"}}}`},
		{"SEC-1", `{"fields":{},"update":{"comment":[{"add":{"body":"unapproved"}}]}}`},
	} {
		t.Run(tc.key+tc.payload, func(t *testing.T) {
			a := testAdapter(t, true, func(*http.Request) (*http.Response, error) {
				t.Fatal("invalid update reached provider")
				return nil, nil
			})
			if err := a.UpdateTicket(context.Background(), tc.key, json.RawMessage(tc.payload)); err == nil || strings.Contains(err.Error(), "secret-token") {
				t.Fatalf("unsafe update result: %v", err)
			}
		})
	}
}

func TestUpdateTicketKeepsLostAcknowledgementUncertainAndErrorsSafe(t *testing.T) {
	for _, tc := range []struct {
		name         string
		status       int
		transportErr error
		ambiguous    bool
	}{
		{name: "network", transportErr: errors.New("secret-token lost acknowledgement"), ambiguous: true},
		{name: "cancelled during request", transportErr: context.Canceled, ambiguous: true},
		{name: "server", status: 503, ambiguous: true},
		{name: "unexpected success", status: 200, ambiguous: true},
		{name: "permission", status: 403},
		{name: "rate limited", status: 429},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := testAdapter(t, true, func(*http.Request) (*http.Response, error) {
				if tc.transportErr != nil {
					return nil, tc.transportErr
				}
				return response(tc.status, `{"error":"secret-token"}`, nil), nil
			})
			err := a.UpdateTicket(context.Background(), "SEC-1", json.RawMessage(`{"fields":{"summary":"safe"}}`))
			var classified *ports.TicketProviderError
			if !errors.As(err, &classified) || classified.Ambiguous != tc.ambiguous || strings.Contains(err.Error(), "secret-token") {
				t.Fatalf("error=%v classified=%+v", err, classified)
			}
		})
	}
}
