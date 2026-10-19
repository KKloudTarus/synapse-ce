package jira

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestWebhookCapabilityRefusesOlderOrUnknownDCBeforeIdentity(t *testing.T) {
	for _, body := range []string{`{}`, `{"versionNumbers":[10,7,0],"deploymentType":"Data Center"}`, `{"versionNumbers":[11,2,9],"deploymentType":"Data Center"}`, `{"versionNumbers":[11,3,0],"deploymentType":"Cloud"}`} {
		calls := 0
		a := testAdapter(t, false, func(r *http.Request) (*http.Response, error) {
			calls++
			if !strings.HasSuffix(r.URL.Path, "/serverInfo") {
				t.Fatal("unsupported server reached identity request")
			}
			return response(200, body, nil), nil
		})
		if _, err := a.TicketWebhookPrincipal(context.Background()); err == nil || calls != 1 {
			t.Fatalf("unsupported capability: calls=%d err=%v", calls, err)
		}
	}
}

func TestWebhookCapabilityUsesAuthenticatedCloudAndSupportedDCIdentity(t *testing.T) {
	for _, cloud := range []bool{true, false} {
		calls := 0
		a := testAdapter(t, cloud, func(r *http.Request) (*http.Response, error) {
			calls++
			if strings.HasSuffix(r.URL.Path, "/serverInfo") {
				return response(200, `{"versionNumbers":[11,3,0],"deploymentType":"Server"}`, nil), nil
			}
			if !strings.HasSuffix(r.URL.Path, "/myself") {
				t.Fatal(r.URL.Path)
			}
			return response(200, `{"accountId":"cloud-user","name":"dc-user"}`, nil), nil
		})
		got, err := a.TicketWebhookPrincipal(context.Background())
		want := "dc-user"
		count := 2
		if cloud {
			want = "cloud-user"
			count = 1
		}
		if err != nil || got != want || calls != count {
			t.Fatalf("identity=%s calls=%d err=%v", got, calls, err)
		}
	}
}
