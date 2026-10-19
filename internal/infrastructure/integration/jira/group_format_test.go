package jira

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestGroupFormatterChecksKnownCredentialsBeforeSnapshot(t *testing.T) {
	for _, cloud := range []bool{true, false} {
		a := testAdapter(t, cloud, func(*http.Request) (*http.Response, error) { t.Fatal("formatting performed HTTP"); return nil, nil })
		raw, err := a.FormatTicketGroupDescription("Phát hiện", nil, []string{"Tài sản"}, [][]string{{"assetone"}})
		if err != nil || !json.Valid(raw) || !strings.Contains(string(raw), "assetone") {
			t.Fatalf("group format=%s err=%v", raw, err)
		}
		if _, err = a.FormatTicketGroupDescription("Report", nil, []string{"Asset"}, [][]string{{"secret-token"}}); err == nil || strings.Contains(err.Error(), "secret-token") {
			t.Fatalf("credential-bearing group result: %v", err)
		}
	}
}

func TestTicketDescriptionRefusesKnownCredentialsBeforeWikiEscaping(t *testing.T) {
	for _, cloud := range []bool{true, false} {
		a := testAdapter(t, cloud, func(*http.Request) (*http.Response, error) { t.Fatal("formatting performed HTTP"); return nil, nil })
		if _, err := a.FormatTicketDescription("The configured value is secret-token", nil); err == nil || strings.Contains(err.Error(), "secret-token") {
			t.Fatalf("credential-bearing description result: %v", err)
		}
	}
}
