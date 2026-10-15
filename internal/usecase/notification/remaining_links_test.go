package notification

import (
	"encoding/json"
	"github.com/KKloudTarus/synapse-ce/internal/domain/consolelink"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"testing"
)

func TestRemainingEventsLinkToExistingConsolePages(t *testing.T) {
	builder, err := consolelink.NewBuilder("https://console.example.test/prefix")
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{}
	service.SetConsoleLinkBuilder(builder)
	for _, tc := range []struct {
		event      domain.EventType
		kind, path string
	}{
		{domain.EventApprovalRequested, "agent", "/engagements/eng/agent"},
		{domain.EventApprovalDecided, "response", "/blueteam/response"},
		{domain.EventResponseFinished, "", "/blueteam/response"},
		{domain.EventIncidentUpdated, "", "/fleet/incidents/subject"},
		{domain.EventEngagementCreated, "", "/engagements/eng"},
		{domain.EventFindingMentioned, "", "/engagements/eng/findings#finding-subject"},
	} {
		raw, _ := json.Marshal(map[string]string{"kind": tc.kind})
		links := service.renderLinks(domain.Event{Type: tc.event, EngagementID: "eng", SubjectID: "subject", Data: raw})
		if len(links) != 1 || links[0].URL != "https://console.example.test/prefix"+tc.path {
			t.Fatalf("%s/%s: %+v", tc.event, tc.kind, links)
		}
	}
	if links := service.renderLinks(domain.Event{Type: domain.EventApprovalRequested, EngagementID: "..", Data: json.RawMessage(`{"kind":"agent"}`)}); len(links) > 0 {
		t.Fatal("invalid subject produced link")
	}
}
