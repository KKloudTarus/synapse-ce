package notificationsender

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestPagerEpisodeAliasSeparatesReopenedSubjectAndRetainsClosureIdentity(t *testing.T) {
	s := New(SMTPConfig{}, 0)
	s.pagerKey = []byte("synthetic-pager-key")
	work := testWork(notification.ChannelJSM)
	work.Event.SubjectKind, work.Event.SubjectID = "finding", "finding"
	legacy, _ := s.pagerDedupKey(work)
	work.Event.PagerLifecycle = notification.PagerLifecycle{Episode: 1, Revision: 1}
	first, _ := s.pagerDedupKey(work)
	work.Event.PagerLifecycle.Revision = 4
	work.Event.PagerLifecycle.Terminal = true
	close, _ := s.pagerDedupKey(work)
	work.Event.PagerLifecycle = notification.PagerLifecycle{Episode: 2, Revision: 5}
	reopened, _ := s.pagerDedupKey(work)
	if legacy == first || first != close || reopened == first {
		t.Fatalf("episode aliases crossed: legacy=%s first=%s close=%s reopened=%s", legacy, first, close, reopened)
	}
}

func TestPagerClassifiedCloseRejectsAnchorFromAnotherEpisode(t *testing.T) {
	for _, channel := range []notification.ChannelType{notification.ChannelJSM, notification.ChannelPagerDuty} {
		t.Run(string(channel), func(t *testing.T) {
			s := New(SMTPConfig{}, 0)
			s.pagerKey = []byte("synthetic-pager-key")
			calls := 0
			s.http = &http.Client{Transport: providerRoundTrip(func(r *http.Request) (*http.Response, error) { calls++; return providerResponse(202, `{}`), nil })}
			work := testWork(channel)
			work.Event.SubjectKind, work.Event.SubjectID = "finding", "finding"
			work.Event.PagerLifecycle = notification.PagerLifecycle{Episode: 1, Revision: 1}
			work.SubjectAnchor, _ = s.pagerDedupKey(work)
			work.Event.PagerLifecycle = notification.PagerLifecycle{Episode: 2, Revision: 5, Terminal: true}
			work.SubjectResolved = true
			var cfg ports.NotificationChannelConfig = ports.JSMChannelConfig{APIKey: "synthetic"}
			if channel == notification.ChannelPagerDuty {
				cfg = ports.PagerDutyChannelConfig{Region: "events.pagerduty.com", RoutingKey: "synthetic"}
			}
			result := s.Send(context.Background(), work, cfg)
			if result.ErrorCode != "pager_resolve_unpaired" || calls != 0 {
				t.Fatalf("wrong-episode close escaped: result=%+v calls=%d", result, calls)
			}
		})
	}
}

func TestJSMFindingStatusPreservesCapturedNote(t *testing.T) {
	s := New(SMTPConfig{}, 0)
	s.pagerKey = []byte("synthetic-pager-key")
	var payload map[string]any
	s.http = &http.Client{Transport: providerRoundTrip(func(r *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		return providerResponse(202, `{"requestId":"status-request"}`), nil
	})}
	work := testWork(notification.ChannelJSM)
	work.Event.Type = notification.EventFindingStatusChanged
	work.Event.SubjectKind, work.Event.SubjectID = "finding", "finding"
	work.Event.PagerLifecycle = notification.PagerLifecycle{Episode: 1, Revision: 2}
	work.Formatted = &ports.FormattedMessage{Body: []byte(`{"summary":"Finding updated","note":"Status changed to confirmed"}`)}
	result := s.Send(context.Background(), work, ports.JSMChannelConfig{APIKey: "synthetic"})
	if result.ProviderRequestRef != "status-request" || payload["note"] != "Status changed to confirmed" {
		t.Fatalf("status note lost: result=%+v payload=%v", result, payload)
	}
}
