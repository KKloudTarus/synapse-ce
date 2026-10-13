package notificationsender

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/messageformat"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type providerRoundTrip func(*http.Request) (*http.Response, error)

func (f providerRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func providerResponse(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestSelfHostedDriversUseAllowedWebhookOnlyAndNeverLeakURL(t *testing.T) {
	for _, tc := range []struct {
		kind notification.ChannelType
		cfg  ports.NotificationChannelConfig
	}{
		{notification.ChannelMattermost, ports.MattermostChannelConfig{URL: "https://chat.example.test/hooks/secret"}},
		{notification.ChannelRocketChat, ports.RocketChatChannelConfig{URL: "https://chat.example.test/hooks/secret"}},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			s := New(SMTPConfig{}, 0)
			s.selfHostedHosts = map[string]bool{"chat.example.test": true}
			var payload []byte
			s.http = &http.Client{Transport: providerRoundTrip(func(r *http.Request) (*http.Response, error) {
				payload, _ = io.ReadAll(r.Body)
				return providerResponse(http.StatusNoContent, ""), nil
			})}
			if got := s.Send(context.Background(), testWork(tc.kind), tc.cfg); got.ErrorCode != "" {
				t.Fatalf("result=%+v", got)
			}
			if bytes.Contains(payload, []byte(`"blocks"`)) || !bytes.Contains(payload, []byte(`"text"`)) {
				t.Fatalf("unsupported self-hosted payload: %s", payload)
			}
			s.selfHostedHosts = nil
			if got := s.Send(context.Background(), testWork(tc.kind), tc.cfg); got.ErrorCode != "channel_config_invalid" || strings.Contains(got.ErrorCode, "secret") {
				t.Fatalf("invalid allowlist result=%+v", got)
			}
		})
	}
}

func TestPagerDutyUsesStableTenantChannelSubjectDedupAndPairedResolve(t *testing.T) {
	s := New(SMTPConfig{}, 0)
	s.pagerKey = []byte("pager-master-key-for-test")
	var payloads []map[string]any
	s.http = &http.Client{Transport: providerRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != pagerDutyEventsEU {
			t.Errorf("target=%s", r.URL)
		}
		var value map[string]any
		_ = json.NewDecoder(r.Body).Decode(&value)
		payloads = append(payloads, value)
		return providerResponse(http.StatusAccepted, "{}"), nil
	})}
	work := testWork(notification.ChannelPagerDuty)
	work.Event.SubjectKind, work.Event.SubjectID = "finding", "finding-1"
	work.Channel.DataClass = notification.DataClassDetail
	cfg := ports.PagerDutyChannelConfig{Region: "events.eu.pagerduty.com", RoutingKey: "routing-key-secret"}
	trigger := s.Send(context.Background(), work, cfg)
	if trigger.ErrorCode != "" || trigger.RemoteRef == "" {
		t.Fatalf("trigger=%+v", trigger)
	}
	work.SubjectAnchor = trigger.RemoteRef
	work.SubjectResolved = true
	resolve := s.Send(context.Background(), work, cfg)
	if resolve.ErrorCode != "" || resolve.RemoteRef != trigger.RemoteRef {
		t.Fatalf("resolve=%+v", resolve)
	}
	if len(payloads) != 2 || payloads[0]["dedup_key"] != payloads[1]["dedup_key"] || payloads[0]["event_action"] != "trigger" || payloads[1]["event_action"] != "resolve" {
		t.Fatalf("payloads=%v", payloads)
	}
	encoded, _ := json.Marshal(payloads[0]["payload"])
	if bytes.Contains(encoded, []byte(`"data"`)) || bytes.Contains(encoded, []byte(`"context"`)) {
		t.Fatalf("pager custom details carry event data: %s", encoded)
	}
}

func TestPagerDedupUsesTrustedSubjectAndIsolatesTenantChannelAndVersion(t *testing.T) {
	s := New(SMTPConfig{}, 0)
	s.pagerKey = []byte("pager-master-key-for-test")
	work := testWork(notification.ChannelPagerDuty)
	work.Event.SubjectKind, work.Event.SubjectID = "finding", "finding-1"
	key, ok := s.pagerDedupKey(work)
	if !ok {
		t.Fatal("missing key")
	}
	// Two distinct source events for one trusted subject resolve to the same provider identity.
	otherEvent := work
	otherEvent.Event.ID = "event-2"
	if got, _ := s.pagerDedupKey(otherEvent); got != key {
		t.Fatalf("event-specific key: %q != %q", got, key)
	}
	otherTenant := work
	otherTenant.Delivery.TenantID = "tenant-other"
	if got, _ := s.pagerDedupKey(otherTenant); got == key {
		t.Fatal("tenant keys crossed")
	}
	otherChannel := work
	otherChannel.Channel.ID = "channel-other"
	if got, _ := s.pagerDedupKey(otherChannel); got == key {
		t.Fatal("channel keys crossed")
	}
	otherVersion := work
	otherVersion.Channel.SecretVersion++
	if got, _ := s.pagerDedupKey(otherVersion); got == key {
		t.Fatal("channel version keys crossed")
	}
	noSubject := work
	noSubject.Event.SubjectKind, noSubject.Event.SubjectID = "", ""
	noSubject.Event.ID = "event-no-subject"
	if got, _ := s.pagerDedupKey(noSubject); got == key {
		t.Fatal("subject-less event aggregated with a subject")
	}
}

func TestJSMConfirmsAsyncRequestBeforeReportingDeliveredAndClosesByAlias(t *testing.T) {
	s := New(SMTPConfig{}, 0)
	s.pagerKey = []byte("pager-master-key-for-test")
	var requests []*http.Request
	s.http = &http.Client{Transport: providerRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r)
		switch {
		case strings.Contains(r.URL.Path, "/requests/"):
			return providerResponse(http.StatusOK, `{"data":{"isSuccess":true}}`), nil
		case strings.Contains(r.URL.Path, "/close"):
			return providerResponse(http.StatusAccepted, `{"requestId":"request-close"}`), nil
		default:
			return providerResponse(http.StatusAccepted, `{"requestId":"request-create"}`), nil
		}
	})}
	work := testWork(notification.ChannelJSM)
	work.Event.SubjectKind, work.Event.SubjectID = "finding", "finding-1"
	cfg := ports.JSMChannelConfig{APIKey: "jsm-api-key-secret"}
	trigger := s.Send(context.Background(), work, cfg)
	if trigger.ErrorCode != "jsm_request_unconfirmed" || trigger.ProviderRequestRef != "request-create" || trigger.RemoteRef != "" {
		t.Fatalf("create=%+v", trigger)
	}
	work.Delivery.ProviderRequestRef = trigger.ProviderRequestRef
	trigger = s.Send(context.Background(), work, cfg)
	if trigger.ErrorCode != "" || trigger.RemoteRef == "" || trigger.ProviderRequestRef != "" {
		t.Fatalf("create confirmation=%+v", trigger)
	}
	work.Delivery.ProviderRequestRef = ""
	work.SubjectAnchor = trigger.RemoteRef
	work.SubjectResolved = true
	resolve := s.Send(context.Background(), work, cfg)
	if resolve.ErrorCode != "jsm_request_unconfirmed" || resolve.ProviderRequestRef != "request-close" || resolve.RemoteRef != "" {
		t.Fatalf("close=%+v", resolve)
	}
	work.Delivery.ProviderRequestRef = resolve.ProviderRequestRef
	resolve = s.Send(context.Background(), work, cfg)
	if resolve.ErrorCode != "" || resolve.RemoteRef != trigger.RemoteRef || resolve.ProviderRequestRef != "" {
		t.Fatalf("close confirmation=%+v", resolve)
	}
	if len(requests) != 4 || !strings.Contains(requests[2].URL.String(), "/close?identifierType=alias") || requests[0].Header.Get("Authorization") != "GenieKey jsm-api-key-secret" {
		t.Fatalf("requests=%d close=%v", len(requests), requests)
	}
}

func TestJSMDoesNotClaimDeliveredWhenAsyncStatusIsUnconfirmed(t *testing.T) {
	s := New(SMTPConfig{}, 0)
	s.pagerKey = []byte("pager-master-key-for-test")
	requests := 0
	s.http = &http.Client{Transport: providerRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		if strings.Contains(r.URL.Path, "/requests/") {
			t.Errorf("initial create read asynchronous status before its request reference was persisted")
			return providerResponse(http.StatusInternalServerError, `{}`), nil
		}
		return providerResponse(http.StatusAccepted, `{"requestId":"request-create"}`), nil
	})}
	work := testWork(notification.ChannelJSM)
	work.Event.SubjectKind, work.Event.SubjectID = "finding", "finding-1"
	got := s.Send(context.Background(), work, ports.JSMChannelConfig{APIKey: "jsm-api-key-secret"})
	if got.ErrorCode != "jsm_request_unconfirmed" || !got.Retryable || got.ProviderRequestRef != "request-create" {
		t.Fatalf("result=%+v", got)
	}
	if requests != 1 {
		t.Fatalf("requests=%d, want only create", requests)
	}
}

func TestJSMRetriesAsyncStatusAcrossWorkerAttemptsWithStableAlias(t *testing.T) {
	var creates, statusReads int
	aliases := make([]string, 0, 1)
	client := &http.Client{Transport: providerRoundTrip(func(r *http.Request) (*http.Response, error) {
		switch r.Method {
		case http.MethodPost:
			creates++
			var payload struct {
				Alias string `json:"alias"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			aliases = append(aliases, payload.Alias)
			return providerResponse(http.StatusAccepted, `{"requestId":"request-create"}`), nil
		case http.MethodGet:
			statusReads++
			switch statusReads {
			case 1:
				return providerResponse(http.StatusNotFound, `{}`), nil
			case 2:
				return providerResponse(http.StatusOK, `{"data":{}}`), nil
			default:
				return providerResponse(http.StatusOK, `{"data":{"isSuccess":true}}`), nil
			}
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})}
	work := testWork(notification.ChannelJSM)
	work.Event.SubjectKind, work.Event.SubjectID = "finding", "eventual-status"
	config := ports.JSMChannelConfig{APIKey: "synthetic-jsm-key"}
	for attempt := 0; attempt < 4; attempt++ {
		// A new Sender models the later durable delivery attempt being handled by a new worker.
		s := New(SMTPConfig{}, 0)
		s.pagerKey = []byte("pager-master-key-for-test")
		s.http = client
		got := s.Send(context.Background(), work, config)
		if attempt < 3 {
			if got.ErrorCode != "jsm_request_unconfirmed" || !got.Retryable || got.RemoteRef != "" || got.ProviderRequestRef != "request-create" {
				t.Fatalf("attempt %d result=%+v", attempt+1, got)
			}
			work.Delivery.ProviderRequestRef = got.ProviderRequestRef
			continue
		}
		if got.ErrorCode != "" || got.RemoteRef == "" || got.RemoteRef != aliases[0] || got.ProviderRequestRef != "" {
			t.Fatalf("attempt %d result=%+v aliases=%q", attempt+1, got, aliases)
		}
	}
	if creates != 1 || statusReads != 3 {
		t.Fatalf("creates=%d status reads=%d", creates, statusReads)
	}
	if len(aliases) != 1 || aliases[0] == "" {
		t.Fatalf("create aliases=%q", aliases)
	}
}

func TestJSMRetainsAcceptedRequestAfterTerminalStatusErrorForGetOnlyRedrive(t *testing.T) {
	var creates, statusReads int
	var repairedAuthorization string
	client := &http.Client{Transport: providerRoundTrip(func(r *http.Request) (*http.Response, error) {
		switch r.Method {
		case http.MethodPost:
			creates++
			return providerResponse(http.StatusAccepted, `{"requestId":"request-create"}`), nil
		case http.MethodGet:
			statusReads++
			if statusReads == 1 {
				return providerResponse(http.StatusUnauthorized, `{}`), nil
			}
			repairedAuthorization = r.Header.Get("Authorization")
			return providerResponse(http.StatusOK, `{"data":{"isSuccess":true}}`), nil
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})}
	work := testWork(notification.ChannelJSM)
	work.Event.SubjectKind, work.Event.SubjectID = "finding", "credential-repair"

	first := New(SMTPConfig{}, 0)
	first.pagerKey = []byte("pager-master-key-for-test")
	first.http = client
	accepted := first.Send(context.Background(), work, ports.JSMChannelConfig{APIKey: "expired-test-key"})
	if accepted.ErrorCode != "jsm_request_unconfirmed" || accepted.ProviderRequestRef != "request-create" {
		t.Fatalf("accepted=%+v", accepted)
	}
	work.Delivery.ProviderRequestRef = accepted.ProviderRequestRef

	failed := New(SMTPConfig{}, 0)
	failed.pagerKey = []byte("pager-master-key-for-test")
	failed.http = client
	result := failed.Send(context.Background(), work, ports.JSMChannelConfig{APIKey: "expired-test-key"})
	if result.ErrorCode != "http_401" || result.Retryable || result.ProviderRequestRef != "request-create" || result.RemoteRef != "" {
		t.Fatalf("credential failure=%+v", result)
	}

	repaired := New(SMTPConfig{}, 0)
	repaired.pagerKey = []byte("pager-master-key-for-test")
	repaired.http = client
	result = repaired.Send(context.Background(), work, ports.JSMChannelConfig{APIKey: "repaired-test-key"})
	if result.ErrorCode != "" || result.RemoteRef == "" || result.ProviderRequestRef != "" {
		t.Fatalf("redrive=%+v", result)
	}
	if creates != 1 || statusReads != 2 || repairedAuthorization != "GenieKey repaired-test-key" {
		t.Fatalf("creates=%d statusReads=%d repairedAuthorization=%q", creates, statusReads, repairedAuthorization)
	}
}

func TestJSMRetainsPendingRequestForLocalValidationFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config ports.NotificationChannelConfig
		key    []byte
		code   string
	}{
		{name: "channel configuration", config: ports.JSMChannelConfig{}, key: []byte("pager-master-key-for-test"), code: "channel_config_invalid"},
		{name: "pager key", config: ports.JSMChannelConfig{APIKey: "test-api-key"}, code: "pager_key_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := New(SMTPConfig{}, 0)
			s.pagerKey = tc.key
			called := false
			s.http = &http.Client{Transport: providerRoundTrip(func(*http.Request) (*http.Response, error) {
				called = true
				return providerResponse(http.StatusOK, `{"data":{"isSuccess":true}}`), nil
			})}
			work := testWork(notification.ChannelJSM)
			work.Event.SubjectKind, work.Event.SubjectID = "finding", "local-validation"
			work.Delivery.ProviderRequestRef = "request-create"
			got := s.Send(context.Background(), work, tc.config)
			if got.ErrorCode != tc.code || got.Retryable || got.ProviderRequestRef != "request-create" || got.RemoteRef != "" || called {
				t.Fatalf("result=%+v called=%v", got, called)
			}
		})
	}
}

func TestJSMResumesPendingRequestBeforeRenderingOrResolvePairing(t *testing.T) {
	s := New(SMTPConfig{}, 0)
	s.pagerKey = []byte("pager-master-key-for-test")
	var methods []string
	s.http = &http.Client{Transport: providerRoundTrip(func(r *http.Request) (*http.Response, error) {
		methods = append(methods, r.Method)
		return providerResponse(http.StatusOK, `{"data":{"isSuccess":true}}`), nil
	})}
	work := testWork(notification.ChannelJSM)
	work.Event.SubjectKind, work.Event.SubjectID = "finding", "resume-before-render"
	work.Delivery.ProviderRequestRef = "request-create"
	work.SubjectResolved = true
	work.Formatted = &ports.FormattedMessage{Body: []byte(`{`)}
	got := s.Send(context.Background(), work, ports.JSMChannelConfig{APIKey: "test-api-key"})
	if got.ErrorCode != "" || got.RemoteRef == "" || got.ProviderRequestRef != "" {
		t.Fatalf("result=%+v", got)
	}
	if len(methods) != 1 || methods[0] != http.MethodGet {
		t.Fatalf("methods=%v", methods)
	}
}

func TestJSMDoesNotAcknowledgeWhenStatusCheckContextIsCancelled(t *testing.T) {
	s := New(SMTPConfig{}, 0)
	s.pagerKey = []byte("pager-master-key-for-test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var statusReads int
	s.http = &http.Client{Transport: providerRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			return providerResponse(http.StatusAccepted, `{"requestId":"request-create"}`), nil
		}
		statusReads++
		cancel()
		return providerResponse(http.StatusNotFound, `{}`), nil
	})}
	work := testWork(notification.ChannelJSM)
	work.Event.SubjectKind, work.Event.SubjectID = "finding", "cancelled-status"
	work.Delivery.ProviderRequestRef = "request-create"
	got := s.Send(ctx, work, ports.JSMChannelConfig{APIKey: "synthetic-jsm-key"})
	if got.ErrorCode != "jsm_request_unconfirmed" || !got.Retryable || got.RemoteRef != "" || got.ProviderRequestRef != "request-create" {
		t.Fatalf("result=%+v", got)
	}
	if statusReads != 1 {
		t.Fatalf("status reads=%d, want one after cancellation", statusReads)
	}
}

func TestJSMRejectsUnsafeRequestReferenceBeforePersistingOrRouting(t *testing.T) {
	for name, body := range map[string]string{
		"unsafe path": `{"requestId":"../unsafe"}`,
		"missing":     `{}`,
		"malformed":   `{`,
	} {
		t.Run("accepted response/"+name, func(t *testing.T) {
			s := New(SMTPConfig{}, 0)
			s.pagerKey = []byte("pager-master-key-for-test")
			calls := 0
			s.http = &http.Client{Transport: providerRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return providerResponse(http.StatusAccepted, body), nil
			})}
			work := testWork(notification.ChannelJSM)
			work.Event.SubjectKind, work.Event.SubjectID = "finding", "unsafe-response"
			got := s.Send(context.Background(), work, ports.JSMChannelConfig{APIKey: "synthetic-jsm-key"})
			if got.ErrorCode != "jsm_request_ref_invalid" || got.Retryable || got.ProviderRequestRef != "" || calls != 1 {
				t.Fatalf("result=%+v calls=%d", got, calls)
			}
		})
	}
	t.Run("persisted reference", func(t *testing.T) {
		s := New(SMTPConfig{}, 0)
		s.pagerKey = []byte("pager-master-key-for-test")
		called := false
		s.http = &http.Client{Transport: providerRoundTrip(func(*http.Request) (*http.Response, error) {
			called = true
			return providerResponse(http.StatusOK, `{"data":{"isSuccess":true}}`), nil
		})}
		work := testWork(notification.ChannelJSM)
		work.Event.SubjectKind, work.Event.SubjectID = "finding", "unsafe-persisted"
		work.Delivery.ProviderRequestRef = strings.Repeat("a", maxJSMRequestID+1)
		got := s.Send(context.Background(), work, ports.JSMChannelConfig{APIKey: "synthetic-jsm-key"})
		if got.ErrorCode != "jsm_request_ref_invalid" || got.Retryable || got.ProviderRequestRef != "" || called {
			t.Fatalf("result=%+v called=%v", got, called)
		}
	})
}

func TestPagerResolveWithoutAcknowledgedTriggerDoesNotCallProvider(t *testing.T) {
	for _, tc := range []struct {
		kind notification.ChannelType
		cfg  ports.NotificationChannelConfig
	}{
		{notification.ChannelPagerDuty, ports.PagerDutyChannelConfig{Region: "events.pagerduty.com", RoutingKey: "routing-key-secret"}},
		{notification.ChannelJSM, ports.JSMChannelConfig{APIKey: "jsm-api-key-secret"}},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			s := New(SMTPConfig{}, 0)
			s.pagerKey = []byte("pager-master-key-for-test")
			called := false
			s.http = &http.Client{Transport: providerRoundTrip(func(*http.Request) (*http.Response, error) {
				called = true
				return providerResponse(http.StatusAccepted, "{}"), nil
			})}
			work := testWork(tc.kind)
			work.Event.SubjectKind, work.Event.SubjectID, work.SubjectResolved = "finding", "finding-1", true
			if got := s.Send(context.Background(), work, tc.cfg); got.ErrorCode != "pager_resolve_unpaired" || got.Retryable || called {
				t.Fatalf("result=%+v called=%v", got, called)
			}
		})
	}
}

func TestJSMUnexpectedSuccessDoesNotAcknowledgeDelivery(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusNoContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			s := New(SMTPConfig{}, 0)
			s.pagerKey = []byte("test-pager-key")
			s.http = &http.Client{Transport: providerRoundTrip(func(*http.Request) (*http.Response, error) { return providerResponse(status, `{}`), nil })}
			work := testWork(notification.ChannelJSM)
			work.Event.SubjectKind, work.Event.SubjectID = "finding", "test-finding"
			result := s.Send(context.Background(), work, ports.JSMChannelConfig{APIKey: "synthetic-jsm-key"})
			if result.ErrorCode != "jsm_request_unconfirmed" || !result.Retryable || result.RemoteRef != "" {
				t.Fatalf("unexpected acknowledgement: %+v", result)
			}
		})
	}
}

func TestPagerDutyPayloadBoundsSummaryAndKeepsOnlyTrustedLinks(t *testing.T) {
	s := New(SMTPConfig{}, 0)
	s.pagerKey = []byte("pager-master-key-for-test")
	var requestBody []byte
	s.http = &http.Client{Transport: providerRoundTrip(func(r *http.Request) (*http.Response, error) {
		requestBody, _ = io.ReadAll(r.Body)
		return providerResponse(http.StatusAccepted, "{}"), nil
	})}
	summary := strings.Repeat("Cảnh báo 🔥 <@here> ", 200)
	formatted, err := (messageformat.PagerDutyFormatter{}).Format(ports.RenderedMessage{Fields: map[string]string{"summary": summary, "body": "must not escape"}, Links: []ports.RenderedLink{{Label: "Open trusted", URL: "https://console.example/finding/1"}}})
	if err != nil {
		t.Fatal(err)
	}
	work := testWork(notification.ChannelPagerDuty)
	work.Event.SubjectKind, work.Event.SubjectID, work.Formatted = "finding", "finding-1", &formatted
	if got := s.Send(context.Background(), work, ports.PagerDutyChannelConfig{Region: "events.pagerduty.com", RoutingKey: "routing-key-secret"}); got.ErrorCode != "" {
		t.Fatalf("result=%+v", got)
	}
	var payload struct {
		Payload struct {
			Summary string                     `json:"summary"`
			Details map[string]json.RawMessage `json:"custom_details"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(requestBody, &payload); err != nil {
		t.Fatal(err)
	}
	if !utf8.ValidString(payload.Payload.Summary) || utf8.RuneCountInString(payload.Payload.Summary) > messageformat.PagerDutySummaryRunes {
		t.Fatalf("summary exceeds pager contract: %q", payload.Payload.Summary)
	}
	if len(payload.Payload.Details) != 1 || bytes.Contains(requestBody, []byte("must not escape")) || !bytes.Contains(requestBody, []byte("console.example/finding/1")) {
		t.Fatalf("pager details=%s", requestBody)
	}
}

func TestJSMPayloadUsesStringDetailsAndBoundsUnicodeMessage(t *testing.T) {
	for _, links := range [][]ports.RenderedLink{
		nil,
		{{Label: "Open trusted", URL: "https://console.example/finding/1"}},
	} {
		t.Run("links="+strconv.Itoa(len(links)), func(t *testing.T) {
			s := New(SMTPConfig{}, 0)
			s.pagerKey = []byte("pager-master-key-for-test")
			var createBody []byte
			s.http = &http.Client{Transport: providerRoundTrip(func(r *http.Request) (*http.Response, error) {
				if strings.Contains(r.URL.Path, "/requests/") {
					return providerResponse(http.StatusOK, `{"data":{"isSuccess":true}}`), nil
				}
				createBody, _ = io.ReadAll(r.Body)
				return providerResponse(http.StatusAccepted, `{"requestId":"request-create"}`), nil
			})}
			summary := strings.Repeat("Cảnh báo 🔥 <@here> ", 200)
			formatted, err := (messageformat.JSMFormatter{}).Format(ports.RenderedMessage{Fields: map[string]string{"summary": summary, "body": "must not escape"}, Links: links})
			if err != nil {
				t.Fatal(err)
			}
			work := testWork(notification.ChannelJSM)
			work.Event.SubjectKind, work.Event.SubjectID, work.Formatted = "finding", "finding-1", &formatted
			if got := s.Send(context.Background(), work, ports.JSMChannelConfig{APIKey: "jsm-api-key-secret"}); got.ErrorCode != "jsm_request_unconfirmed" || got.ProviderRequestRef != "request-create" {
				t.Fatalf("result=%+v", got)
			}
			var payload struct {
				Message string            `json:"message"`
				Details map[string]string `json:"details"`
			}
			if err := json.Unmarshal(createBody, &payload); err != nil {
				t.Fatal(err)
			}
			if !utf8.ValidString(payload.Message) || utf8.RuneCountInString(payload.Message) > messageformat.JSMMessageRunes {
				t.Fatalf("message exceeds JSM contract: %q", payload.Message)
			}
			if bytes.Contains(createBody, []byte("must not escape")) {
				t.Fatalf("arbitrary content entered JSM details: %s", createBody)
			}
			if len(links) == 0 && len(payload.Details) != 0 {
				t.Fatalf("zero links details=%v", payload.Details)
			}
			if len(links) == 1 && (len(payload.Details) != 1 || payload.Details["link_1"] != "https://console.example/finding/1") {
				t.Fatalf("string link details=%v", payload.Details)
			}
		})
	}
}

func TestJSMPayloadPriorityComesFromEventSeverity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		severity shared.Severity
		want     string
	}{
		{name: "critical", severity: shared.SeverityCritical, want: "P1"},
		{name: "high", severity: shared.SeverityHigh, want: "P2"},
		{name: "medium", severity: shared.SeverityMedium, want: "P3"},
		{name: "low", severity: shared.SeverityLow, want: "P4"},
		{name: "info", severity: shared.SeverityInfo, want: "P5"},
		{name: "unknown", severity: shared.SeverityUnknown, want: "P3"},
		{name: "invalid", severity: shared.Severity("untrusted-P1"), want: "P3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := New(SMTPConfig{}, 0)
			s.pagerKey = []byte("pager-master-key-for-test")
			var createBody []byte
			s.http = &http.Client{Transport: providerRoundTrip(func(r *http.Request) (*http.Response, error) {
				createBody, _ = io.ReadAll(r.Body)
				return providerResponse(http.StatusAccepted, `{"requestId":"request-create"}`), nil
			})}
			formatted, err := (messageformat.JSMFormatter{}).Format(ports.RenderedMessage{Fields: map[string]string{"summary": "operator text says P1"}})
			if err != nil {
				t.Fatal(err)
			}
			work := testWork(notification.ChannelJSM)
			work.Event.SubjectKind, work.Event.SubjectID, work.Event.Severity = "finding", "finding-priority", tc.severity
			work.Formatted = &formatted
			if got := s.Send(context.Background(), work, ports.JSMChannelConfig{APIKey: "jsm-api-key-secret"}); got.ErrorCode != "jsm_request_unconfirmed" {
				t.Fatalf("result=%+v", got)
			}
			var payload struct {
				Priority string `json:"priority"`
			}
			if err := json.Unmarshal(createBody, &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Priority != tc.want {
				t.Fatalf("priority=%q, want %q", payload.Priority, tc.want)
			}
		})
	}
}

func TestJSMClosePayloadDoesNotIncludeTriggerPriority(t *testing.T) {
	s := New(SMTPConfig{}, 0)
	s.pagerKey = []byte("pager-master-key-for-test")
	var closeBody []byte
	s.http = &http.Client{Transport: providerRoundTrip(func(r *http.Request) (*http.Response, error) {
		if !strings.Contains(r.URL.Path, "/close") {
			t.Fatalf("target=%s", r.URL)
		}
		closeBody, _ = io.ReadAll(r.Body)
		return providerResponse(http.StatusAccepted, `{"requestId":"request-close"}`), nil
	})}
	formatted, err := (messageformat.JSMFormatter{}).Format(ports.RenderedMessage{Fields: map[string]string{"summary": "closed alert"}})
	if err != nil {
		t.Fatal(err)
	}
	work := testWork(notification.ChannelJSM)
	work.Event.SubjectKind, work.Event.SubjectID, work.Event.Severity = "finding", "finding-close", shared.SeverityCritical
	work.SubjectResolved, work.SubjectAnchor, work.Formatted = true, "acknowledged-alias", &formatted
	if got := s.Send(context.Background(), work, ports.JSMChannelConfig{APIKey: "jsm-api-key-secret"}); got.ErrorCode != "jsm_request_unconfirmed" {
		t.Fatalf("result=%+v", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(closeBody, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload) != 1 || payload["source"] != "synapse" {
		t.Fatalf("close payload=%s", closeBody)
	}
}
