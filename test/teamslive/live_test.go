// Package teamslive posts the acceptance messages of #1420 into a real Microsoft Teams 1:1
// conversation, through the shipped templates, the shipped Adaptive Card formatter and the real
// Bot Connector client. It exists so the client evidence that issue asks for is one command, not a
// hand-assembled payload: what lands in Teams is what a delivery would land.
//
// It is opt-in, like the Postgres, syslog and S3 suites. Set:
//
//	SYNAPSE_TEST_TEAMS_APP_ID          bot application (client) ID
//	SYNAPSE_TEST_TEAMS_APP_PASSWORD    bot client secret
//	SYNAPSE_TEST_TEAMS_TENANT_ID       Entra tenant of a single-tenant bot; empty for multi-tenant
//	SYNAPSE_TEST_TEAMS_SERVICE_URL     conversation service URL, for example https://smba.trafficmanager.net/emea/
//	SYNAPSE_TEST_TEAMS_CONVERSATION_ID the 1:1 conversation ID the bot already has with the tester
//	SYNAPSE_TEST_TEAMS_LOCALES         optional, "en", "vi" or "en,vi" (default both)
//	SYNAPSE_PUBLIC_BASE_URL            optional console origin for the deep link
//
// The service URL and conversation ID are what the link flow stores for a person; read them from
// the bot's own activity payload, or from the stored contact after linking a test account.
package teamslive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/notificationbuiltin"
	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/messageformat"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/teamsbot"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// acceptanceMessage is one row of the evidence table in #1420.
type acceptanceMessage struct {
	name     string
	event    domain.EventType
	severity shared.Severity
	vars     map[string]string
	lists    map[string][]map[string]string
}

// injectionTitle carries every construct the issue requires to arrive as literal text.
const injectionTitle = "[Reset password](https://evil.example) @everyone <!channel> **bold**"

func acceptanceMessages() []acceptanceMessage {
	return []acceptanceMessage{
		{
			name: "1-finding-created-critical", event: domain.EventFindingCreated, severity: shared.SeverityCritical,
			vars: map[string]string{
				"severity": "critical", "finding_kind": "sast", "status": "open",
				"engagement_name": "Live acceptance", "finding_title": "SQL injection in /login", "actor": "Synapse",
			},
		},
		{
			name: "2-scan-completed-enriched", event: domain.EventScanCompleted, severity: shared.SeverityHigh,
			vars: map[string]string{
				"scan_kind": "sast", "total_count": "12", "critical_count": "1", "high_count": "2",
				"medium_count": "3", "low_count": "4", "info_count": "2",
				"new_count": "2", "fixed_count": "1", "unchanged_count": "9", "delta_available": "true",
				"engagement_name": "Live acceptance", "target": "api.example.com",
			},
			lists: map[string][]map[string]string{"findings": {{"id": "f-1", "severity": "critical", "title": "SQL injection in /login", "status": "open"}}},
		},
		{
			name: "3-sla-approaching", event: domain.EventSLAApproaching, severity: shared.SeverityHigh,
			vars: map[string]string{
				"tier": "high", "deadline": "2026-10-30T09:00:00Z", "lead_time_hours": "24",
				"engagement_name": "Live acceptance", "finding_title": "SQL injection in /login",
			},
		},
		{
			name: "4-incident-created", event: domain.EventIncidentCreated, severity: shared.SeverityCritical,
			vars: map[string]string{"severity": "critical", "engagement_name": "Live acceptance", "asset_name": "payments-api"},
		},
		{
			name: "5-injection-stays-literal", event: domain.EventFindingCreated, severity: shared.SeverityCritical,
			vars: map[string]string{
				"severity": "critical", "finding_kind": "sast", "status": "open",
				"engagement_name": "Live acceptance", "finding_title": injectionTitle, "actor": "Synapse",
			},
		},
	}
}

func TestTeamsLiveAcceptanceMessages(t *testing.T) {
	appID, password := os.Getenv("SYNAPSE_TEST_TEAMS_APP_ID"), os.Getenv("SYNAPSE_TEST_TEAMS_APP_PASSWORD")
	serviceURL, conversation := os.Getenv("SYNAPSE_TEST_TEAMS_SERVICE_URL"), os.Getenv("SYNAPSE_TEST_TEAMS_CONVERSATION_ID")
	if appID == "" || password == "" || serviceURL == "" || conversation == "" {
		t.Skip("set SYNAPSE_TEST_TEAMS_APP_ID, SYNAPSE_TEST_TEAMS_APP_PASSWORD, SYNAPSE_TEST_TEAMS_SERVICE_URL and SYNAPSE_TEST_TEAMS_CONVERSATION_ID to run the live Teams suite")
	}
	if !teamsbot.ValidServiceURL(serviceURL) {
		t.Fatalf("service URL is not a Bot Connector endpoint: %q", serviceURL)
	}
	bot := teamsbot.New(teamsbot.Config{AppID: appID, AppPassword: password, TenantID: os.Getenv("SYNAPSE_TEST_TEAMS_TENANT_ID")}, safehttp.New(20*time.Second, false))
	ref := ports.TeamsConversationRef{ServiceURL: serviceURL, ConversationID: conversation}
	catalog := notificationbuiltin.New()
	ctx := context.Background()

	for _, locale := range locales(t) {
		for _, message := range acceptanceMessages() {
			t.Run(message.name+"-"+string(locale), func(t *testing.T) {
				rendered := renderBuiltin(t, catalog, message, locale)
				formatted, err := messageformat.Teams(rendered)
				if err != nil {
					t.Fatalf("format the Adaptive Card: %v", err)
				}
				activity, err := bot.Send(ctx, ref, teamsActivity(formatted.Body))
				if err != nil {
					t.Fatalf("send to the conversation: %v", err)
				}
				if strings.TrimSpace(activity) == "" {
					t.Fatalf("the connector accepted the activity without an id")
				}
				t.Logf("delivered %s as activity %s: screenshot it as teams-%s-%s-<theme>.png", message.name, activity, strings.SplitN(message.name, "-", 2)[1], locale)
			})
		}
	}
	t.Log("every message above is in the conversation now; capture light and dark, desktop and mobile, and mask the channel settings")
}

// teamsActivity wraps the card body the formatter produced in the activity envelope the Bot
// Connector accepts. The formatter already emits the message shape a Workflows webhook takes, so
// only the activity type is added.
func teamsActivity(card []byte) []byte {
	return []byte(`{"type":"message","attachments":` + attachmentsOf(string(card)) + `}`)
}

func attachmentsOf(body string) string {
	const marker = `"attachments":`
	index := strings.Index(body, marker)
	if index < 0 {
		return `[]`
	}
	return strings.TrimSuffix(body[index+len(marker):], "}")
}

func locales(t *testing.T) []tenancy.Locale {
	t.Helper()
	switch strings.TrimSpace(os.Getenv("SYNAPSE_TEST_TEAMS_LOCALES")) {
	case "en":
		return []tenancy.Locale{tenancy.LocaleEnglish}
	case "vi":
		return []tenancy.Locale{tenancy.LocaleVietnamese}
	case "", "en,vi", "vi,en":
		return []tenancy.Locale{tenancy.LocaleEnglish, tenancy.LocaleVietnamese}
	default:
		t.Fatalf("SYNAPSE_TEST_TEAMS_LOCALES must be en, vi or en,vi")
		return nil
	}
}

// renderBuiltin renders the shipped chat template of the event with the message's variables,
// through the same template engine the delivery path uses.
func renderBuiltin(t *testing.T, catalog *notificationbuiltin.Catalog, message acceptanceMessage, locale tenancy.Locale) ports.RenderedMessage {
	t.Helper()
	template, ok := catalog.Builtin(message.event, domain.FamilyChat, locale)
	if !ok {
		t.Fatalf("no shipped chat template for %s in %s", message.event, locale)
	}
	spec, ok := domain.LookupEvent(message.event)
	if !ok {
		t.Fatalf("unknown event %s", message.event)
	}
	schema := eventSchema(t, spec)
	data := msgtemplate.Data{Vars: withCommonVars(message, spec), Lists: message.lists}
	fields := make(map[string]string, len(template.Fields))
	for name, source := range template.Fields {
		compiled, err := msgtemplate.Compile(name, source, schema)
		if err != nil {
			t.Fatalf("compile the shipped %s field: %v", name, err)
		}
		out, err := compiled.Render(data, 8000)
		if err != nil {
			t.Fatalf("render the shipped %s field: %v", name, err)
		}
		fields[name] = out.Text
	}
	rendered := ports.RenderedMessage{Fields: fields, TemplateRef: template.Ref, Severity: message.severity}
	if base := strings.TrimRight(os.Getenv("SYNAPSE_PUBLIC_BASE_URL"), "/"); base != "" {
		rendered.Links = []ports.RenderedLink{{Label: "Open in Synapse", URL: base + "/engagements"}}
	}
	return rendered
}

func withCommonVars(message acceptanceMessage, spec domain.EventSpec) map[string]string {
	vars := map[string]string{
		"event_type":  string(message.event),
		"event_label": spec.Label,
		"occurred_at": time.Now().UTC().Format(time.RFC3339),
		"title":       spec.Label,
		"summary":     fmt.Sprintf("%s acceptance message", spec.Label),
	}
	for name, value := range message.vars {
		vars[name] = value
	}
	return vars
}

// eventSchema mirrors templateSchemas in internal/usecase/notification: the declared variables of
// the event, with its list variables carrying their caps and item fields.
func eventSchema(t *testing.T, spec domain.EventSpec) *msgtemplate.Schema {
	t.Helper()
	var vars []string
	lists := map[string]msgtemplate.List{}
	for _, variable := range spec.Variables {
		if variable.ListCap == 0 {
			vars = append(vars, variable.Name)
			continue
		}
		lists[variable.Name] = msgtemplate.List{Cap: variable.ListCap, Fields: append([]string(nil), variable.ItemFields...)}
	}
	schema, err := msgtemplate.NewSchema(msgtemplate.SchemaSpec{Vars: vars, Lists: lists})
	if err != nil {
		t.Fatalf("event schema for %s: %v", spec.Type, err)
	}
	return schema
}

// fakeConnector answers the token request and the activity post, and keeps what it received.
type fakeConnector struct {
	activities []map[string]any
}

func (f *fakeConnector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
		_, _ = w.Write([]byte(`{"access_token":"fake-connector-token","expires_in":3600}`))
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var activity map[string]any
	if json.Unmarshal(body, &activity) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.activities = append(f.activities, activity)
	_, _ = w.Write([]byte(`{"id":"activity-` + strconv.Itoa(len(f.activities)) + `"}`))
}

// connectorRewrite sends the pinned Microsoft hosts to the fake while the client keeps building
// the real URLs, so the service-URL allowlist is exercised rather than bypassed.
type connectorRewrite struct {
	host  string
	inner http.RoundTripper
}

func (t connectorRewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = t.host
	return t.inner.RoundTrip(clone)
}

// TestTeamsAcceptanceMessagesRenderAndPost runs the same five messages the live suite sends, with
// the shipped templates and formatter, against a fake Bot Connector. It proves the suite is
// correct before anyone spends a tenant on it, and it is the contract test #1420 asks for: the
// payload that reaches the connector is one Adaptive Card whose injection message stays literal.
func TestTeamsAcceptanceMessagesRenderAndPost(t *testing.T) {
	fake := &fakeConnector{}
	server := httptest.NewServer(fake)
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	client := &http.Client{Transport: connectorRewrite{host: host, inner: http.DefaultTransport}, Timeout: 10 * time.Second}
	bot := teamsbot.New(teamsbot.Config{AppID: "app-id", AppPassword: "app-password", TenantID: "tenant"}, client).WithLoginBase(client, "https://login.microsoftonline.com")
	ref := ports.TeamsConversationRef{ServiceURL: "https://smba.trafficmanager.net/emea/", ConversationID: "19:conversation@thread.tacv2"}
	catalog := notificationbuiltin.New()

	for _, locale := range []tenancy.Locale{tenancy.LocaleEnglish, tenancy.LocaleVietnamese} {
		for _, message := range acceptanceMessages() {
			rendered := renderBuiltin(t, catalog, message, locale)
			if strings.TrimSpace(rendered.Fields["title"]) == "" || strings.TrimSpace(rendered.Fields["body"]) == "" {
				t.Fatalf("%s/%s rendered an empty field: %+v", message.name, locale, rendered.Fields)
			}
			formatted, err := messageformat.Teams(rendered)
			if err != nil {
				t.Fatalf("%s/%s format: %v", message.name, locale, err)
			}
			activity, err := bot.Send(context.Background(), ref, teamsActivity(formatted.Body))
			if err != nil {
				t.Fatalf("%s/%s send: %v", message.name, locale, err)
			}
			if activity == "" {
				t.Fatalf("%s/%s got no activity id", message.name, locale)
			}
		}
	}
	if len(fake.activities) != 2*len(acceptanceMessages()) {
		t.Fatalf("connector received %d activities, want %d", len(fake.activities), 2*len(acceptanceMessages()))
	}
	for i, activity := range fake.activities {
		if activity["type"] != "message" {
			t.Fatalf("activity %d is not a message: %v", i, activity["type"])
		}
		attachments, ok := activity["attachments"].([]any)
		if !ok || len(attachments) != 1 {
			t.Fatalf("activity %d carries %v attachments", i, activity["attachments"])
		}
		attachment, ok := attachments[0].(map[string]any)
		if !ok || attachment["contentType"] != "application/vnd.microsoft.card.adaptive" {
			t.Fatalf("activity %d is not one Adaptive Card: %v", i, attachments[0])
		}
	}
	// The injection message is the last of each locale. Its constructs must reach
	// the recipient as text, in one TextRun, with no Markdown-parsing TextBlock
	// and no link action built from a value.
	for _, index := range []int{len(acceptanceMessages()) - 1, 2*len(acceptanceMessages()) - 1} {
		raw, err := json.Marshal(fake.activities[index])
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), `"TextBlock"`) {
			t.Fatalf("the injection message used a Markdown-parsing TextBlock: %s", raw)
		}
		if strings.Contains(string(raw), `"Action.OpenUrl"`) && strings.Contains(string(raw), "evil.example") {
			t.Fatalf("a value became a link action: %s", raw)
		}
		found := false
		for _, run := range cardRuns(t, fake.activities[index]) {
			if strings.Contains(run, injectionTitle) {
				found = true
			}
		}
		if !found {
			t.Fatalf("the injection value did not arrive as one literal run: %s", raw)
		}
	}
}

// cardRuns returns the text of every TextRun in the card, which is everything the
// recipient sees.
func cardRuns(t *testing.T, activity map[string]any) []string {
	t.Helper()
	raw, err := json.Marshal(activity)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Attachments []struct {
			Content struct {
				Body []struct {
					Inlines []struct {
						Text string `json:"text"`
					} `json:"inlines"`
				} `json:"body"`
			} `json:"content"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	var runs []string
	for _, attachment := range payload.Attachments {
		for _, block := range attachment.Content.Body {
			for _, inline := range block.Inlines {
				runs = append(runs, inline.Text)
			}
		}
	}
	return runs
}
