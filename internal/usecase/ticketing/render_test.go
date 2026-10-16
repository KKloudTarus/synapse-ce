package ticketing

import (
	"errors"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/messageformat"
)

func renderFinding() finding.Finding {
	return finding.Finding{ID: "finding-1", EngagementID: "engagement-1", Title: "SQL injection", Description: "Validate every input.", Severity: shared.SeverityHigh, Status: finding.StatusOpen}
}

func TestRenderTicketBuiltinsGoldenEnAndVietnamese(t *testing.T) {
	for _, locale := range []string{"en", "vi"} {
		t.Run(locale, func(t *testing.T) {
			summary, body, links, err := RenderTicket(domain.Mapping{}, renderFinding(), notification.DataClassDetail, locale, "https://console.example/app")
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile("testdata/ticket/" + locale + ".golden")
			if err != nil {
				t.Fatal(err)
			}
			if got := summary + "\n---\n" + body + "\n"; got != string(want) {
				t.Fatalf("render\n%s\nwant\n%s", got, want)
			}
			if len(links) != 1 || links[0].Label != "Open finding" || links[0].URL != "https://console.example/app/engagements/engagement-1/findings#finding-finding-1" {
				t.Fatalf("links = %#v", links)
			}
		})
	}
}

func TestRenderTicketFiltersAndEscapesHostileFindingText(t *testing.T) {
	f := renderFinding()
	f.Title = "{{panel}} @here *not bold*"
	syntheticCredential := "AKIA" + strings.Repeat("A", 16)
	f.Description = "password=" + syntheticCredential + " and [~admin] {macro}"
	m := domain.Mapping{SummaryTemplate: "{{.severity}} {{.title}} {{.description}}", DescriptionTemplate: "id={{.finding_id}} title={{.title}} desc={{.description}}"}
	summary, body, _, err := RenderTicket(m, f, notification.DataClassSignal, "en", "https://console.example")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(summary+body, "AKIA") || strings.Contains(summary+body, "SQL injection") || strings.Contains(summary+body, "{{panel}}") || strings.Contains(summary+body, "<no value>") {
		t.Fatalf("signal leaked filtered or unsafe text: %q / %q", summary, body)
	}

	_, body, links, err := RenderTicket(domain.Mapping{}, f, notification.DataClassDetail, "en", "https://console.example")
	if err != nil {
		t.Fatal(err)
	}
	adf, err := messageformat.JiraADF(body, links)
	if err != nil {
		t.Fatal(err)
	}
	if got := adf["content"].([]any); len(got) == 0 {
		t.Fatal("ADF has no content")
	}
	wiki, err := messageformat.JiraWiki(body, links)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(wiki, "{macro}") || strings.Contains(wiki, "[~admin]") || strings.Contains(wiki, "AKIA") {
		t.Fatalf("wiki macro/secret escaped incorrectly: %q", wiki)
	}
}

func TestRenderTicketScrubsLiteralTemplatesAndKeepsSummaryPlain(t *testing.T) {
	f := renderFinding()
	f.Title = "[input](https://example.test) *must validate*"
	m := domain.Mapping{
		SummaryTemplate:     "Credential token=literal-template-secret: {{.title}}",
		DescriptionTemplate: "password=literal-template-password\nFinding: {{.title}}",
	}
	summary, body, _, err := RenderTicket(m, f, notification.DataClassSummary, "en", "https://console.example")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(summary+body, "literal-template-secret") || strings.Contains(summary+body, "literal-template-password") || !strings.Contains(summary+body, privacy.RedactionPlaceholder) {
		t.Fatalf("literal template credential leaked: %q / %q", summary, body)
	}
	if strings.Contains(summary, `\[`) || strings.Contains(summary, `\*`) || !strings.Contains(summary, f.Title) {
		t.Fatalf("Jira summary retained Markdown escape artifacts: %q", summary)
	}
}

func TestRenderTicketSignalOmitsSensitiveTemplateVariables(t *testing.T) {
	f := renderFinding()
	f.Title = "customer database exposure"
	f.Description = "password=not-for-signal"
	m := domain.Mapping{SummaryTemplate: "{{.title}}/{{.description}}", DescriptionTemplate: "{{.description}}/{{.remediation}}"}
	summary, body, _, err := RenderTicket(m, f, notification.DataClassSignal, "en", "https://console.example")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(summary+body, f.Title) || strings.Contains(summary+body, "not-for-signal") || strings.Contains(summary+body, "<no value>") {
		t.Fatalf("signal output leaked sensitive variable: %q / %q", summary, body)
	}
}

func TestRenderTicketRejectsInvalidTemplateAndBoundsOutput(t *testing.T) {
	_, _, _, err := RenderTicket(domain.Mapping{SummaryTemplate: "{{.unknown}}", DescriptionTemplate: "body"}, renderFinding(), notification.DataClassSummary, "en", "https://console.example")
	if !errors.Is(err, msgtemplate.ErrInvalidTemplate) {
		t.Fatalf("invalid template error = %v", err)
	}
	f := renderFinding()
	f.Title = strings.Repeat("界", 10000)
	f.Description = strings.Repeat("x", 30000)
	summary, body, _, err := RenderTicket(domain.Mapping{}, f, notification.DataClassDetail, "en", "https://console.example")
	if err != nil {
		t.Fatal(err)
	}
	if utf8.RuneCountInString(summary) > 255 || len(body) >= 16<<10 {
		t.Fatalf("render bounds: summary=%d body=%d", utf8.RuneCountInString(summary), len(body))
	}
	if _, _, _, err := RenderTicket(domain.Mapping{}, renderFinding(), notification.DataClassSummary, "en", "https://console.example?token=bad"); err == nil {
		t.Fatal("untrusted console origin accepted")
	}
}
