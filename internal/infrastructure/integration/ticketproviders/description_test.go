package ticketproviders

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestServiceNowDescriptionRendersPlainSubsetAndPreservesLiteralData(t *testing.T) {
	literal := `Phát hiện giả lập: complete-content, v1.2! [Reset password](https://evil.invalid) <script>alert("x")</script> C:\work\file *literal* & data`
	body := "**Finding**\n" + msgtemplate.EscapeMarkdown(literal) + "\n\n- *Review* `C:\\work\\file`"
	trusted := "https://console.example/engagements/example/findings#finding-safe"
	a := &Adapter{provider: ServiceNowProvider, project: "incident"}
	formatted, err := a.FormatTicketDescription(body, []ports.RenderedLink{{Label: "Open finding", URL: trusted}})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := a.BuildTicketPayload(context.Background(), ports.TicketPayloadInput{Summary: "Synthetic finding", Description: formatted})
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Description string `json:"description"`
	}
	if err = json.Unmarshal(payload.Wire, &wire); err != nil {
		t.Fatal(err)
	}
	want := "Finding\n" + literal + "\n\n- Review C:\\work\\file\nOpen finding: " + trusted
	if wire.Description != want {
		t.Fatalf("description=%q want=%q", wire.Description, want)
	}
	if strings.Contains(wire.Description, `complete\-content`) || strings.Contains(wire.Description, `giả lập\:`) {
		t.Fatal("Markdown escapes leaked into plain description")
	}
}

func TestMarkdownTicketDescriptionsRetainLiteralEscapes(t *testing.T) {
	body := "**Finding**\n" + msgtemplate.EscapeMarkdown("literal *text*: v1.2")
	for _, provider := range []integration.Provider{GitHubProvider, GitLabProvider, LinearProvider} {
		t.Run(string(provider), func(t *testing.T) {
			a := &Adapter{provider: provider}
			raw, err := a.FormatTicketDescription(body, nil)
			if err != nil {
				t.Fatal(err)
			}
			var got string
			if err := json.Unmarshal(raw, &got); err != nil || got != body {
				t.Fatalf("body=%q err=%v", got, err)
			}
		})
	}
}

func TestAzureDescriptionRendersSafeHTMLAtPayloadBoundary(t *testing.T) {
	literal := `Phát hiện: v1.2! <img src=x onerror=alert(1)> [Reset](https://evil.invalid) & data`
	body := "**Finding**\n" + msgtemplate.EscapeMarkdown(literal) + "\n\n- *Review* `file.go`"
	links := []ports.RenderedLink{{Label: "Open finding & report", URL: "https://console.example/findings?a=1&b=2"}}
	a := &Adapter{provider: AzureProvider}
	formatted, err := a.FormatTicketDescription(body, links)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := a.BuildTicketPayload(context.Background(), ports.TicketPayloadInput{Summary: "Finding", Description: formatted, Links: links})
	if err != nil {
		t.Fatal(err)
	}
	got := azureDescription(t, payload)
	want := "<p><strong>Finding</strong><br>\nPhát hiện: v1.2! &lt;img src=x onerror=alert(1)&gt; [Reset](https[:]//evil[.]invalid) &amp; data</p>\n<ul>\n<li><em>Review</em> <code>file.go</code></li>\n</ul>\n<p><a href=\"https://console.example/findings?a=1&amp;b=2\" rel=\"noopener noreferrer\">Open finding &amp; report</a></p>\n"
	if got != want {
		t.Fatalf("description=%q want=%q", got, want)
	}
	if output := os.Getenv("SYNAPSE_TICKET_PREVIEW_DIR"); output != "" {
		if err := os.MkdirAll(output, 0700); err != nil {
			t.Fatal(err)
		}
		page := "<!doctype html><html lang=\"vi\"><meta charset=\"utf-8\"><title>Azure description fixture</title><body><p>Local serializer preview · synthetic data · no native Azure acceptance</p><hr>" + got + "</body></html>"
		if err := os.WriteFile(filepath.Join(output, "azure-description.html"), []byte(page), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAzureDirectPayloadEscapesUntrustedHTMLAndBodyLinks(t *testing.T) {
	a := &Adapter{provider: AzureProvider}
	body := `<script>alert(1)</script> <a href="https://evil.invalid">click</a> https://evil.invalid`
	raw, _ := json.Marshal(body)
	payload, err := a.BuildTicketPayload(context.Background(), ports.TicketPayloadInput{Summary: "Finding", Description: raw})
	if err != nil {
		t.Fatal(err)
	}
	got := azureDescription(t, payload)
	if !strings.Contains(got, "<p>&lt;script&gt;") || strings.Contains(got, "<a ") || strings.Contains(got, "https://evil.invalid") {
		t.Fatalf("unsafe or unformatted description: %q", got)
	}
}

func TestAzureDescriptionRejectsUnsafeTypedLinksAtBothBoundaries(t *testing.T) {
	a := &Adapter{provider: AzureProvider}
	for _, target := range []string{"http://console.example", "https://user:password@console.example", "https://console.example/a\n", "https://console.example/a b", `https://console.example/"onclick=x`} {
		t.Run(target, func(t *testing.T) {
			links := []ports.RenderedLink{{Label: "Open", URL: target}}
			if _, err := a.FormatTicketDescription("Finding", links); err == nil {
				t.Fatal("formatter accepted unsafe link")
			}
			if _, err := a.BuildTicketPayload(context.Background(), ports.TicketPayloadInput{Summary: "Finding", Description: json.RawMessage(`"Finding"`), Links: links}); err == nil {
				t.Fatal("direct builder accepted unsafe link")
			}
		})
	}
}

func azureDescription(t *testing.T, payload ports.TicketPayload) string {
	t.Helper()
	var patch []struct {
		Path  string `json:"path"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(payload.Wire, &patch); err != nil {
		t.Fatal(err)
	}
	for _, operation := range patch {
		if operation.Path == "/fields/System.Description" {
			return operation.Value
		}
	}
	t.Fatal("description missing")
	return ""
}
