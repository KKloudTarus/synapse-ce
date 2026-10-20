package ticketproviders

import (
	"context"
	"encoding/json"
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
