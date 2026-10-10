package messageformat

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestSlackGolden(t *testing.T) {
	out, err := Slack{}.Format(sampleMessage())
	if err != nil {
		t.Fatal(err)
	}
	if out.ContentType != "application/json" || !json.Valid(out.Body) {
		t.Fatalf("content type %q, valid JSON %v", out.ContentType, json.Valid(out.Body))
	}
	if !strings.Contains(string(out.Body), `"unfurl_links":false`) || !strings.Contains(string(out.Body), `"unfurl_media":false`) {
		t.Fatalf("Slack unfurls were not disabled: %s", out.Body)
	}
	var pretty strings.Builder
	var decoded any
	_ = json.Unmarshal(out.Body, &decoded)
	encoded, _ := json.MarshalIndent(decoded, "", "  ")
	pretty.Write(encoded)
	pretty.WriteByte('\n')
	checkGolden(t, "slack.json", []byte(pretty.String()))
}

// slackTexts collects every string Slack would display from the payload, with the style of each
// rich_text element, so the injection test can assert where a value ends up.
type displayedText struct {
	text  string
	style map[string]any
}

func slackTextsOf(t *testing.T, body []byte) (fallback string, header string, texts []displayedText) {
	t.Helper()
	var payload struct {
		Text   string           `json:"text"`
		Blocks []map[string]any `json:"blocks"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	var walk func(any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			if v["type"] == "text" {
				style, _ := v["style"].(map[string]any)
				texts = append(texts, displayedText{text: v["text"].(string), style: style})
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	for _, block := range payload.Blocks {
		if block["type"] == "header" {
			header = block["text"].(map[string]any)["text"].(string)
			continue
		}
		walk(block)
	}
	return payload.Text, header, texts
}

// Every injection value, interpolated as msgtemplate interpolates it, must arrive as one unstyled
// rich_text text element holding the value: Slack shows rich_text text literally, so no mention,
// link or formatting can be forged. In the title it must be plain_text, and in the mrkdwn fallback
// its control characters must be escaped.
func TestSlackInjectionValuesStayLiteral(t *testing.T) {
	for _, value := range injectionValues {
		clean := msgtemplate.Sanitize(value)
		// A template escapes a value in every field, the title included; the header shows it as it was.
		message := ports.RenderedMessage{Fields: map[string]string{"title": msgtemplate.EscapeMarkdown(clean), "body": "Value: " + msgtemplate.EscapeMarkdown(clean)}}
		out, err := Slack{}.Format(message)
		if err != nil {
			t.Fatalf("%q: %v", value, err)
		}
		fallback, header, texts := slackTextsOf(t, out.Body)
		if header != strings.Join(strings.Fields(clean), " ") {
			t.Errorf("%q: header %q", value, header)
		}
		if strings.ContainsAny(fallback, "<>") {
			t.Errorf("%q: fallback text %q carries an unescaped control character", value, fallback)
		}
		if len(texts) != 1 || texts[0].text != "Value: "+clean || texts[0].style != nil {
			t.Errorf("%q: rich text elements %+v", value, texts)
		}
		if strings.Contains(value, "\u202e") && strings.Contains(string(out.Body), "\u202e") {
			t.Errorf("%q: bidi override reached the payload", value)
		}
	}
}

func TestSlackStylesNestAndLinksComeOnlyFromLinks(t *testing.T) {
	message := ports.RenderedMessage{
		Fields: map[string]string{"body": "***both*** `code` [not](https://evil.test)"},
		Links:  []ports.RenderedLink{{Label: "Open", URL: "https://synapse.example.com/a"}, {Label: "", URL: "https://synapse.example.com/b"}},
	}
	out, err := Slack{}.Format(message)
	if err != nil {
		t.Fatal(err)
	}
	body := string(out.Body)
	for _, want := range []string{`"style":{"bold":true,"italic":true}`, `"style":{"code":true}`, `"text":" [not](https://evil.test)"`,
		`{"text":"Open","type":"link","url":"https://synapse.example.com/a"}`, `{"text":"synapse.example.com","type":"link","url":"https://synapse.example.com/b"}`} {
		if !strings.Contains(body, want) {
			t.Errorf("payload lacks %s:\n%s", want, body)
		}
	}
	if strings.Count(body, `"type":"link"`) != 2 {
		t.Errorf("payload has links other than the two typed ones:\n%s", body)
	}
}

func TestSlackRefusesUncheckedLinks(t *testing.T) {
	for _, raw := range []string{"http://synapse.example.com/a", "javascript:alert(1)", "https://user:pw@synapse.example.com/", "/relative", "https://synapse.example.com/a|b", "https://x.test/<>"} {
		_, err := Slack{}.Format(ports.RenderedMessage{Links: []ports.RenderedLink{{Label: "x", URL: raw}}})
		if !errors.Is(err, ErrInvalidLink) {
			t.Errorf("%q: err = %v", raw, err)
		}
	}
}

func TestSlackTitleIsBoundedAndEmptyPartsAreOmitted(t *testing.T) {
	out, err := Slack{}.Format(ports.RenderedMessage{Fields: map[string]string{"title": strings.Repeat("é", 200)}})
	if err != nil {
		t.Fatal(err)
	}
	_, header, texts := slackTextsOf(t, out.Body)
	if len([]rune(header)) != slackHeaderRunes || texts != nil {
		t.Fatalf("header runes %d, texts %v", len([]rune(header)), texts)
	}
	empty, _ := Slack{}.Format(ports.RenderedMessage{})
	if string(empty.Body) != `{"blocks":[],"text":"","unfurl_links":false,"unfurl_media":false}` {
		t.Fatalf("empty message = %s", empty.Body)
	}
}

// A title rendered from a template carries escaped values; the plain_text header shows the value,
// not the escape backslashes.
func TestSlackHeaderShowsTemplateValuesWithoutEscapes(t *testing.T) {
	value := "Lỗi <!channel> [Reset](https://evil.example) @everyone **bold**"
	out, err := Slack{}.Format(ports.RenderedMessage{Fields: map[string]string{"title": "Finding: " + msgtemplate.EscapeMarkdown(value), "body": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	_, header, _ := slackTextsOf(t, out.Body)
	if header != "Finding: "+value || strings.Contains(header, `\`) {
		t.Fatalf("header = %q", header)
	}
}
