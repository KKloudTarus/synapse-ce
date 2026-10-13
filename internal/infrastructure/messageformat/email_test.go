package messageformat

import (
	"errors"
	"html"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestEmailGolden(t *testing.T) {
	out, err := Email{}.Format(sampleMessage())
	if err != nil {
		t.Fatal(err)
	}
	if out.ContentType != "text/plain; charset=UTF-8" || out.Subject != "[Synapse] Critical finding in payments-api" {
		t.Fatalf("content type %q subject %q", out.ContentType, out.Subject)
	}
	checkGolden(t, "email.txt", out.Body)
	fragment, err := EmailHTML(sampleMessage())
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile(filepath.Join("testdata", "email.html"))
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.TrimSpace(string(golden)); strings.TrimSpace(fragment) != want {
		t.Errorf("email.html changed:\n got  %s\n want %s", fragment, want)
	}
}

// In HTML every value must be escaped text: no tag, attribute or entity from a value survives. In
// text/plain the value is shown as literal text. URL-looking values are visibly defanged so email
// clients cannot turn event data into an actionable link.
func TestEmailInjectionValuesStayLiteral(t *testing.T) {
	for _, value := range injectionValues {
		clean := msgtemplate.Sanitize(value)
		want := clean
		if strings.Contains(want, "https://evil.test") {
			want = strings.ReplaceAll(want, "https://evil.test", "https[:]//evil[.]test")
		}
		message := ports.RenderedMessage{Fields: map[string]string{"subject": clean, "body": "Value: " + msgtemplate.EscapeMarkdown(clean)}}
		fragment, err := EmailHTML(message)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(fragment, "<script") || strings.Contains(fragment, "<img") || !strings.Contains(fragment, "Value: "+html.EscapeString(want)) {
			t.Errorf("%q: HTML fragment %q", value, fragment)
		}
		out, err := Email{}.Format(message)
		if err != nil {
			t.Fatal(err)
		}
		if string(out.Body) != "Value: "+want {
			t.Errorf("%q: text body %q", value, out.Body)
		}
		if strings.ContainsAny(out.Subject, "\r\n") {
			t.Errorf("%q: subject %q breaks the header", value, out.Subject)
		}
	}
}

func TestEmailDefangsLiteralURLsButKeepsCheckedLinksActionable(t *testing.T) {
	message := ports.RenderedMessage{
		Fields: map[string]string{
			"subject": "Synthetic notification",
			"body": "Values: " + msgtemplate.EscapeMarkdown("https://evil.com/path?x=1, http://bad.example). www.attacker.example/next!") +
				"\n\nCode `https://code.example/a`; **https://strong.example/** and _www.emphasis.example_.",
		},
		Links: []ports.RenderedLink{{Label: "Open finding", URL: "https://synapse.example.com/engagements/e1/findings/f1"}},
	}

	out, err := Email{}.Format(message)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"https[:]//evil[.]com/path?x=1, http[:]//bad[.]example). www[.]attacker[.]example/next!",
		"https[:]//code[.]example/a",
		"https[:]//strong[.]example/",
		"www[.]emphasis[.]example",
		"Open finding: https://synapse.example.com/engagements/e1/findings/f1",
	} {
		if !strings.Contains(string(out.Body), want) {
			t.Errorf("text body missing %q: %q", want, out.Body)
		}
	}
	for _, forbidden := range []string{"https://evil.com", "http://bad.example", "www.attacker.example", "https://code.example", "https://strong.example", "www.emphasis.example"} {
		if strings.Contains(string(out.Body), forbidden) {
			t.Errorf("text body left literal URL %q: %q", forbidden, out.Body)
		}
	}

	fragment, err := EmailHTML(message)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"https[:]//evil[.]com/path?x=1, http[:]//bad[.]example). www[.]attacker[.]example/next!",
		"<code>https[:]//code[.]example/a</code>",
		"<strong>https[:]//strong[.]example/</strong>",
		"<em>www[.]emphasis[.]example</em>",
		`<a href="https://synapse.example.com/engagements/e1/findings/f1" rel="noopener noreferrer">Open finding</a>`,
	} {
		if !strings.Contains(fragment, want) {
			t.Errorf("HTML fragment missing %q: %q", want, fragment)
		}
	}
}

func TestEmailDefangsExplicitURLVariants(t *testing.T) {
	message := ports.RenderedMessage{Fields: map[string]string{
		"body": msgtemplate.EscapeMarkdown("https://user:secret@evil.com/redirect?next=https://nested.evil.com/x; http://[2001:db8::1]/route, https://localhost:8443/payload! https://tést.example/path. www.evil.com/nested?redirect=http://nested.example/"),
	}}

	out, err := (Email{}).Format(message)
	if err != nil {
		t.Fatal(err)
	}
	want := "https[:]//user:secret@evil[.]com/redirect?next=https[:]//nested[.]evil[.]com/x; http[:]//[2001:db8::1]/route, https[:]//localhost:8443/payload! https[:]//tést[.]example/path. www[.]evil[.]com/nested?redirect=http[:]//nested[.]example/"
	if got := string(out.Body); got != want {
		t.Errorf("text body = %q, want %q", got, want)
	}
	fragment, err := EmailHTML(message)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fragment, want) {
		t.Errorf("HTML fragment missing defanged variants: %q", fragment)
	}
}

func TestEmailSubjectIsOneBoundedLine(t *testing.T) {
	cases := map[string]string{
		"Line one\r\nBcc: victim@example.com": "Line one Bcc: victim@example.com",
		"  spaced\t\tout  ":                   "spaced out",
		strings.Repeat("a", 300):              strings.Repeat("a", emailSubjectRunes),
		"bidi\u202eevil":                      "bidievil",
	}
	for in, want := range cases {
		if got := EmailSubject(in); got != want {
			t.Errorf("EmailSubject(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEmailHTMLRefusesUncheckedLinks(t *testing.T) {
	if _, err := EmailHTML(ports.RenderedMessage{Links: []ports.RenderedLink{{Label: "x", URL: "javascript:alert(1)"}}}); !errors.Is(err, ErrInvalidLink) {
		t.Fatalf("err = %v", err)
	}
	if _, err := (Email{}).Format(ports.RenderedMessage{Links: []ports.RenderedLink{{Label: "x", URL: "http://x.test"}}}); !errors.Is(err, ErrInvalidLink) {
		t.Fatalf("err = %v", err)
	}
}
