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
// text/plain the value is shown as is, which is safe for a text/plain part.
func TestEmailInjectionValuesStayLiteral(t *testing.T) {
	for _, value := range injectionValues {
		clean := msgtemplate.Sanitize(value)
		message := ports.RenderedMessage{Fields: map[string]string{"subject": clean, "body": "Value: " + msgtemplate.EscapeMarkdown(clean)}}
		fragment, err := EmailHTML(message)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(fragment, "<script") || strings.Contains(fragment, "<img") || !strings.Contains(fragment, "Value: "+html.EscapeString(clean)) {
			t.Errorf("%q: HTML fragment %q", value, fragment)
		}
		out, err := Email{}.Format(message)
		if err != nil {
			t.Fatal(err)
		}
		if string(out.Body) != "Value: "+clean {
			t.Errorf("%q: text body %q", value, out.Body)
		}
		if strings.ContainsAny(out.Subject, "\r\n") {
			t.Errorf("%q: subject %q breaks the header", value, out.Subject)
		}
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
