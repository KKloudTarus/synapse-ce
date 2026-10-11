package consolelink

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestBuilderCreatesTypedConsoleLinks(t *testing.T) {
	b, err := NewBuilder("https://console.example/console/")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		build   func() (Link, error)
		kind    SubjectKind
		subject shared.ID
		href    string
	}{
		{"finding", func() (Link, error) { return b.Finding("eng-1", "find-1") }, KindFinding, "find-1", "https://console.example/console/engagements/eng-1/findings#finding-find-1"},
		{"scan", func() (Link, error) { return b.Scan("eng-1", "scan-1") }, KindScan, "scan-1", "https://console.example/console/engagements/eng-1/scanruns#scan-scan-1"},
		{"engagement", func() (Link, error) { return b.Engagement("eng-1") }, KindEngagement, "eng-1", "https://console.example/console/engagements/eng-1"},
		{"incident", func() (Link, error) { return b.Incident("inc-1") }, KindIncident, "inc-1", "https://console.example/console/fleet/incidents/inc-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			link, err := tc.build()
			if err != nil {
				t.Fatal(err)
			}
			if link.Kind() != tc.kind || link.SubjectID() != tc.subject || link.Href() != tc.href {
				t.Fatalf("link = %+v, want %s %s %s", link, tc.kind, tc.subject, tc.href)
			}
			u, err := url.Parse(link.Href())
			if err != nil || u.Scheme != "https" || u.Host != "console.example" {
				t.Fatalf("generated untrusted URL: %v, %v", u, err)
			}
		})
	}
}

func TestBuilderRejectsUnsafeOrigins(t *testing.T) {
	cases := []string{
		"", "http://console.example", "/relative", "//console.example", "https:console.example",
		"https://user:password@console.example", "https://console.example/path?token=secret",
		"https://console.example/#evil", "https://console.example/?",
		"https://console.example/%0a", "https://console.example/../admin",
		"https://console.example/%2e%2e/admin", "https://console.example/%252e%252e/admin",
		"https://console.example:65536/path", "https://console.example:0/path",
		"https://console.example:/path", "https://exa\u202emple.com", "https://ex\u200bample.com",
		"https://exa%E2%80%AEple.com", "https://exa%C2%A0ple.com", "https://ex%25ample.com",
		"https://console.example/%250a", "https://console.example\\@evil.example",
		"https://console.example\n.evil.example", " https://console.example",
	}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			_, err := NewBuilder(input)
			if !errors.Is(err, ErrInvalidOrigin) {
				t.Fatalf("unsafe origin accepted, err = %v", err)
			}
			if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "token=secret") {
				t.Fatal("origin validation leaked a credential")
			}
		})
	}
	for _, input := range []string{"https://console.example", "https://console.example/", "https://localhost:8443/synapse"} {
		if _, err := NewBuilder(input); err != nil {
			t.Fatalf("safe origin %s rejected: %v", input, err)
		}
	}
}

func TestBuilderEscapesIDsAndRejectsInvalidSubjects(t *testing.T) {
	b, err := NewBuilder("https://console.example")
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.Finding("eng/one", "f?x#frag")
	if err != nil {
		t.Fatal(err)
	}
	if got.Href() != "https://console.example/engagements/eng%2Fone/findings#finding-f%3Fx%23frag" {
		t.Fatalf("unescaped subject: %s", got.Href())
	}
	for _, id := range []shared.ID{"", ".", "..", "id\nheader", "id\u202eevil"} {
		if _, err := b.Finding("eng", id); !errors.Is(err, ErrInvalidSubject) {
			t.Fatalf("unsafe finding ID accepted (%q): %v", id, err)
		}
		if _, err := b.Scan(id, "scan"); !errors.Is(err, ErrInvalidSubject) {
			t.Fatalf("unsafe engagement ID accepted (%q): %v", id, err)
		}
	}
	if _, err := (Builder{}).Incident("inc"); !errors.Is(err, ErrInvalidOrigin) {
		t.Fatalf("zero-value builder generated a link: %v", err)
	}
}

func TestLinkSealedConstructionAndSafeJSON(t *testing.T) {
	b, err := NewBuilder("https://console.example")
	if err != nil {
		t.Fatal(err)
	}
	link, err := b.Incident("inc-123")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(link)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"kind":"incident","subject_id":"inc-123","href":"https://console.example/fleet/incidents/inc-123"}`
	if string(encoded) != want {
		t.Fatalf("typed link JSON = %s, want %s", encoded, want)
	}
	if _, err := json.Marshal(Link{}); !errors.Is(err, ErrInvalidOrigin) {
		t.Fatalf("zero-value link serialized: %v", err)
	}
	var forged Link
	if err := json.Unmarshal([]byte(`{"kind":"incident","subject_id":"inc-123","href":"https://evil.example"}`), &forged); err == nil {
		t.Fatal("untrusted JSON created a typed link")
	}
}
