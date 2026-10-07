package notification

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
)

// TestBuildersScrubSecretsFromVariables is the #1361 golden test: secrets a scanner put in a
// finding title, or anywhere else a variable comes from, are gone from the snapshot before any
// template sees them, and the rest of the text is kept.
func TestBuildersScrubSecretsFromVariables(t *testing.T) {
	cases := []struct {
		name, title, want string
	}{
		{"AWS access key", "Leaked key AKIAIOSFODNN7EXAMPLE in config", "Leaked key [redacted] in config"},
		// The token is split so secret scanners do not flag the fixture, as the privacy tests do.
		{"bearer token", "Header Authorization: Bearer " + "eyJhbGciOiJIUzI1NiJ9" + ".payload.sig sent", "Header Authorization: Bearer [redacted] sent"},
		{"password assignment", "Default creds password=Hunter2! on admin", "Default creds password=[redacted] on admin"},
		{"PEM block", "Key -----BEGIN RSA PRIVATE KEY----- MIIEow -----END RSA PRIVATE KEY----- committed", "Key [redacted] committed"},
		{"URL credentials", "Clone from https://ci:s3cr3t@git.example.test/repo failed", "Clone from https://***@git.example.test/repo failed"},
		{"plain title", "SQL injection in /login", "SQL injection in /login"},
		// The snapshot removes invisible characters. A key split by one must not come back whole
		// with its value, so the value is scrubbed again after it is sanitized.
		{"zero width space in key", "Default creds pass" + zeroWidthSpace + "word=Hunter2! on admin", "Default creds password=[redacted] on admin"},
		{"soft hyphen in key", "Leaked to" + softHyphen + "ken=abc123def in log", "Leaked token=[redacted] in log"},
		{"word joiner in bearer", "Header Bear" + wordJoiner + "er " + "eyJhbGciOiJIUzI1NiJ9" + ".payload.sig sent", "Header Bearer [redacted] sent"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			snapshot := scrubbedSnapshot(t, projectTitle(t, c.title))
			for _, name := range []string{"finding_title", "reason", "title"} {
				if got := snapshot.Vars[name]; got != c.want {
					t.Errorf("%s = %q, want %q", name, got, c.want)
				}
			}
		})
	}
}

// TestBuildersScrubIsStableAcrossProjections projects an event, then projects the result again, as
// a replayed or re-normalized event is. The second snapshot must equal the first: a value that only
// matches a pattern once sanitized would otherwise be stored differently the second time.
func TestBuildersScrubIsStableAcrossProjections(t *testing.T) {
	for _, title := range []string{
		"Default creds pass" + zeroWidthSpace + "word=Hunter2! on admin",
		"Key -----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY----- committed",
		"Clone from https://ci:s3cr3t@git.example.test/repo failed",
		"SQL injection in /login",
	} {
		first := projectTitle(t, title)
		second, err := NewEventBuilders().Project(context.Background(), first)
		if err != nil {
			t.Fatal(err)
		}
		if string(second.Context) != string(first.Context) {
			t.Errorf("projecting %q again changed the snapshot:\n first  %s\n second %s", title, first.Context, second.Context)
		}
	}
}

var (
	zeroWidthSpace = string(rune(0x200b))
	softHyphen     = string(rune(0x00ad))
	wordJoiner     = string(rune(0x2060))
)

// projectTitle projects an ownership event whose title, finding title and reason are title.
func projectTitle(t *testing.T, title string) domain.Event {
	t.Helper()
	seed, err := domain.TemplateContext{Vars: map[string]string{"finding_title": title, "reason": title}}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	e := domain.Event{TenantID: "tenant-1", ID: "event", Type: domain.EventOwnershipChanged, SourceKind: "ownership_decision", SourceID: "d1",
		SchemaVersion: 1, OccurredAt: time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC), Data: json.RawMessage(`{"title":` + quote(title) + `}`), Context: seed}
	projected, err := NewEventBuilders().Project(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	return projected
}

func scrubbedSnapshot(t *testing.T, e domain.Event) domain.TemplateContext {
	t.Helper()
	snapshot, err := domain.DecodeTemplateContext(e.Context)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func quote(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}
