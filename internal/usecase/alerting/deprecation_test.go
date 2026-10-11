package alerting

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestWarnLegacyWebhookDeprecatedNamesRemovalRelease(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	WarnLegacyWebhookDeprecated(log, true)
	out := buf.String()
	if !strings.Contains(out, "level=WARN") {
		t.Fatalf("deprecation must log at warn level: %q", out)
	}
	if !strings.Contains(out, "removed in "+LegacyWebhookRemovalRelease) || !strings.Contains(out, "removal_release="+LegacyWebhookRemovalRelease) {
		t.Fatalf("warning does not name the removal release: %q", out)
	}
	if !strings.Contains(out, "incident.created") {
		t.Fatalf("warning does not name the replacement: %q", out)
	}
	// The helper never receives the URL, so nothing credential-bearing can appear.
	if strings.Contains(out, "https://") || strings.Contains(out, "http://") {
		t.Fatalf("warning leaked a URL: %q", out)
	}
}

func TestWarnLegacyWebhookDeprecatedSilentWhenUnset(t *testing.T) {
	var buf bytes.Buffer
	WarnLegacyWebhookDeprecated(slog.New(slog.NewTextHandler(&buf, nil)), false)
	WarnLegacyWebhookDeprecated(nil, true)
	if buf.Len() != 0 {
		t.Fatalf("unconfigured legacy webhook logged: %q", buf.String())
	}
}
