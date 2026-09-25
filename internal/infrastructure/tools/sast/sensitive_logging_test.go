package sast

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestSensitiveDataLoggingCoversStandardLoggers pins the receivers and methods the rule has to reach. The
// old pattern accepted only logger/console with info|log|warn|error|debug, which misses the standard
// library of the two languages this fires on most: Python writes logger.warning and logging.error, and the
// method alternation stopped at "warn", so "warning(" could not match at all. Found on a real service where
// logger.warning("... token=%s", token) went unreported while a competitor flagged it.
func TestSensitiveDataLoggingCoversStandardLoggers(t *testing.T) {
	dir := t.TempDir()
	flagged := map[string]string{
		"py_warning.py":   "logger.warning(\"Redis release failed for token=%s: %s\", token, exc)\n",
		"py_logging.py":   "logging.error(\"secret rotation failed: %s\", secret)\n",
		"py_exception.py": "logger.exception(\"reset_url=%s\", url)\n",
		"go_printf.go":    "log.Printf(\"auth failed for bearer %s\", bearer)\n",
		"go_slog.go":      "slog.Info(\"issued\", \"api_key\", k)\n",
	}
	// The multi-line shape: the call opens on one line and the sensitive argument arrives on the next.
	// A line pattern cannot see this, which is how three real findings were missed on a live service.
	flagged["py_multiline.py"] = "logger.warning(\n    \"token refresh failed for %s\",\n    refresh_token,\n)\n"
	flagged["py_multiline_kw.py"] = "logger.info(\n    \"issued\",\n    extra={\"api_key\": key},\n)\n"

	// Must stay silent: a logger receiver that only looks like one, and a log line with no sensitive field.
	quiet := map[string]string{
		// A multi-line call carrying nothing sensitive must stay silent too, so the block test cannot
		// degrade into "any logger call spanning lines".
		"plain_multiline.py": "logger.info(\n    \"processed %d orders\",\n    count,\n)\n",
		"catalog.py":         "catalog.info(\"item %s\", name)\n",
		"backlog.go": "backlog.debug(\"queued %d\", n)\n",
		"plain.py":   "logger.info(\"user %s logged in\", username)\n",
	}
	for name, body := range flagged {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range quiet {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	found, err := New().AnalyzeSource(context.Background(), dir)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	hit := map[string]bool{}
	for _, f := range found {
		if f.RuleID == "sensitive-data-logging" {
			hit[f.File] = true
		}
	}
	for name := range flagged {
		if !hit[name] {
			t.Errorf("sensitive logging not reported in %s", name)
		}
	}
	for name := range quiet {
		if hit[name] {
			t.Errorf("%s must not be reported: it logs no sensitive field", name)
		}
	}
}
