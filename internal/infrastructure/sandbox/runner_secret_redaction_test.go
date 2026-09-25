package sandbox

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// The runner scrubs a tool's stdout and stderr before they reach the recon log or the evidence
// seal. The error took the same path to the same sinks and nothing scrubbed it, which became a
// leak once an initialization failure started quoting the tool's first stderr line: a tool that
// dies holding an injected token prints it, and the error carried it verbatim to the run record.
func TestRedactErrRemovesResolvedSecrets(t *testing.T) {
	secrets := [][]byte{[]byte("ghp_livetoken123"), []byte("s3cr3t-pass")}

	err := fmt.Errorf("toolrunner: initialize %q after start: %w (npm wrote: npm ERR! 401 with ghp_livetoken123)",
		"npm", errors.New("egress netns setup: no such process"))

	got := redactErr(err, secrets)
	if strings.Contains(got.Error(), "ghp_livetoken123") {
		t.Fatalf("error still carries the secret: %s", got)
	}
	if !strings.Contains(got.Error(), "[REDACTED]") {
		t.Fatalf("want the secret replaced with the placeholder, got %s", got)
	}
	// The cause must survive the scrub or every errors.Is downstream silently stops matching.
	if !strings.Contains(got.Error(), "initialize") {
		t.Errorf("the message lost its context: %s", got)
	}
	if !errors.Is(got, errors.Unwrap(errors.Unwrap(err))) && errors.Unwrap(got) == nil {
		t.Errorf("the original error must stay in the chain")
	}
}

// A URL that carries credentials is scrubbed even when the value is not in the secret list,
// which is what redact.Bytes already does for output.
func TestRedactErrStripsURLCredentials(t *testing.T) {
	err := errors.New("clone https://user:hunter2@example.com/repo.git failed")
	got := redactErr(err, nil)
	if strings.Contains(got.Error(), "hunter2") {
		t.Fatalf("URL credentials survived: %s", got)
	}
}

// Nothing to scrub must return the very same error, so error identity is untouched on the
// path every run takes.
func TestRedactErrKeepsIdentityWhenNothingToScrub(t *testing.T) {
	sentinel := shared.ErrValidation
	wrapped := fmt.Errorf("resolve egress policy: %w", sentinel)
	got := redactErr(wrapped, [][]byte{[]byte("unrelated")})
	if got != wrapped {
		t.Fatalf("an error with no secret in it must be returned unchanged")
	}
	if !errors.Is(got, sentinel) {
		t.Errorf("errors.Is must still match")
	}
	if redactErr(nil, nil) != nil {
		t.Errorf("a nil error must stay nil")
	}
}
