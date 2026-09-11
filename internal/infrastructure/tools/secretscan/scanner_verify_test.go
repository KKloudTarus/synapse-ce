package secretscan

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// fakeVerifier records what it was asked to verify and returns a fixed verdict, so a test can prove the
// scanner passes the raw secret to the verifier while never letting the plaintext into a finding.
type fakeVerifier struct {
	verdict   ports.SecretVerdict
	calls     int
	gotRules  []string
	gotSecret string
}

func (f *fakeVerifier) Verify(_ context.Context, ruleID string, secret []byte) (ports.SecretVerdict, error) {
	f.calls++
	f.gotRules = append(f.gotRules, ruleID)
	f.gotSecret = string(secret)
	return f.verdict, nil
}

func writeSecretFixture(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.go"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func findByRule(rep ports.SecretScanReport, ruleID string) (ports.SecretRawFinding, bool) {
	for _, f := range rep.Findings {
		if f.RuleID == ruleID {
			return f, true
		}
	}
	return ports.SecretRawFinding{}, false
}

// The acceptance test for D6.3: a live-credential fixture verified against a (fake) provider returns
// verified, and the raw secret never appears in the finding (only a redacted preview).
func TestScanFilesVerifiedStampsVerdictAndRedacts(t *testing.T) {
	dir := writeSecretFixture(t, "package x\n\nconst gh = \""+ghToken+"\"\n")
	fv := &fakeVerifier{verdict: ports.SecretVerified}

	rep, err := New().ScanFilesVerified(context.Background(), dir, fv)
	if err != nil {
		t.Fatalf("verified scan: %v", err)
	}
	f, ok := findByRule(rep, "github-token")
	if !ok {
		t.Fatalf("the github token must be detected; findings=%+v", rep.Findings)
	}
	if f.Verified != ports.SecretVerified {
		t.Errorf("a live credential must be stamped verified, got %q", f.Verified)
	}
	// The verifier received the raw plaintext (it is confined to the scanner + the single call)...
	if fv.gotSecret != ghToken {
		t.Errorf("the verifier must receive the raw secret, got %q", fv.gotSecret)
	}
	// ...but the finding NEVER carries it: Match is a redacted preview only.
	if f.Match == ghToken || strings.Contains(f.Match, ghToken) {
		t.Errorf("the finding Match must be redacted, never the raw secret; got %q", f.Match)
	}
}

// The deterministic path (ScanFiles) makes no verdict: Verified stays unknown, so the SecretScanner
// contract (deterministic, offline) is preserved.
func TestScanFilesDeterministicLeavesVerdictUnknown(t *testing.T) {
	dir := writeSecretFixture(t, "package x\n\nconst gh = \""+ghToken+"\"\n")
	rep, err := New().ScanFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range rep.Findings {
		if f.Verified != ports.SecretUnknown {
			t.Errorf("ScanFiles must leave verdict unknown, got %q for %s", f.Verified, f.RuleID)
		}
	}
}

// A nil verifier falls back to the deterministic scan (no calls, unknown verdict).
func TestScanFilesVerifiedNilVerifierIsDeterministic(t *testing.T) {
	dir := writeSecretFixture(t, "package x\n\nconst gh = \""+ghToken+"\"\n")
	rep, err := New().ScanFilesVerified(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if _, ok := findByRule(rep, "github-token"); !ok {
		t.Fatal("the token must still be detected with a nil verifier")
	}
}

// The same credential repeated across files is verified once (per-scan dedup by rule + secret hash).
func TestScanFilesVerifiedDedupsProviderCalls(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.go", "b.go", "c.go"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("package x\nconst gh = \""+ghToken+"\"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fv := &fakeVerifier{verdict: ports.SecretVerified}
	if _, err := New().ScanFilesVerified(context.Background(), dir, fv); err != nil {
		t.Fatalf("verified scan: %v", err)
	}
	if fv.calls != 1 {
		t.Errorf("the same secret across files must be verified once, got %d calls", fv.calls)
	}
}

// The raw secret must never reach a log during a verified scan (acceptance: "raw secret never appears in
// logs/output"). Capture the default slog output around the scan and assert the token is absent.
func TestScanFilesVerifiedDoesNotLogSecret(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	dir := writeSecretFixture(t, "package x\n\nconst gh = \""+ghToken+"\"\n")
	if _, err := New().ScanFilesVerified(context.Background(), dir, &fakeVerifier{verdict: ports.SecretVerified}); err != nil {
		t.Fatalf("verified scan: %v", err)
	}
	if strings.Contains(buf.String(), ghToken) {
		t.Errorf("the raw secret must never be logged during a verified scan")
	}
}

// The per-scan verification cap bounds outbound provider calls: once maxSecretVerifications distinct
// credentials have been verified, further distinct secrets are left unknown without calling the verifier
// (a hostile-repo egress/rate-limit guard). Findings are unaffected; only calls are capped.
func TestVerifyStatePerScanCap(t *testing.T) {
	fv := &fakeVerifier{verdict: ports.SecretVerified}
	vf := &verifyState{ctx: context.Background(), verifier: fv, cache: map[string]ports.SecretVerdict{}, calls: maxSecretVerifications}
	if got := verdict(vf, "github-token", "ghp_overthecap00000000000000000000000000"); got != ports.SecretUnknown {
		t.Errorf("a secret past the per-scan cap must be unknown, got %q", got)
	}
	if fv.calls != 0 {
		t.Errorf("no provider call may be made past the cap, got %d", fv.calls)
	}
	// Under the cap, it still calls.
	vf2 := &verifyState{ctx: context.Background(), verifier: fv, cache: map[string]ports.SecretVerdict{}}
	if got := verdict(vf2, "github-token", "ghp_underthecap0000000000000000000000000"); got != ports.SecretVerified || fv.calls != 1 {
		t.Errorf("under the cap the verifier must be called, got %q calls=%d", got, fv.calls)
	}
}
