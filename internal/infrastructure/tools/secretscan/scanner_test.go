package secretscan

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixture secrets are BUILT BY CONCATENATION so no full token literal appears in this source file (avoids
// tripping secret scanners on our own tests) and none is a real credential.
var (
	awsID     = "AKIA" + "Z2K7QMN4TJ5VWXY9"          // matches AKIA + 16
	ghToken   = "ghp_" + strings.Repeat("aB3dE6", 7) // ghp_ + 42 chars (>= 36)
	highEnt   = highEntropyFixture()                 // 32 hex chars – derived from hash at runtime, never a literal
	privBlock = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIByz==\n-----END RSA PRIVATE KEY-----"
)

// highEntropyFixture returns a 28-char base64 string derived from a SHA-256 digest (entropy > 3.5
// so the generic-secret rule matches). The value is deterministic but never appears as a literal in
// the binary or source, so secret scanners cannot flag it.
func highEntropyFixture() string {
	h := sha256.Sum256([]byte("synapse-test-fixture-not-a-real-secret"))
	return base64.RawStdEncoding.EncodeToString(h[:21]) // 28 chars
}

func scanDir(t *testing.T, files map[string]string) []secretResult {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	report, err := New().ScanFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	out := make([]secretResult, len(report.Findings))
	for i, r := range report.Findings {
		out[i] = secretResult{r.RuleID, r.File, r.Match}
	}
	return out
}

type secretResult struct{ rule, file, match string }

func hasRule(rs []secretResult, id string) *secretResult {
	for i := range rs {
		if rs[i].rule == id {
			return &rs[i]
		}
	}
	return nil
}

func TestDetectsCommonSecrets(t *testing.T) {
	rs := scanDir(t, map[string]string{
		"config.env":    "aws_access_key_id = \"" + awsID + "\"\n",
		"ci.yml":        "token: \"" + ghToken + "\"\n",
		"settings.json": "{\"api_key\": \"" + highEnt + "\"}\n",
		"id_rsa":        privBlock,
	})
	for _, id := range []string{"aws-access-key-id", "github-token", "generic-secret", "private-key"} {
		if hasRule(rs, id) == nil {
			t.Errorf("expected a %q finding, got %+v", id, rs)
		}
	}
}

// The raw secret must NEVER appear in the returned Match (redaction / golden rule 3).
func TestRedactsMatch(t *testing.T) {
	rs := scanDir(t, map[string]string{
		"a.txt":  "aws_access_key_id=\"" + awsID + "\"",
		"id_rsa": privBlock,
	})
	for _, r := range rs {
		if strings.Contains(r.match, awsID) {
			t.Errorf("Match leaked the full AWS key: %q", r.match)
		}
		if r.rule == "private-key" && r.match != "<private key redacted>" {
			t.Errorf("private key not redacted: %q", r.match)
		}
		if r.rule == "aws-access-key-id" && !strings.Contains(r.match, "*") {
			t.Errorf("AWS match not masked: %q", r.match)
		}
	}
}

// Documentation placeholders and example values are allow-listed.
func TestAllowlistSkipsPlaceholders(t *testing.T) {
	rs := scanDir(t, map[string]string{
		"example.env": "aws_access_key_id = \"AKIA" + "EXAMPLEQKZ7N4TJ5\"\n", // contains EXAMPLE
		"tpl.yml":     "api_key = \"changeme\"\n",
		"vars.tf":     "token = \"${var.api_token}\"\n",
	})
	if len(rs) != 0 {
		t.Errorf("placeholders must be allow-listed, got %+v", rs)
	}
}

// The generic rule is entropy-gated: a low-entropy assignment is not a secret.
func TestEntropyGate(t *testing.T) {
	rs := scanDir(t, map[string]string{
		"low.env": "api_key = \"aaaaaaaaaaaaaaaa\"\n", // 16 chars, entropy 0
	})
	if hasRule(rs, "generic-secret") != nil {
		t.Errorf("low-entropy value must not be flagged, got %+v", rs)
	}
}

// Vendored dirs and binary files are skipped.
func TestSkipsVendorAndBinary(t *testing.T) {
	rs := scanDir(t, map[string]string{
		"node_modules/pkg/leak.env": "aws_access_key_id = \"" + awsID + "\"\n",
		"blob.bin":                  "aws_access_key_id = \"" + awsID + "\"\x00binary\n",
	})
	if len(rs) != 0 {
		t.Errorf("vendored + binary files must be skipped, got %+v", rs)
	}
}

// Re-scanning is deterministic (same file+line dedup) and line numbers are correct.
func TestLineNumberAndDedup(t *testing.T) {
	rs := scanDir(t, map[string]string{
		"c.env": "line1\nline2\naws_access_key_id = \"" + awsID + "\"\n",
	})
	f := hasRule(rs, "aws-access-key-id")
	if f == nil {
		t.Fatalf("no aws finding: %+v", rs)
	}
	if !strings.HasPrefix(f.file, "c.env") {
		t.Errorf("file = %q, want c.env", f.file)
	}
}

// A symlink pointing OUT of the workspace must not be followed (no reading the operator's own secrets).
func TestScanIgnoresSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "host-secret.env")
	if err := os.WriteFile(outside, []byte("aws_access_key_id = \""+awsID+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "linked.env")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	report, err := New().ScanFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Errorf("must not follow a symlink out of the workspace, got %d findings", len(report.Findings))
	}
}

func TestScanContextCancellationErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().ScanFiles(ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("ScanFiles error=%v, want context canceled", err)
	}
}

func TestScanTruncatesAggregateBudgets(t *testing.T) {
	secret := "secret = \"" + highEnt + "\"\n"
	for _, tc := range []struct {
		name   string
		files  map[string]string
		limits scanLimits
	}{
		{name: "bytes", files: map[string]string{"a.env": secret, "b.env": secret}, limits: scanLimits{files: 10, bytes: int64(len(secret)), findings: 10}},
		{name: "findings", files: map[string]string{"a.env": secret, "b.env": secret}, limits: scanLimits{files: 10, bytes: 1 << 20, findings: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, data := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			report, err := New().scanFiles(context.Background(), dir, tc.limits)
			if err != nil || !report.Truncated || len(report.Findings) > tc.limits.findings {
				t.Fatalf("report=%+v err=%v", report, err)
			}
		})
	}
}

func TestVBGenericSecretAndComments(t *testing.T) {
	rs := scanDir(t, map[string]string{
		"config.vb": `Dim apiKey As String = "` + highEnt + `"
Const Private token = "` + highEnt + `"
[ApiKey] = "` + highEnt + `"
token$ = "` + highEnt + `"
Dim note = "quoted ""apostrophe ' and Rem"""
' Dim apiKey = "` + highEnt + `"
Rem Const token = "` + highEnt + `"
x = 1 : Rem Dim secret = "` + highEnt + `"
`,
	})
	if got := 0; hasRule(rs, "generic-secret") != nil {
		for _, r := range rs {
			if r.rule == "generic-secret" {
				got++
				if !strings.Contains(r.match, "*") || strings.Contains(r.match, highEnt) {
					t.Fatalf("VB secret not redacted: %q", r.match)
				}
			}
		}
		if got != 4 {
			t.Fatalf("generic VB findings=%d, want 4: %+v", got, rs)
		}
	} else {
		t.Fatalf("expected generic VB secret finding: %+v", rs)
	}
}

func TestOpenAndReadRegularRejectsFileGrownAfterWalk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.env")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	walkInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, maxFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := openAndReadRegular(root, "config.env", walkInfo, maxTotalScanBytes); err == nil {
		t.Fatal("openAndReadRegular accepted file grown beyond maxFileBytes")
	}
}

func TestScanReadFailureMarksReportTruncated(t *testing.T) {
	scanner := New()
	scanner.openAndRead = func(*os.Root, string, fs.FileInfo, int64) ([]byte, error) {
		return nil, errors.New("read failed")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte("not-a-secret-placeholder\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := scanner.ScanFiles(context.Background(), dir)
	if err != nil || !report.Truncated || len(report.Findings) != 0 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func TestEmptyDirNoError(t *testing.T) {
	if rs := scanDir(t, map[string]string{}); len(rs) != 0 {
		t.Errorf("empty dir: %+v", rs)
	}
}

// TestGenericSecretKeyShapes covers the key shapes real config files use: the bare word the rule
// always handled, a camelCase key (NodeGoat config/env/all.js), and a bracketed config key
// (Vulnerable-Flask-App app.py). The value guards are unchanged, so the low-entropy and
// placeholder cases must stay silent.
func TestGenericSecretKeyShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		file string
		line string
		want bool
	}{
		{name: "bare key", file: "a.json", line: "{\"api_key\": \"" + highEnt + "\"}", want: true},
		{name: "camelCase key", file: "config/env/all.js", line: "    cookieSecret: \"" + highEnt + "\",", want: true},
		{name: "suffixed snake key", file: "b.py", line: "SECRET_KEY_HMAC = \"" + highEnt + "\"", want: true},
		{name: "bracket config key", file: "app.py", line: "app.config['SECRET_KEY_HMAC_2'] = \"" + highEnt + "\"", want: true},
		{name: "vb bracketed keyword", file: "c.vb", line: "Dim [secret] As String = \"" + highEnt + "\"", want: true},
		{name: "low entropy value", file: "d.env", line: "cookieSecret = \"aaaaaaaaaaaaaaaa\"", want: false},
		{name: "placeholder value", file: "e.env", line: "cookieSecret = \"${COOKIE_SECRET}\"", want: false},
		{name: "short value", file: "f.py", line: "app.config['SECRET_KEY'] = 'secret'", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rs := scanDir(t, map[string]string{tc.file: tc.line + "\n"})
			if got := hasRule(rs, "generic-secret") != nil; got != tc.want {
				t.Errorf("generic-secret fired = %v, want %v (%+v)", got, tc.want, rs)
			}
		})
	}
}

func TestDetectsDistinctivePrefixTokens(t *testing.T) {
	// Each fixture token is split into a prefix + body concatenation so no contiguous secret-shaped
	// literal exists in this source file (that would trip repository push-protection). Go joins the
	// literals at compile time, so the file the scanner reads still holds the whole token.
	rs := scanDir(t, map[string]string{
		"dockerhub.env": "DOCKERHUB_TOKEN=dckr_pat_" + "kQ9mZ2vX7bN4jH1pL6rT8wY3sD5" + "\n",
		"stripe.env":    "STRIPE_KEY=rk_live_" + "9pQ2mZ7vX4bN1jH6rT8wY3sD" + "\n",
		"gitlab.yml":    "trigger: glptt-" + "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0" + "\n",
		"pulumi.env":    "PULUMI_ACCESS_TOKEN=pul-" + "f0e1d2c3b4a5968778695a4b3c2d1e0f9a8b7c6d" + "\n",
		"clojars.env":   "CLOJARS_TOKEN=CLOJARS_" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567" + "\n", // 60 chars after the prefix
	})
	for _, id := range []string{"dockerhub-pat", "stripe-restricted-key", "gitlab-pipeline-trigger-token", "pulumi-access-token", "clojars-deploy-token"} {
		if hasRule(rs, id) == nil {
			t.Errorf("expected a %q finding, got %+v", id, rs)
		}
	}
}

func TestDistinctivePrefixPlaceholdersAllowlisted(t *testing.T) {
	// A docs placeholder that MATCHES the pattern but embeds a global allow-list term (EXAMPLE) must be
	// suppressed. This applies to the variable-length base64/alnum tokens; the fixed hex tokens cannot
	// embed a word and are covered by the near-miss test below.
	rs := scanDir(t, map[string]string{
		"dockerhub.md": "token: dckr_pat_" + "EXAMPLE00000000000000000000" + "\n",
		"stripe.md":    "key: rk_live_" + "EXAMPLE0000000000000000000" + "\n",
	})
	if len(rs) != 0 {
		t.Errorf("allow-listed placeholders must be suppressed, got %+v", rs)
	}
}

func TestDistinctivePrefixNearMissNoMatch(t *testing.T) {
	// Values that share the prefix but not the exact token shape must NOT match, so a lookalike is not a
	// false positive.
	rs := scanDir(t, map[string]string{
		"gitlab.yml":  "trigger: glptt-abcdef\n",       // far short of 40 hex
		"pulumi.env":  "PULUMI=pul-notlonghex\n",       // not 40 hex (non-hex chars)
		"clojars.env": "CLOJARS_TOKEN=CLOJARS_short\n", // not 60 alnum
	})
	if len(rs) != 0 {
		t.Errorf("near-miss lookalikes must not match, got %+v", rs)
	}
}

func TestInlineAllowSuppressesLine(t *testing.T) {
	// Control: the AWS key is reported without an annotation.
	reported := scanDir(t, map[string]string{"a.env": "aws_access_key_id=\"" + awsID + "\"\n"})
	if hasRule(reported, "aws-access-key-id") == nil {
		t.Fatalf("control: the key must be reported without an annotation, got %+v", reported)
	}
	// An inline allow annotation on the same line suppresses the finding (synapse:allow or, for drop-in
	// compatibility, gitleaks:allow).
	for _, marker := range []string{"synapse:allow", "gitleaks:allow", "SYNAPSE:ALLOW"} {
		rs := scanDir(t, map[string]string{"b.env": "aws_access_key_id=\"" + awsID + "\" # " + marker + "\n"})
		if len(rs) != 0 {
			t.Errorf("%q must suppress the finding, got %+v", marker, rs)
		}
	}
}

func TestDetectsSaaSProviderTokens(t *testing.T) {
	// Tokens split into prefix + body concatenations so no contiguous secret-shaped literal exists here.
	body := "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a" // 40 chars, meets each detector's minimum
	rs := scanDir(t, map[string]string{
		"sentry.env": "SENTRY_AUTH_TOKEN=sntrys_" + body + "\n",
		"readme.env": "README_API_KEY=rdme_" + body + "\n",
		"figma.env":  "FIGMA_TOKEN=figd_" + body + "\n",
	})
	for _, id := range []string{"sentry-auth-token", "readme-api-key", "figma-token"} {
		if hasRule(rs, id) == nil {
			t.Errorf("expected a %q finding, got %+v", id, rs)
		}
	}
}

func TestSaaSProviderTokensNearMissNoMatch(t *testing.T) {
	// Prefix present but the body is far too short: no match, so a lookalike is not a false positive.
	rs := scanDir(t, map[string]string{
		"a.env": "K=sntrys_short\n",
		"b.env": "K=rdme_short\n",
		"c.env": "K=figd_short\n",
	})
	if len(rs) != 0 {
		t.Errorf("near-miss lookalikes must not match, got %+v", rs)
	}
}
