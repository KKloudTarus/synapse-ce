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
			report, err := New().scanFiles(context.Background(), dir, tc.limits, nil)
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

func TestDetectsPrefixedProviderTokens(t *testing.T) {
	// Tokens split into prefix + body so no contiguous secret-shaped literal exists in this test source.
	// Each body is the exact length the detector's format requires (openshift/duffel 43, frame.io 64,
	// dnkey two base32-shaped chunks 26+52, atlassian/typeform a >=40 body).
	b := strings.Repeat("aB3cD4eF5g", 7) // 70 varied chars to slice from
	rs := scanDir(t, map[string]string{
		"atlassian.env": "ATLASSIAN_API_TOKEN=" + "ATATT3xFfGF0" + b[:40] + "\n",
		"openshift.env": "OC_TOKEN=" + "sha256~" + b[:43] + "\n",
		"duffel.env":    "DUFFEL_TOKEN=" + "duffel_live_" + b[:43] + "\n",
		"frameio.env":   "FRAMEIO_TOKEN=" + "fio-u-" + b[:64] + "\n",
		"dn.env":        "DN_API_KEY=" + "dnkey-" + b[:26] + "-" + b[:52] + "\n",
		"typeform.env":  "TYPEFORM_TOKEN=" + "tfp_" + b[:40] + "\n",
	})
	for _, id := range []string{"atlassian-api-token", "openshift-token", "duffel-api-token", "frameio-token", "definednetworking-token", "typeform-token"} {
		if hasRule(rs, id) == nil {
			t.Errorf("expected a %q finding, got %+v", id, rs)
		}
	}
}

func TestPrefixedProviderTokensNearMissNoMatch(t *testing.T) {
	// Prefix present but the body is far too short: a lookalike is not a false positive.
	rs := scanDir(t, map[string]string{
		"a.env": "K=" + "ATATT3xFfGF0" + "short\n",
		"b.env": "K=" + "sha256~" + "short\n",
		"c.env": "K=" + "duffel_live_" + "short\n",
		"d.env": "K=" + "fio-u-" + "short\n",
		"e.env": "K=" + "dnkey-" + "s\n",
		"f.env": "K=" + "tfp_" + "short\n",
	})
	if len(rs) != 0 {
		t.Errorf("near-miss lookalikes must not match, got %+v", rs)
	}
}

func TestDetectsMoreProviderTokens(t *testing.T) {
	// Prefix + body concatenations so no contiguous secret-shaped literal exists in this test source.
	an := strings.Repeat("aB3cD4eF5g", 9)   // 90 varied alnum chars
	b64 := strings.Repeat("aB3cD4eF5g", 25) // 250 base64-charset chars (1Password bodies are long JWTs)
	hx := strings.Repeat("abcdef0123", 4)   // 40 hex chars
	rs := scanDir(t, map[string]string{
		"prefect.env":      "PREFECT_API_KEY=" + "pnb_" + an[:36] + "\n", // service-account form covered by pn[ub]_
		"contentful.env":   "CONTENTFUL_TOKEN=" + "CFPAT-" + an[:43] + "\n",
		"shippo.env":       "SHIPPO_TOKEN=" + "shippo_live_" + hx[:40] + "\n",
		"onepassword.env":  "OP_SERVICE_ACCOUNT_TOKEN=" + "ops_eyJ" + b64[:250] + "\n",
		"gitlabrunner.env": "GITLAB_RUNNER_TOKEN=" + "GR1348941" + an[:20] + "\n",
		"easypost.env":     "EASYPOST_API_KEY=" + "EZAK" + an[:54] + "\n",
	})
	for _, id := range []string{"prefect-api-key", "contentful-token", "shippo-token", "onepassword-service-account", "gitlab-runner-token", "easypost-token"} {
		if hasRule(rs, id) == nil {
			t.Errorf("expected a %q finding, got %+v", id, rs)
		}
	}
}

func TestMoreProviderTokensNearMissNoMatch(t *testing.T) {
	rs := scanDir(t, map[string]string{
		"a.env": "K=" + "pnu_" + "short\n",
		"b.env": "K=" + "CFPAT-" + "short\n",
		"c.env": "K=" + "shippo_live_" + "nothex\n",
		"d.env": "K=" + "ops_eyJ" + "short\n",
		"e.env": "K=" + "GR1348941" + "short\n",
		"f.env": "K=" + "EZAK" + "short\n",
	})
	if len(rs) != 0 {
		t.Errorf("near-miss lookalikes must not match, got %+v", rs)
	}
}

func TestDetectsMoreProviderTokens2(t *testing.T) {
	an := strings.Repeat("aB3cD4eF5g", 6) // 60 alnum
	hx := strings.Repeat("abcdef0123", 7) // 70 hex
	rs := scanDir(t, map[string]string{
		"slack.env":   "SLACK_APP_TOKEN=" + "xapp-1-ABCDE12345F-1234567890123-" + hx[:64] + "\n",
		"intra42.env": "INTRA42_SECRET=" + "s-s4t2ud-" + hx[:64] + "\n",
		"yandex.env":  "YANDEX_API_KEY=" + "AQVN" + an[:36] + "\n",
		"notion.env":  "NOTION_TOKEN=" + "ntn_" + "12345678901" + an[:35] + "\n",
	})
	for _, id := range []string{"slack-app-token", "intra42-client-secret", "yandex-api-key", "notion-token"} {
		if hasRule(rs, id) == nil {
			t.Errorf("expected a %q finding, got %+v", id, rs)
		}
	}
}

func TestMoreProviderTokens2NearMissNoMatch(t *testing.T) {
	rs := scanDir(t, map[string]string{
		"a.env": "K=" + "xapp-1-short\n",
		"b.env": "K=" + "s-s4t2ud-short\n",
		"c.env": "K=" + "AQVNshort\n",
		"d.env": "K=" + "ntn_short\n",
	})
	if len(rs) != 0 {
		t.Errorf("near-miss lookalikes must not match, got %+v", rs)
	}
}

func TestDetectsMoreProviderTokens3(t *testing.T) {
	an := strings.Repeat("aB3cD4eF5g", 6) // 60 alnum
	hx := strings.Repeat("abcdef0123", 7) // 70 hex
	rs := scanDir(t, map[string]string{
		"flw.env": "FLW_SECRET_KEY=" + "FLWSECK_TEST-" + hx[:32] + "-X" + "\n",
		"ali.env": "ALIBABA_CLOUD_ACCESS_KEY_ID=" + "LTAI" + an[:20] + "\n",
		"aio.env": "ADAFRUIT_IO_KEY=" + "aio_" + an[:28] + "\n",
		"sg.env":  "SRC_ACCESS_TOKEN=" + "sgp_" + hx[:16] + "_" + hx[:40] + "\n", // v3 instance-scoped form
		"rep.env": "REPLICATE_API_TOKEN=" + "r8_" + an[:37] + "\n",
	})
	for _, id := range []string{"flutterwave-secret-key", "alibaba-access-key-id", "adafruit-io-key", "sourcegraph-access-token", "replicate-api-token"} {
		if hasRule(rs, id) == nil {
			t.Errorf("expected a %q finding, got %+v", id, rs)
		}
	}
}

func TestMoreProviderTokens3NearMissNoMatch(t *testing.T) {
	rs := scanDir(t, map[string]string{
		"a.env": "K=" + "FLWSECK_TEST-short\n",
		"b.env": "K=" + "LTAIshort\n",
		"c.env": "K=" + "aio_short\n",
		"d.env": "K=" + "sgp_short\n",
		"e.env": "K=" + "r8_short\n",
	})
	if len(rs) != 0 {
		t.Errorf("near-miss lookalikes must not match, got %+v", rs)
	}
}

func TestDetectsMoreProviderTokens4(t *testing.T) {
	an := strings.Repeat("aB3cD4eF5g", 6)          // 60 alnum
	hx := strings.Repeat("abcdef0123", 7)          // 70 hex
	d135 := strings.Repeat("aB3cD4eF5g", 14)[:135] // 135 base64url-ish
	rs := scanDir(t, map[string]string{
		"airtable.env":   "AIRTABLE_TOKEN=" + "pat" + an[:14] + "." + hx[:64] + "\n",
		"sonar.env":      "SONAR_TOKEN=" + "sqp_" + hx[:40] + "\n",
		"dropbox.env":    "DROPBOX_TOKEN=" + "sl." + d135 + "\n",
		"cloudinary.env": "CLOUDINARY_URL=" + "cloudinary://123456789012345:" + an[:27] + "@democloud" + "\n",
	})
	for _, id := range []string{"airtable-pat", "sonarqube-token", "dropbox-token", "cloudinary-url"} {
		if hasRule(rs, id) == nil {
			t.Errorf("expected a %q finding, got %+v", id, rs)
		}
	}
	// The Dropbox rule reports capture group 1 (the token without the trailing boundary char); it must be
	// redacted, never the raw body.
	if f := hasRule(rs, "dropbox-token"); f != nil && strings.Contains(f.match, d135) {
		t.Errorf("dropbox token not redacted: %q", f.match)
	}
}

func TestMoreProviderTokens4NearMissNoMatch(t *testing.T) {
	rs := scanDir(t, map[string]string{
		"a.env": "K=" + "patSHORT.short\n",
		"b.env": "K=" + "sqp_short\n",
		"c.env": "K=" + "sl.short\n",
		"d.env": "K=" + "cloudinary://short\n",
	})
	if len(rs) != 0 {
		t.Errorf("near-miss lookalikes must not match, got %+v", rs)
	}
}

func TestDetectsDiscordWebhook(t *testing.T) {
	an := strings.Repeat("aB3cD4eF5g", 8) // 80 alnum for the token body (60-110)
	rs := scanDir(t, map[string]string{
		"hook.env":   "DISCORD_WEBHOOK=https://discord.com/api/webhooks/123456789012345678/" + an[:70] + "\n",
		"canary.env": "H=https://canary.discordapp.com/api/webhooks/12345678901234567/" + an[:64] + "\n",
	})
	if hasRule(rs, "discord-webhook-url") == nil {
		t.Errorf("expected a discord-webhook-url finding, got %+v", rs)
	}
	// A bare discord URL with a too-short token must not match.
	rs2 := scanDir(t, map[string]string{
		"a.env": "K=https://discord.com/api/webhooks/123/short\n",
	})
	if len(rs2) != 0 {
		t.Errorf("near-miss discord URL must not match, got %+v", rs2)
	}
}

// TestGenericHighEntropyTuning is the D6.7 tuning test: it fixes the entropy threshold on
// real-looking-vs-random fixtures. High-entropy base64-alphabet blobs (the shape of real keys/tokens) MUST
// fire the keyword-free detector; hex hashes/SHAs, UUIDs, English prose, low-entropy runs, and short tokens
// MUST NOT (the 4.5 bits/char floor sits above the 4.0 hex maximum, so every hex string is excluded by
// construction). Values that must fire are hashed rather than written as literals so no real-looking secret
// appears in this source.
func TestGenericHighEntropyTuning(t *testing.T) {
	sum := func(s string) []byte { d := sha256.Sum256([]byte(s)); return d[:] }
	fires := []string{
		base64.StdEncoding.EncodeToString(sum("alpha")),    // 44 chars, ~6 bits/char
		base64.StdEncoding.EncodeToString(sum("bravo")),    // padded base64
		base64.RawURLEncoding.EncodeToString(sum("delta")), // url alphabet, no padding
	}
	for i, v := range fires {
		rs := scanDir(t, map[string]string{"f.txt": "value = \"" + v + "\"\n"})
		if hasRule(rs, "generic-high-entropy") == nil {
			t.Errorf("fires[%d] (a high-entropy base64 blob) must trigger generic-high-entropy: %q", i, v)
		}
	}

	benign := map[string]string{
		"sha256hex": "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03", // 64 hex ⇒ entropy 4.0
		"sha1hex":   "e83c5163316f89bfbde7d9ab23ca2e25604af290",                         // 40 hex (git SHA)
		"uuid":      "550e8400-e29b-41d4-a716-446655440000",                             // hex + dashes ⇒ < 4.0
		"english":   "the quick brown fox jumps over the lazy dog again and again now",  // prose ⇒ low entropy + spaces
		"repeated":  strings.Repeat("ab", 30),                                           // 60 chars, 2 symbols ⇒ entropy 1.0
		"shortish":  "abc123XYZ_short",                                                  // < 32 chars
	}
	for name, v := range benign {
		rs := scanDir(t, map[string]string{name + ".txt": "value = \"" + v + "\"\n"})
		if r := hasRule(rs, "generic-high-entropy"); r != nil {
			t.Errorf("benign %s (%q) must NOT trigger generic-high-entropy, got match %q", name, v, r.match)
		}
	}
}

// D6.7 (keyword-defer): a high-entropy value on a line WITH a secret keyword must NOT fire the keyword-free
// generic-high-entropy rule — it defers to the PROMOTED/gating generic-secret rule, so a keyword-context
// secret is never demoted to gate-exempt. A benign integrity/digest context is skipped entirely.
func TestGenericHighEntropyDefersToKeywordRules(t *testing.T) {
	sum := func(s string) []byte { d := sha256.Sum256([]byte(s)); return d[:] }
	blob := base64.StdEncoding.EncodeToString(sum("zeta"))

	rs := scanDir(t, map[string]string{"a.go": "password = \"" + blob + "\"\n"})
	if r := hasRule(rs, "generic-high-entropy"); r != nil {
		t.Errorf("a keyword-adjacent high-entropy value must defer to keyword rules, not fire generic-high-entropy: %+v", r)
	}
	if hasRule(rs, "generic-secret") == nil {
		t.Errorf("the keyword-anchored generic-secret rule must still catch (and gate) the keyword-context secret")
	}

	// A benign integrity/SRI or digest context is a public hash, not a credential: skipped.
	for _, ctx := range []string{"integrity=\"" + blob + "\"", "digest: \"" + blob + "\"", "checksum = \"" + blob + "\""} {
		rsB := scanDir(t, map[string]string{"b.txt": ctx + "\n"})
		if r := hasRule(rsB, "generic-high-entropy"); r != nil {
			t.Errorf("a benign hash context (%q) must not fire generic-high-entropy: %+v", ctx, r)
		}
	}
}
