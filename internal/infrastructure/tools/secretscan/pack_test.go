package secretscan

import (
	"strings"
	"testing"
)

// Detector fixtures are BUILT BY CONCATENATION so no full token literal appears in this source file
// (avoids tripping secret scanners on our own tests) and none is a real credential. A literal "@" in a
// connection string is written as \x40 for the same reason.
func TestDetectorPackTriggers(t *testing.T) {
	hex32 := strings.Repeat("0123456789abcdef", 2) // 32 hex, entropy 4.0
	at := "\x40"                                   // '@', kept out of source text
	cases := []struct {
		id      string
		file    string
		content string
	}{
		{"aws-secret-access-key", "a.env", "aws_secret_access_key = \"" + hex32 + "wJalrXbP" + "\""}, // 40 chars, entropy >= 4.0
		{"gcp-service-account-key", "key.json", "{\"type\": " + "\"service_account\"}"},
		{"azure-storage-key", "b.env", "AccountKey=" + strings.Repeat("Ab3Dz9", 14) + "ABCD" + "=="},
		{"github-fine-grained-pat", "c.txt", "t = \"github_pat_" + strings.Repeat("aB3dE6", 6) + "\""},
		{"npm-token", "d.npmrc", "_authToken=npm_" + strings.Repeat("aB3dE6", 6)},
		{"pypi-token", "e.cfg", "upload_token = pypi-" + strings.Repeat("aB3dE6", 9)},
		{"rubygems-token", "f.txt", "k = rubygems_" + strings.Repeat("0a1b2c", 8)},
		{"stripe-secret-key", "g.txt", "k = \"sk_live_" + strings.Repeat("aB3dE6", 4) + "\""},
		{"twilio-api-key", "h.txt", "sid = \"SK" + strings.Repeat("0a1b2c", 5) + "0a" + "\""},
		{"sendgrid-api-key", "i.txt", "k = \"SG." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 43) + "\""},
		{"slack-webhook-url", "j.txt", "u = \"https://hooks.slack.com/services/" + strings.Repeat("ABC12/", 8) + "\""},
		{"mailgun-api-key", "k.txt", "k = \"key-" + strings.Repeat("0a1b2c", 5) + "0a" + "\""},
		{"mailchimp-api-key", "l.txt", "k = \"" + strings.Repeat("0a1b2c", 5) + "0a" + "-us21\""},
		{"openai-api-key", "m.txt", "k = \"sk-" + strings.Repeat("aB3dE6", 4) + "\""},
		{"anthropic-api-key", "n.txt", "k = \"sk-ant-" + strings.Repeat("aB3dE6", 4) + "\""},
		{"digitalocean-token", "o.txt", "k = \"dop_v1_" + strings.Repeat("0a1b2c", 10) + "0a1b" + "\""},
		{"shopify-token", "p.txt", "k = \"shpat_" + strings.Repeat("0a1b2c", 5) + "0a" + "\""},
		{"square-token", "q.txt", "k = \"sq0atp-" + strings.Repeat("a", 22) + "\""},
		{"telegram-bot-token", "r.txt", "k = \"" + strings.Repeat("1", 9) + ":AA" + strings.Repeat("b", 33) + "\""},
		{"new-relic-key", "s.txt", "k = \"NRAK-" + strings.Repeat("a", 27) + "\""},
		{"dynatrace-token", "t.txt", "k = \"dt0c01." + strings.Repeat("A", 24) + "." + strings.Repeat("B", 64) + "\""},
		{"grafana-token", "u.txt", "k = \"glsa_" + strings.Repeat("a", 32) + "\""},
		{"planetscale-token", "v.txt", "k = \"pscale_pw_" + strings.Repeat("a", 32) + "\""},
		{"doppler-token", "w.txt", "k = \"dp.pt." + strings.Repeat("a", 40) + "\""},
		{"postman-api-key", "x.txt", "k = \"PMAK-" + strings.Repeat("0a1b2c", 4) + "-" + strings.Repeat("0a1b2c", 5) + "0a1b" + "\""},
		{"huggingface-token", "y.txt", "k = \"hf_" + strings.Repeat("a", 34) + "\""},
		{"sentry-dsn", "z.txt", "d = \"https://" + strings.Repeat("0a1b2c", 5) + "0a" + at + "o0.ingest.sentry.io/1234567\""},
		{"vault-token", "aa.txt", "k = \"hvs." + strings.Repeat("a", 24) + "\""},
		{"terraform-cloud-token", "ab.txt", "k = \"" + strings.Repeat("a", 14) + ".atlasv1." + strings.Repeat("b", 60) + "\""},
		{"datadog-api-key", "ac.env", "datadog_api_key = \"" + hex32 + "\""},
		{"db-connection-string", "ad.env", "DSN = postgres://app:" + "S3cretP4ssw0rd" + at + "db.internal:5432/appdb"},
		{"putty-private-key", "id.ppk", "PuTTY-User-Key-File" + "-3: ssh-ed25519"},
		{"age-secret-key", "ae.txt", "k = \"AGE-SECRET-KEY-1" + strings.Repeat("ABCDEF2345", 5) + "AAAAAAAA" + "\""},
		{"databricks-token", "af.txt", "k = \"dapi" + strings.Repeat("0a1b2c", 5) + "0a" + "\""},
		{"linear-api-key", "ag.txt", "k = \"lin_api_" + strings.Repeat("a", 40) + "\""},
		{"jfrog-token", "ah.txt", "k = \"AKCp8" + strings.Repeat("a", 50) + "\""},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			rs := scanDir(t, map[string]string{tc.file: tc.content + "\n"})
			if hasRule(rs, tc.id) == nil {
				t.Errorf("expected a %q finding, got %+v", tc.id, rs)
			}
		})
	}
}

// A clean file that uses environment variables and non-secret values must trigger no detector.
func TestDetectorPackNoFalsePositives(t *testing.T) {
	clean := strings.Join([]string{
		"stripeKey := os.Getenv(\"STRIPE_SECRET_KEY\")",
		"token := os.Getenv(\"GITHUB_TOKEN\")",
		"dsn := os.Getenv(\"DATABASE_URL\")",
		"apiKey := config.OpenAIKey",
		"endpoint := \"https://example.com/api\"",
	}, "\n")
	rs := scanDir(t, map[string]string{"main.go": clean + "\n"})
	if len(rs) != 0 {
		t.Errorf("clean env-var usage must yield no findings, got %+v", rs)
	}
}
