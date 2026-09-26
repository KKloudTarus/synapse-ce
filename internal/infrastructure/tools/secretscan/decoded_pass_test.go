package secretscan

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// The decode pass exists to find a secret carried inside an encoded value, and its contract is that a hit
// requires a real detector with its distinctive keyword to fire on the decoded bytes. The keyword-free
// entropy rule broke that: decoded bytes are high-entropy by construction, so an EKS cluster's base64 CA
// certificate decoded to a PEM whose DER body is a perfect high-entropy token. That was 19 findings on one
// Terraform module repository, one per rendered fixture, for a value that is public by definition.
func TestDecodedPassIgnoresEncodedCertificate(t *testing.T) {
	line := "B64_CLUSTER_CA=" + base64.StdEncoding.EncodeToString([]byte(certificatePEM()))

	for _, id := range scanOneFile(t, "bootstrap.sh", line) {
		if id == "generic-high-entropy" {
			t.Errorf("a base64-encoded certificate is public material, not a secret; rule %s fired", id)
		}
	}
}

// A credential really hidden inside a base64 value is still found, because its own keyword travels with it
// in the decoded text.
func TestDecodedPassStillFindsEncodedCredential(t *testing.T) {
	inner := `{"password": "S3cr3t-Value-For-The-Decode-Pass-Test"}`
	line := "data: " + base64.StdEncoding.EncodeToString([]byte(inner))

	hits := scanOneFile(t, "secret.yaml", line)
	for _, id := range hits {
		if strings.Contains(id, "secret") || strings.Contains(id, "password") || id == "generic-secret" {
			return
		}
	}
	t.Errorf("a keyword-anchored credential inside base64 must still be found; rules that fired: %v", hits)
}

// certificatePEM builds a PEM certificate whose body carries real DER-like entropy, which is what made the
// keyword-free entropy rule fire on it. The bytes are hash-derived so no real certificate appears here.
func certificatePEM() string {
	var body []byte
	digest := sha256.Sum256([]byte("synapse-decode-pass-fixture"))
	for len(body) < 600 {
		body = append(body, digest[:]...)
		digest = sha256.Sum256(digest[:])
	}
	encoded := base64.StdEncoding.EncodeToString(body)
	var out strings.Builder
	out.WriteString("-----BEGIN CERTIFICATE-----\n")
	for len(encoded) > 64 {
		out.WriteString(encoded[:64] + "\n")
		encoded = encoded[64:]
	}
	out.WriteString(encoded + "\n-----END CERTIFICATE-----\n")
	return out.String()
}

// scanOneFile runs the scanner over one file and returns the rule ids that fired.
func scanOneFile(t *testing.T, name, content string) []string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, name, content+"\n")
	report, err := New().ScanFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	ids := make([]string, 0, len(report.Findings))
	for _, f := range report.Findings {
		ids = append(ids, f.RuleID)
	}
	if len(ids) == 0 {
		ids = append(ids, "(none)")
	}
	return ids
}

// A CDN asset URL carries a high-entropy path segment by design. An avatar URL in a documentation page
// cleared the keyword-free entropy floor six times in one repository, where gitleaks reported nothing.
func TestHighEntropyIgnoresAssetURL(t *testing.T) {
	lines := []string{
		`      'https://pbs.twimg.com/profile_images/557940120184041473/bFyXy8Pu_400x400.jpeg',`,
		`      'https://cdn.example.com/assets/9f8Ab2Cd7eF1gH3iJ4kL5mN6oP7qR8sT/logo.webp',`,
		`  <img src="https://static.example.com/uSer_AvatarS/1691627325794725888/voQFcYjY.png" />`,
	}
	for _, line := range lines {
		for _, id := range scanOneFile(t, "Community.vue", line) {
			if id == "generic-high-entropy" {
				t.Errorf("an asset URL is a location, not a credential: %q", line)
			}
		}
	}
}

// A credential in a URL query string is untouched: that line names a location but carries no asset
// extension, so the resource-path guard does not apply to it.
func TestHighEntropyStillReadsCredentialInQueryString(t *testing.T) {
	line := `webhook = "https://hooks.example.com/services/` + base64.RawURLEncoding.EncodeToString([]byte("synapse-entropy-query-fixture-value")) + `"`
	hits := scanOneFile(t, "config.yaml", line)
	for _, id := range hits {
		if id != "(none)" {
			return
		}
	}
	t.Errorf("a high-entropy value on a URL line with no asset extension must still be reported; rules that fired: %v", hits)
}

// A webfont is served under a content hash, so a font stylesheet carries a high-entropy token on every
// @font-face block by design. Two stylesheets produced 20 of one repository's 26 secret findings, where
// gitleaks reported one. CSS names a location with `src:` and `url(` rather than an attribute.
func TestHighEntropyIgnoresWebfontSource(t *testing.T) {
	lines := []string{
		`  src: url(/fonts/UcC73FwrK3iLTeHuS_fvQtMwCp50KnMa25L7W0Q5n-wU.woff2) format('woff2');`,
		`  src: url("../fonts/9tK5xB3rQ7wZmH2vL8pN4sT6uY1cE0fG5jD3kR7aW9b.ttf");`,
	}
	for _, line := range lines {
		for _, id := range scanOneFile(t, "inter.scss", line) {
			if id == "generic-high-entropy" {
				t.Errorf("a webfont source is a location, not a credential: %q", line)
			}
		}
	}
}

// A codec alphabet has maximal character variety, so it clears any entropy floor by construction, and one
// appears in a vendored polyfill in most JavaScript repositories.
func TestHighEntropyIgnoresCodecAlphabet(t *testing.T) {
	lines := []string{
		`      var byteToCharMap = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='`,
		`const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"`,
		`  private static final String BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";`,
	}
	for _, line := range lines {
		for _, id := range scanOneFile(t, "codec.js", line) {
			if id == "generic-high-entropy" {
				t.Errorf("a codec alphabet is a constant table, not a credential: %q", line)
			}
		}
	}
}

// A shuffled alphabet of the same characters is NOT a table: that is exactly the shape of a generated
// secret, so it must still be reported.
func TestHighEntropyStillReadsShuffledAlphabet(t *testing.T) {
	line := `token = "qWzR7tYuI9oPaS4dFgHjKlZ2xCvBnM1e3rTyU6iO0pAs"`
	hits := scanOneFile(t, "config.yaml", line)
	for _, id := range hits {
		if id != "(none)" {
			return
		}
	}
	t.Errorf("a generated token must still be reported; rules that fired: %v", hits)
}

// A database's own documentation gives the connection-URI shape with the parts named, so every such line
// matched: on one repository that was 234 of 267 secret findings, almost all in docs.
func TestConnectionStringIgnoresDocumentedPlaceholders(t *testing.T) {
	lines := []string{
		"| PostgreSQL | `postgresql://<UserName>:<DBPassword>@<Database Host>/<Database Name>` |",
		"| MySQL | `mysql://<UserName>:<DBPassword>@<Database Host>/<Database Name>` |",
		"DATABASE_URL=postgresql://{username}:{password}@{host}/{database}",
		"uri: mongodb://admin:${MONGO_PASSWORD}@mongo:27017/app",
		"redis://default:%(redis_password)s@cache:6379/0",
	}
	for _, line := range lines {
		for _, id := range scanOneFile(t, "configuring.mdx", line) {
			if id == "db-connection-string" {
				t.Errorf("a documented URI template is not a credential: %q", line)
			}
		}
	}
}

// A connection string carrying a real password is still reported.
func TestConnectionStringStillReadsRealPassword(t *testing.T) {
	line := `psql "postgresql://superset:h4rdc0dedPassw0rd@127.0.0.1:15432/superset"`
	hits := scanOneFile(t, "bashlib.sh", line)
	for _, id := range hits {
		if id == "db-connection-string" {
			return
		}
	}
	t.Errorf("a literal password in a connection string must be reported; rules that fired: %v", hits)
}

// The whitespace between a key and its value may cross a newline, which is how a JSON formatter breaks a
// long line. A key with an EMPTY value then reached past its own line and took the next one as its secret,
// reporting it a line below the key. Three of those sat in one env template on a real repository.
func TestEmptyValueDoesNotCaptureTheNextLine(t *testing.T) {
	content := "CAPTCHA_H_SITEKEY=\nCAPTCHA_H_SECRET=\nCAPTCHA_H_TIMEOUT=5\nCAPTCHA_H_FAIL_OPEN=false\n"
	for _, id := range scanOneFile(t, ".env.captcha", content) {
		if id != "(none)" {
			t.Errorf("an empty value is not a credential; rule %s fired", id)
		}
	}
}

// A credential really assigned on the line is still reported, and so is one a formatter moved to the next
// line, because only an identifier-shaped value is refused.
func TestValueOnTheFollowingLineStillCounts(t *testing.T) {
	cases := map[string]string{
		"same line": `  "api_key": "AbCdEf0123456789GhIjKl"`,
		"next line": "  \"api_key\":\n    \"AbCdEf0123456789GhIjKl\"",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			hits := scanOneFile(t, "config.json", content)
			for _, id := range hits {
				if id != "(none)" {
					return
				}
			}
			t.Errorf("a real credential must still be reported; rules that fired: %v", hits)
		})
	}
}

// A credential keyword and the separator that assigns it are always on one line. Letting whitespace cross a
// newline there made a keyword bind to the NEXT line's attribute: `:tokens="tokens"` on one line and
// `:available-permissions="availablePermissions"` on the next captured `available-permissions=` as the
// secret, on a Vue component with no credential in it at all.
func TestKeywordDoesNotBindToTheNextLinesAttribute(t *testing.T) {
	content := "        <ApiTokenManager\n" +
		"          :tokens=\"tokens\"\n" +
		"          :available-permissions=\"availablePermissions\"\n" +
		"          :default-permissions=\"defaultPermissions\" />\n"
	for _, id := range scanOneFile(t, "Index.vue", content) {
		if id != "(none)" {
			t.Errorf("a prop binding is not a credential; rule %s fired", id)
		}
	}
}

// The keyword still reaches its value across the shapes that really occur on one line: a quoted YAML key,
// a bracketed config key, and Go's short variable declaration.
func TestKeywordStillReachesItsValueOnOneLine(t *testing.T) {
	cases := map[string]string{
		"yaml":            `  client-secret: "AbCdEf0123456789GhIjKl"`,
		"bracketed":       `app.config['SECRET_KEY_HMAC'] = "AbCdEf0123456789GhIjKl"`,
		"go short assign": `apiKey := "AbCdEf0123456789GhIjKl"`,
		"quoted key":      `"access_token" : "AbCdEf0123456789GhIjKl"`,
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			hits := scanOneFile(t, "config.yaml", line)
			for _, id := range hits {
				if id != "(none)" {
					return
				}
			}
			t.Errorf("the credential must still be found; rules that fired: %v", hits)
		})
	}
}

// The other documented URI shape names the parts with the words themselves. In driver docstrings and
// translation catalogues that line was 65 of one repository's secret findings.
func TestConnectionStringIgnoresPlaceholderWords(t *testing.T) {
	lines := []string{
		`            - postgres://user:password@host/db`,
		`        "mysql://user:password@host:port/dbname[?key=value&key=value...]"`,
		`  uri = "postgresql://username:changeme@your-postgres-host/dbname"`,
	}
	for _, line := range lines {
		for _, id := range scanOneFile(t, "base.py", line) {
			if id == "db-connection-string" {
				t.Errorf("a URI grammar example is not a credential: %q", line)
			}
		}
	}
}

// Only BOTH components being generic makes it an example. A real account name beside a weak password is a
// credential, and reporting it is the point.
func TestConnectionStringStillReadsRealAccount(t *testing.T) {
	lines := []string{
		`DATABASE_URL=postgresql://superset_admin:password@db.internal/superset`,
		`uri: mysql://user:h4rdc0dedPassw0rd@db.internal/app`,
	}
	for _, line := range lines {
		hits := scanOneFile(t, "settings.py", line)
		found := false
		for _, id := range hits {
			if id == "db-connection-string" {
				found = true
			}
		}
		if !found {
			t.Errorf("a real account or password must be reported: %q gave %v", line, hits)
		}
	}
}
