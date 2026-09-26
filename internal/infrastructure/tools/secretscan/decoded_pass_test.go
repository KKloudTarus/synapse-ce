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
