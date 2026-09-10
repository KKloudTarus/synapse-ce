package imageconfig

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func ruleIDs(fs []ports.MisconfigRawFinding) map[string]ports.MisconfigRawFinding {
	m := map[string]ports.MisconfigRawFinding{}
	for _, f := range fs {
		m[f.RuleID] = f
	}
	return m
}

// TestCheckFlagsRootUserSecretEnvAndSensitiveHistory covers the D7.10 acceptance: a root user, a credential in
// an ENV variable, and sensitive build commands each produce the corresponding finding.
func TestCheckFlagsRootUserSecretEnvAndSensitiveHistory(t *testing.T) {
	info := &sbom.ImageInfo{
		User: "",                                                       // no USER set => runs as root
		Env:  []string{"PATH=/usr/bin", "API_TOKEN=" + secretRedacted}, // a detected credential, value already redacted
		Layers: []sbom.ImageLayer{
			{Index: 0, CreatedBy: "/bin/sh -c #(nop) ADD file:abc in /"},
			{Index: 1, CreatedBy: "/bin/sh -c curl -sSL https://get.example.com/install.sh | sh"},
			{Index: 2, CreatedBy: "/bin/sh -c #(nop) ADD https://example.com/app.tar.gz in /opt/"},
		},
	}
	got := ruleIDs(Check(info))
	for _, want := range []string{"image-runs-as-root", "image-secret-in-env", "image-pipe-to-shell", "image-add-remote-url"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected a %q finding, got %v", want, keys(got))
		}
	}
	if f := got["image-secret-in-env"]; f.Severity != shared.SeverityHigh {
		t.Errorf("a baked-in credential must be High, got %s", f.Severity)
	}
}

// TestCheckExplicitRootFlags: an explicit USER root / uid 0 is flagged, including with a non-root group;
// a non-root user is not.
func TestCheckExplicitRootFlags(t *testing.T) {
	for _, u := range []string{"root", "0", "root:root", "0:0", "root:0", "0:1000", "root:1000"} {
		if _, ok := ruleIDs(Check(&sbom.ImageInfo{User: u}))["image-runs-as-root"]; !ok {
			t.Errorf("USER %q must be flagged as root", u)
		}
	}
	for _, u := range []string{"app", "1000", "app:app", "1000:1000", "nobody"} {
		if _, ok := ruleIDs(Check(&sbom.ImageInfo{User: u}))["image-runs-as-root"]; ok {
			t.Errorf("USER %q is non-root and must NOT be flagged", u)
		}
	}
}

// TestRedactEnvIsValueBased: a value that IS a recognized credential is redacted; a config knob whose NAME
// merely contains a secret word (PASSWORD_MIN_LENGTH) is NOT, so it never becomes a false "secret in ENV".
func TestRedactEnvIsValueBased(t *testing.T) {
	in := []string{
		"API_TOKEN=ghp_" + strings.Repeat("a", 36), // a GitHub PAT: redacted
		"PASSWORD_MIN_LENGTH=12",                   // a config knob, value not a secret: kept
		"AUTH_MODE=oidc",                           // a config knob: kept
		"DB_URL=postgres://user:s3cr3tpw@db/app",   // a DSN with an inline password: redacted
		"PATH=/usr/bin",                            // kept
	}
	out := RedactEnv(in)
	want := []string{
		"API_TOKEN=" + secretRedacted,
		"PASSWORD_MIN_LENGTH=12",
		"AUTH_MODE=oidc",
		"DB_URL=" + secretRedacted,
		"PATH=/usr/bin",
	}
	if len(out) != len(want) {
		t.Fatalf("RedactEnv len = %d, want %d: %v", len(out), len(want), out)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("RedactEnv[%d] = %q, want %q", i, out[i], want[i])
		}
	}
}

// TestRedactCommandScrubsCredentials: a token or URL credential in a build command is scrubbed while the
// command structure (which the pipe-to-shell / remote-ADD checks key off) is preserved.
func TestRedactCommandScrubsCredentials(t *testing.T) {
	cmd := "/bin/sh -c curl https://user:tok3nvalue@get.example.com/install.sh | sh"
	got := RedactCommand(cmd)
	if strings.Contains(got, "user:tok3nvalue@") {
		t.Errorf("RedactCommand must scrub the URL credential, got %q", got)
	}
	if !strings.Contains(got, "| sh") { // structure preserved so the pipe-to-shell check still fires
		t.Errorf("RedactCommand must preserve command structure, got %q", got)
	}
}

// TestCheckCleanImageHasNoFindings: a non-root user, no secret ENV, and benign history produce nothing.
func TestCheckCleanImageHasNoFindings(t *testing.T) {
	info := &sbom.ImageInfo{
		User: "app",
		Env:  []string{"PATH=/usr/bin", "LANG=C.UTF-8"},
		Layers: []sbom.ImageLayer{
			{Index: 0, CreatedBy: "/bin/sh -c apk add --no-cache openssl"},
			{Index: 1, CreatedBy: "/bin/sh -c #(nop) COPY dir:abc in /app"},
		},
	}
	if fs := Check(info); len(fs) != 0 {
		t.Fatalf("a hardened image must produce no findings, got %+v", fs)
	}
	if Check(nil) != nil {
		t.Error("nil info must produce no findings")
	}
}

func keys(m map[string]ports.MisconfigRawFinding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestCredentialedRemoteAddStillDetected: redacting a URL credential must keep the scheme, so a remote ADD
// with an embedded credential is still flagged (the credential scrub must not create a detection false negative).
func TestCredentialedRemoteAddStillDetected(t *testing.T) {
	raw := "/bin/sh -c #(nop) ADD https://user:s3cr3t@example.com/app.tar.gz in /opt/"
	redacted := RedactCommand(raw)
	if strings.Contains(redacted, "user:s3cr3t@") {
		t.Fatalf("credential must be scrubbed, got %q", redacted)
	}
	info := &sbom.ImageInfo{User: "app", Layers: []sbom.ImageLayer{{Index: 0, CreatedBy: redacted}}}
	if _, ok := ruleIDs(Check(info))["image-add-remote-url"]; !ok {
		t.Fatalf("a credentialed remote ADD must still be flagged after redaction: %q", redacted)
	}
}

// TestPEMInCommandFullyRedacted: a full PEM private key in a build command is scrubbed body and footer, not
// just the header.
func TestPEMInCommandFullyRedacted(t *testing.T) {
	cmd := "echo '-----BEGIN RSA PRIVATE KEY-----\nMIIBODYSECRETLINE\n-----END RSA PRIVATE KEY-----' > /key"
	got := RedactCommand(cmd)
	if strings.Contains(got, "MIIBODYSECRETLINE") || strings.Contains(got, "END RSA PRIVATE KEY") {
		t.Errorf("the whole PEM block must be scrubbed, got %q", got)
	}
}
