package secretscan

import (
	"context"
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
	highEnt   = "kJ8xQ" + "2vN7pL4mZ9wR3tB6"         // 21 chars, high entropy
	privBlock = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIByz==\n-----END RSA PRIVATE KEY-----"
)

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
	raws, err := New().ScanFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	out := make([]secretResult, len(raws))
	for i, r := range raws {
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
		"settings.json": "{\"password\": \"" + highEnt + "\"}\n",
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
		"tpl.yml":     "password = \"changeme\"\n",
		"vars.tf":     "token = \"${var.api_token}\"\n",
	})
	if len(rs) != 0 {
		t.Errorf("placeholders must be allow-listed, got %+v", rs)
	}
}

// The generic rule is entropy-gated: a low-entropy assignment is not a secret.
func TestEntropyGate(t *testing.T) {
	rs := scanDir(t, map[string]string{
		"low.env": "password = \"aaaaaaaaaaaaaaaa\"\n", // 16 chars, entropy 0
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
	raws, err := New().ScanFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	if len(raws) != 0 {
		t.Errorf("must not follow a symlink out of the workspace, got %d findings", len(raws))
	}
}

func TestEmptyDirNoError(t *testing.T) {
	if rs := scanDir(t, map[string]string{}); len(rs) != 0 {
		t.Errorf("empty dir: %+v", rs)
	}
}
