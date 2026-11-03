package secretscan

import (
	"path/filepath"
	"testing"
)

// A Terraform lockfile records published provider checksums. They clear the keyword-free entropy
// floor by construction, so the audit saw an `h1:` checksum reported as a high-entropy secret
// (#1638). The checksum syntax is recognized; the file is not allowlisted.
func TestTerraformProviderChecksumIsNotASecret(t *testing.T) {
	dir := t.TempDir()
	lock := "provider \"registry.terraform.io/hashicorp/aws\" {\n" +
		"  version     = \"5.31.0\"\n" +
		"  constraints = \"~> 5.0\"\n" +
		"  hashes = [\n" +
		"    \"h1:JQ2ZB1xCXhHA9D6xWlX4Dy2Cy4z3Pq0TgUJ5sMvK7Ro=\",\n" +
		"    \"zh:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\n" +
		"  ]\n" +
		"}\n"
	write(t, filepath.Join(dir, ".terraform.lock.hcl"), lock)

	got := scanIDs(t, dir)
	if f, ok := got["generic-high-entropy"]; ok {
		t.Fatalf("a provider checksum must not be reported as a high-entropy secret, got line %d", f.Line)
	}
	if len(got) != 0 {
		t.Fatalf("a lockfile of checksums must report nothing, got %v", idList(got))
	}
}

// The recognition is syntactic, so a real credential in the same lockfile still reports: this is
// not a file-level or prefix-level exemption.
func TestRealCredentialInALockfileStillReports(t *testing.T) {
	dir := t.TempDir()
	lock := "provider \"registry.terraform.io/hashicorp/aws\" {\n" +
		"  hashes = [\n" +
		"    \"h1:JQ2ZB1xCXhHA9D6xWlX4Dy2Cy4z3Pq0TgUJ5sMvK7Ro=\",\n" +
		"  ]\n" +
		"  registry_token = \"" + syntheticToken(32) + "\"\n" +
		"}\n"
	write(t, filepath.Join(dir, ".terraform.lock.hcl"), lock)

	got := scanIDs(t, dir)
	if len(got) == 0 {
		t.Fatalf("a credential assigned beside the checksums must still be reported")
	}
}

// A value that merely begins with the two letters is not a checksum: the length, alphabet and
// padding all have to match, otherwise the entropy rule keeps it.
func TestChecksumLookalikeStillReports(t *testing.T) {
	dir := t.TempDir()
	content := "hashes = [\n" +
		"  \"h1:" + syntheticToken(40) + "\",\n" +
		"]\n"
	write(t, filepath.Join(dir, "lookalike.hcl"), content)

	got := scanIDs(t, dir)
	if _, ok := got["generic-high-entropy"]; !ok {
		t.Fatalf("a value that is not a valid checksum must keep its entropy finding, got %v", idList(got))
	}
}
