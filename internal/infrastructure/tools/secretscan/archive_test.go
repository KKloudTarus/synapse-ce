package secretscan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// awsKey is a syntactically valid AWS access key id (not an "example" placeholder, so the allowlist keeps it).
const awsKey = "AKIAZ3ABCDEFGHIJKLMN"

func zipBytes(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func tarGzBytes(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzBytes(t *testing.T, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestScanArchivesFindsSecrets covers EPIC #860 D6.9: a secret inside a zip/jar, a tar.gz, and a plain .gz is
// found, attributed to "<archive>!<member>", and redacted (the raw secret never leaves the package).
func TestScanArchivesFindsSecrets(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("bundle.jar", zipBytes(t, map[string]string{"config/app.properties": "aws_key=" + awsKey + "\n"}))
	write("release.tar.gz", tarGzBytes(t, map[string]string{"app/.env": "AWS_KEY=" + awsKey + "\n"}))
	write("creds.txt.gz", gzBytes(t, "AWS_KEY="+awsKey+"\n"))

	report, err := New().ScanFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	want := map[string]bool{
		"bundle.jar!config/app.properties": false,
		"release.tar.gz!app/.env":          false,
		"creds.txt.gz!creds.txt":           false, // a plain .gz member keeps its archive layer, named "<archive>!<inner>"
	}
	for _, f := range report.Findings {
		if f.RuleID != "aws-access-key-id" {
			continue
		}
		if f.Match == awsKey {
			t.Errorf("archive finding must be redacted, leaked the raw secret")
		}
		if _, ok := want[f.File]; ok {
			want[f.File] = true
		}
	}
	for path, found := range want {
		if !found {
			t.Errorf("secret inside %q was not found; findings=%+v", path, report.Findings)
		}
	}
}

// TestScanArchivesNestedDepth: a jar inside a war (depth 1) is still looked into.
func TestScanArchivesNestedDepth(t *testing.T) {
	dir := t.TempDir()
	innerJar := zipBytes(t, map[string]string{"secret.env": "aws_key=" + awsKey + "\n"})
	war := zipBytes(t, map[string]string{"WEB-INF/lib/app.jar": string(innerJar)})
	if err := os.WriteFile(filepath.Join(dir, "service.war"), war, 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := New().ScanFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	found := false
	for _, f := range report.Findings {
		if f.RuleID == "aws-access-key-id" && strings.Contains(f.File, "app.jar!secret.env") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a secret in a jar nested inside a war must be found; findings=%+v", report.Findings)
	}
}

// TestScanArchivesBombTerminates: a zip whose single entry decompresses far beyond the caps must terminate
// (the byte budget stops it) rather than exhaust memory, and the scan still returns.
func TestScanArchivesBombTerminates(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("huge.txt")
	if err != nil {
		t.Fatal(err)
	}
	// 300 MiB of highly compressible zeros: past maxArchiveTotalBytes, but the ZIP stays tiny on disk.
	chunk := make([]byte, 1<<20)
	for i := 0; i < 300; i++ {
		if _, err := w.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bomb.zip"), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := New().ScanFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan must not fail on a bomb: %v", err)
	}
	if !report.Truncated {
		t.Error("an oversized archive member must mark the report truncated")
	}
}

// TestScanTarMixedEntries: a directory entry and a symlink among the members must not stop the scan from
// finding a secret in a following regular file (the skipped non-regular entries are handled, not fatal).
func TestScanTarMixedEntries(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{Name: "app/", Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "app/link", Linkname: "config", Typeflag: tar.TypeSymlink}); err != nil {
		t.Fatal(err)
	}
	secret := "AWS_KEY=" + awsKey + "\n"
	if err := tw.WriteHeader(&tar.Header{Name: "app/config.env", Mode: 0o644, Size: int64(len(secret)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(secret)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mixed.tar.gz"), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := New().ScanFiles(context.Background(), dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	found := false
	for _, f := range report.Findings {
		if f.RuleID == "aws-access-key-id" && f.File == "mixed.tar.gz!app/config.env" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a secret after a dir/symlink entry must still be found; findings=%+v", report.Findings)
	}
}
