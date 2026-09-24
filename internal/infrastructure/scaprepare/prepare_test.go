package scaprepare

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"testing"
)

func TestExtractBinary_ReturnsNamedArchiveMember(t *testing.T) {
	body := tarGzip(t, map[string]string{"README": "ignored", "grype": "binary"})
	got, err := extractBinary("tools/grype", body)
	if err != nil {
		t.Fatalf("extractBinary() error = %v", err)
	}
	if string(got) != "binary" {
		t.Fatalf("extractBinary() = %q", got)
	}
}

func TestExtractCapability_ReturnsPinnedSourceMember(t *testing.T) {
	body := tarGzip(t, map[string]string{"osv-scanner-x/internal/utility/purl/purl_to_package.go": "source"})
	got, err := extractCapability("repository/capability/osv-scanner-v2.5.1/purl_to_package.go", body)
	if err != nil {
		t.Fatalf("extractCapability() error = %v", err)
	}
	if string(got) != "source" {
		t.Fatalf("extractCapability() = %q", got)
	}
}

func TestValidateRoots_RejectsSharedRoots(t *testing.T) {
	if err := validateRoots(Config{OfflineRoot: "/tmp/inputs", RawRetentionRoot: "/tmp/inputs"}); err == nil {
		t.Fatal("validateRoots() accepted shared roots")
	}
}

func TestValidateRoots_RejectsNestedAndSymlinkedRoots(t *testing.T) {
	root := t.TempDir()
	offline := root + "/offline"
	if err := validateRoots(Config{OfflineRoot: offline, RawRetentionRoot: offline + "/raw"}); err == nil {
		t.Fatal("validateRoots() accepted raw retention under offline root")
	}
	if err := os.Mkdir(offline, 0o700); err != nil {
		t.Fatal(err)
	}
	link := root + "/raw-link"
	if err := os.Symlink(offline, link); err != nil {
		t.Skipf("create symlink: %v", err)
	}
	if err := validateRoots(Config{OfflineRoot: offline, RawRetentionRoot: link + "/raw"}); err == nil {
		t.Fatal("validateRoots() accepted symlinked nested root")
	}
}

func TestWriteWithin_RejectsChildSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, root+"/tools"); err != nil {
		t.Skipf("create symlink: %v", err)
	}
	if err := writeWithin(root, "tools/grype", []byte("binary"), 0o500); err == nil {
		t.Fatal("writeWithin() accepted symlinked child directory")
	}
	if _, err := os.Lstat(outside + "/grype"); !os.IsNotExist(err) {
		t.Fatalf("writeWithin() wrote outside output root: %v", err)
	}
}

func tarGzip(t *testing.T, members map[string]string) []byte {
	t.Helper()
	var body bytes.Buffer
	gz := gzip.NewWriter(&body)
	tw := tar.NewWriter(gz)
	for name, value := range members {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(value))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}
