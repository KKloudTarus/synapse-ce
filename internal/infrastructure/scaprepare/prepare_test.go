package scaprepare

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestExtractBinary_ReturnsNamedArchiveMember(t *testing.T) {
	body := tarGzip(t, map[string]string{"README": "ignored", "grype": "binary"})
	got, err := extractBinary(context.Background(), "tools/grype", body)
	if err != nil {
		t.Fatalf("extractBinary() error = %v", err)
	}
	if string(got) != "binary" {
		t.Fatalf("extractBinary() = %q", got)
	}
}

func TestExtractCapability_ReturnsPinnedSourceMember(t *testing.T) {
	body := tarGzip(t, map[string]string{"osv-scanner-x/internal/utility/purl/purl_to_package.go": "source"})
	got, err := extractCapability(context.Background(), "repository/capability/osv-scanner-v2.5.1/purl_to_package.go", body)
	if err != nil {
		t.Fatalf("extractCapability() error = %v", err)
	}
	if string(got) != "source" {
		t.Fatalf("extractCapability() = %q", got)
	}
}

func TestTarFindWithin_RejectsCumulativeDecompressedArchiveOverLimit(t *testing.T) {
	body := tarGzipMembers(t, []tarMemberFixture{
		{name: "ignored", body: strings.Repeat("a", 2_000)},
		{name: "grype", body: strings.Repeat("b", 2_000)},
	})
	_, err := tarFindWithin(context.Background(), body, func(name string) bool { return name == "grype" }, 3_000)
	if !errors.Is(err, errArchiveTooLarge) {
		t.Fatalf("tarFindWithin() error = %v, want decompressed archive size limit", err)
	}
}

func TestTarFindWithin_RejectsSelectedMemberOverLimit(t *testing.T) {
	body := tarGzipMembers(t, []tarMemberFixture{{name: "grype", body: strings.Repeat("a", 3_001)}})
	_, err := tarFindWithin(context.Background(), body, func(name string) bool { return name == "grype" }, 3_000)
	if !errors.Is(err, errArchiveTooLarge) {
		t.Fatalf("tarFindWithin() error = %v, want selected member size limit", err)
	}
}

func TestTarFindWithin_ReturnsCanceledContext(t *testing.T) {
	body := tarGzip(t, map[string]string{"grype": strings.Repeat("a", 2_000)})
	ctx, cancel := context.WithCancel(context.Background())
	_, err := tarFindWithin(ctx, body, func(name string) bool {
		cancel()
		return name == "grype"
	}, 3_000)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("tarFindWithin() error = %v, want context canceled", err)
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
	ordered := make([]tarMemberFixture, 0, len(members))
	for name, body := range members {
		ordered = append(ordered, tarMemberFixture{name: name, body: body})
	}
	return tarGzipMembers(t, ordered)
}

type tarMemberFixture struct {
	name string
	body string
}

func tarGzipMembers(t *testing.T, members []tarMemberFixture) []byte {
	t.Helper()
	var body bytes.Buffer
	gz := gzip.NewWriter(&body)
	tw := tar.NewWriter(gz)
	for _, member := range members {
		if err := tw.WriteHeader(&tar.Header{Name: member.name, Mode: 0o644, Size: int64(len(member.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(member.body)); err != nil {
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
