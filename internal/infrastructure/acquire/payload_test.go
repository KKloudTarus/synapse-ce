package acquire

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// --- fixture builders (newc cpio / minimal rpm / ar deb) ---

type fentry struct {
	name string
	mode int
	data []byte
}

func cpioHeader(name string, mode, size int) []byte {
	namesize := len(name) + 1
	h := "070701"
	for _, f := range []int{1, mode, 0, 0, 1, 0, size, 0, 0, 0, 0, namesize, 0} {
		h += fmt.Sprintf("%08x", f)
	}
	b := append([]byte(h), []byte(name)...)
	b = append(b, 0) // NUL-terminate the name
	for len(b)%4 != 0 { // pad name so the data starts on a 4-byte boundary
		b = append(b, 0)
	}
	return b
}

func buildNewcCPIO(entries []fentry) []byte {
	var out []byte
	for _, e := range entries {
		out = append(out, cpioHeader(e.name, e.mode, len(e.data))...)
		out = append(out, e.data...)
		for len(out)%4 != 0 {
			out = append(out, 0)
		}
	}
	return append(out, cpioHeader("TRAILER!!!", 0, 0)...)
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	zw := gzip.NewWriter(buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildRPM(payload []byte) []byte {
	b := make([]byte, 96) // lead
	copy(b, rpmLeadMagic)
	hdr := func() []byte { // magic(3)+ver(1)+reserved(4)+nindex(4=0)+hsize(4=0) = 16 bytes, empty header
		return append(append([]byte{}, rpmHeaderMagic...), 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	}
	b = append(b, hdr()...) // signature header (ends at 112, already 8-aligned)
	b = append(b, hdr()...) // main header (ends at 128)
	return append(b, payload...)
}

func buildDeb(t *testing.T, dataTar []byte) []byte {
	t.Helper()
	out := append([]byte{}, arMagic...)
	member := func(name string, data []byte) {
		out = append(out, []byte(fmt.Sprintf("%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, 0, 0, 0, "100644", len(data)))...)
		out = append(out, data...)
		if len(data)%2 == 1 {
			out = append(out, '\n')
		}
	}
	member("debian-binary", []byte("2.0\n"))
	member("control.tar.gz", gzipBytes(t, []byte("dummy")))
	member("data.tar.gz", gzipBytes(t, dataTar))
	return out
}

func buildTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	tw := tar.NewWriter(buf)
	for name, content := range files {
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
	return buf.Bytes()
}

// --- tests ---

func TestDecompressStreamDispatch(t *testing.T) {
	payload := []byte("hello payload")
	r, closeFn, err := decompressStream(bytes.NewReader(gzipBytes(t, payload)))
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	got := &bytes.Buffer{}
	if _, err := got.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	if got.String() != string(payload) {
		t.Errorf("gzip roundtrip = %q, want %q", got.String(), payload)
	}
	// A bare (uncompressed) stream passes through unchanged.
	r2, close2, _ := decompressStream(bytes.NewReader([]byte("plain")))
	defer close2()
	b2 := &bytes.Buffer{}
	_, _ = b2.ReadFrom(r2)
	if b2.String() != "plain" {
		t.Errorf("passthrough = %q", b2.String())
	}
}

func TestExtractCPIO(t *testing.T) {
	cpio := buildNewcCPIO([]fentry{
		{"usr/bin/app", 0x81a4, []byte("ELF-ish binary bytes")}, // regular file (0100644)
		{"usr/lib", 0x41ed, nil},                                // directory (040755)
		{"usr/bin/evil-link", 0xa1ff, []byte("/etc/passwd")},    // symlink (0120777) -> must be skipped
	})
	dest := t.TempDir()
	if err := extractCPIO(bytes.NewReader(cpio), dest); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "usr/bin/app")); err != nil || string(b) != "ELF-ish binary bytes" {
		t.Errorf("regular file not extracted correctly: %v / %q", err, b)
	}
	if fi, err := os.Lstat(filepath.Join(dest, "usr/bin/evil-link")); err == nil {
		t.Errorf("symlink entry must be skipped, but exists (mode %v)", fi.Mode())
	}
	if fi, err := os.Stat(filepath.Join(dest, "usr/lib")); err != nil || !fi.IsDir() {
		t.Errorf("directory entry not created")
	}
}

// TestExtractCPIODirWithBodyStaysAligned covers the guard against a crafted directory entry that declares
// a non-zero body: its bytes must be drained so the following entry is still parsed from the right offset.
func TestExtractCPIODirWithBodyStaysAligned(t *testing.T) {
	cpio := buildNewcCPIO([]fentry{
		{"usr/lib", 0x41ed, []byte("bogusdirbody")}, // directory with a (spec-violating) body -> must be drained
		{"usr/bin/app", 0x81a4, []byte("real binary")},
	})
	dest := t.TempDir()
	if err := extractCPIO(bytes.NewReader(cpio), dest); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "usr/bin/app")); err != nil || string(b) != "real binary" {
		t.Errorf("entry after a dir-with-body misaligned: %v / %q", err, b)
	}
}

func TestExtractCPIORejectsTraversal(t *testing.T) {
	cpio := buildNewcCPIO([]fentry{{"../../../../tmp/escape", 0x81a4, []byte("pwn")}})
	dest := t.TempDir()
	if err := extractCPIO(bytes.NewReader(cpio), dest); err == nil {
		t.Fatal("expected a path-traversal cpio entry to be rejected")
	}
}

func TestExtractRPMPayload(t *testing.T) {
	rpm := buildRPM(gzipBytes(t, buildNewcCPIO([]fentry{
		{"usr/bin/xora-node-agent", 0x81a4, []byte("go binary")},
	})))
	path := filepath.Join(t.TempDir(), "a.rpm")
	if err := os.WriteFile(path, rpm, 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "out")
	if err := extractRPMPayload(path, dest, MaxWorkspaceBytes); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "usr/bin/xora-node-agent")); err != nil || string(b) != "go binary" {
		t.Errorf("rpm payload not extracted: %v / %q", err, b)
	}
}

func TestExtractRPMRejectsBadMagic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.rpm")
	_ = os.WriteFile(path, append([]byte("NOTANRPM"), make([]byte, 200)...), 0o600)
	if err := extractRPMPayload(path, filepath.Join(t.TempDir(), "o"), MaxWorkspaceBytes); err == nil {
		t.Fatal("expected error for a non-rpm file")
	}
}

func TestRPMHeaderBoundsRejectsHugeCounts(t *testing.T) {
	// A main header claiming a huge nindex must be rejected (allocation/DoS guard), not trusted.
	b := make([]byte, 96)
	copy(b, rpmLeadMagic)
	sig := append(append([]byte{}, rpmHeaderMagic...), 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	b = append(b, sig...)
	main := append(append([]byte{}, rpmHeaderMagic...), 0x01, 0, 0, 0, 0)
	main = append(main, 0x7F, 0xFF, 0xFF, 0xFF) // nindex huge
	main = append(main, 0, 0, 0, 0)
	b = append(b, main...)
	path := filepath.Join(t.TempDir(), "huge.rpm")
	_ = os.WriteFile(path, b, 0o600)
	if err := extractRPMPayload(path, filepath.Join(t.TempDir(), "o"), MaxWorkspaceBytes); err == nil {
		t.Fatal("expected rejection of an oversized rpm header")
	}
}

func TestExtractDebPayload(t *testing.T) {
	deb := buildDeb(t, buildTar(t, map[string]string{"usr/bin/agent": "deb go binary"}))
	path := filepath.Join(t.TempDir(), "a.deb")
	if err := os.WriteFile(path, deb, 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "out")
	if err := extractDebPayload(path, dest, MaxWorkspaceBytes); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "usr/bin/agent")); err != nil || string(b) != "deb go binary" {
		t.Errorf("deb data.tar not extracted: %v / %q", err, b)
	}
}

func TestExtractDebRejectsNonAr(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.deb")
	_ = os.WriteFile(path, []byte("not an ar archive at all"), 0o600)
	if err := extractDebPayload(path, filepath.Join(t.TempDir(), "o"), MaxWorkspaceBytes); err == nil {
		t.Fatal("expected error for a non-ar .deb")
	}
}
