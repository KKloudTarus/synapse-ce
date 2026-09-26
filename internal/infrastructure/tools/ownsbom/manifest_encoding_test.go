package ownsbom

import (
	"strings"
	"testing"
	"unicode/utf16"
)

func utf16LE(t *testing.T, s string) []byte {
	t.Helper()
	out := []byte{0xFF, 0xFE}
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

func utf16BE(t *testing.T, s string) []byte {
	t.Helper()
	out := []byte{0xFE, 0xFF}
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u>>8), byte(u))
	}
	return out
}

// TestDecodeManifestTextHandlesByteOrderMarks pins the fix for a real service whose requirements.txt was
// written through a Windows PowerShell redirect and is therefore UTF-16LE. Every parser here reads bytes,
// so all 122 pinned dependencies were present and none of them matched: the repository reported an empty
// inventory with no vulnerability query possible.
func TestDecodeManifestTextHandlesByteOrderMarks(t *testing.T) {
	const want = "aiohttp==3.8.6\nattrs==23.1.0\n"
	for name, in := range map[string][]byte{
		"utf-16le": utf16LE(t, want),
		"utf-16be": utf16BE(t, want),
		"utf-8bom": append([]byte{0xEF, 0xBB, 0xBF}, []byte(want)...),
		"plain":    []byte(want),
	} {
		if got := string(decodeManifestText(in)); got != want {
			t.Errorf("%s decoded to %q, want %q", name, got, want)
		}
	}
}

// TestDecodeManifestTextNeverGuesses pins the deliberate limit. Only a byte-order mark converts, because a
// BOM is the writer declaring the encoding and cannot be misread. Guessing from content could corrupt a
// manifest, and a dependency inventory is the wrong place to guess.
func TestDecodeManifestTextNeverGuesses(t *testing.T) {
	// UTF-16 content with NO BOM: left alone rather than sniffed.
	noBOM := []byte{'a', 0x00, 'b', 0x00}
	if got := decodeManifestText(noBOM); string(got) != string(noBOM) {
		t.Errorf("BOM-less content was converted: %q", got)
	}
	// Latin-1 high bytes must survive untouched; they are not a BOM.
	latin := []byte{'c', 'a', 'f', 0xE9, '\n'}
	if got := decodeManifestText(latin); string(got) != string(latin) {
		t.Errorf("latin-1 content was converted: %q", got)
	}
}

// TestUTF16ToUTF8SurvivesBadInput pins that one unreadable rune does not cost the rest of the manifest,
// which is the posture every parser here takes toward a line it cannot read.
func TestUTF16ToUTF8SurvivesBadInput(t *testing.T) {
	// A lone high surrogate, then a valid entry, then a trailing odd byte.
	b := []byte{0x00, 0xD8, 'x', 0x00, 'y', 0x00, 0x41}
	got := string(utf16ToUTF8(b, true))
	if !strings.Contains(got, "xy") {
		t.Fatalf("valid runes after an unpaired surrogate were lost: %q", got)
	}
}
