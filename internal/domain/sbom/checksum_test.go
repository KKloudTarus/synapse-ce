package sbom

import (
	"strings"
	"testing"
)

func TestNormalizeChecksumAlg(t *testing.T) {
	cases := map[string]string{
		"sha-256": "SHA256", "SHA256": "SHA256", "SHA_256": "SHA256",
		"sha3-512": "SHA3512", "  sha1  ": "SHA1", "BLAKE2b-256": "BLAKE2B256",
	}
	for in, want := range cases {
		if got := NormalizeChecksumAlg(in); got != want {
			t.Errorf("NormalizeChecksumAlg(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanonicalHexDigest(t *testing.T) {
	// hex input is lowercased and returned as-is; the canonical (SPDX-style) name comes back.
	if name, hv, ok := CanonicalHexDigest("sha-256", strings.ToUpper(strings.Repeat("a", 64))); !ok || name != "SHA256" || hv != strings.Repeat("a", 64) {
		t.Errorf("CanonicalHexDigest(sha-256, UPPER hex) = %q,%q,%v; want SHA256, lower hex, true", name, hv, ok)
	}
	// base64 (npm SRI) input decodes to canonical lowercase hex; SHA3 keeps its hyphenated canonical name.
	if name, hv, ok := CanonicalHexDigest("sha3-512", strings.Repeat("A", 86)+"=="); !ok || name != "SHA3-512" || hv != strings.Repeat("00", 64) {
		t.Errorf("CanonicalHexDigest(sha3-512, base64) = %q,%q,%v; want SHA3-512, hex of 64 zero bytes, true", name, hv, ok)
	}
	// unrecognized algorithm and malformed value are dropped.
	if _, _, ok := CanonicalHexDigest("crc32", strings.Repeat("a", 8)); ok {
		t.Error("CanonicalHexDigest must drop an unrecognized algorithm")
	}
	if _, _, ok := CanonicalHexDigest("SHA256", "nope"); ok {
		t.Error("CanonicalHexDigest must drop a wrong-length value")
	}
}

func TestValidChecksum(t *testing.T) {
	sha256Hex := strings.Repeat("a", 64)
	sha512SRI := strings.Repeat("A", 86) + "==" // 88-char base64 → 64 bytes = a real SHA-512
	cases := []struct {
		name string
		c    Checksum
		want bool
	}{
		{"valid sha256 hex", Checksum{Algorithm: "SHA256", Value: sha256Hex}, true},
		{"valid sha256 UPPER hex", Checksum{Algorithm: "SHA256", Value: strings.ToUpper(sha256Hex)}, true},
		{"valid sha512 base64 SRI", Checksum{Algorithm: "sha-512", Value: sha512SRI}, true},
		{"valid sha1 hex", Checksum{Algorithm: "SHA1", Value: strings.Repeat("f", 40)}, true},
		{"unknown algorithm", Checksum{Algorithm: "CRC32", Value: strings.Repeat("a", 8)}, false},
		{"empty value", Checksum{Algorithm: "SHA256", Value: ""}, false},
		{"wrong length hex", Checksum{Algorithm: "SHA256", Value: "aaa"}, false},
		{"non-hex right length", Checksum{Algorithm: "SHA256", Value: strings.Repeat("z", 64)}, false},
		{"over max chars", Checksum{Algorithm: "SHA256", Value: strings.Repeat("a", maxDigestChars+1)}, false},
		{"empty algorithm", Checksum{Algorithm: "", Value: sha256Hex}, false},
	}
	for _, tc := range cases {
		if got := ValidChecksum(tc.c); got != tc.want {
			t.Errorf("%s: ValidChecksum(%+v) = %v, want %v", tc.name, tc.c, got, tc.want)
		}
	}
}
