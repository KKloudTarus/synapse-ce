package sbom

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// Checksum digest validation – the single source of truth for "what a real integrity digest looks like",
// shared by the quality scorer (HasChecksum, via ValidChecksum) and the SPDX export gate (via
// CanonicalHexDigest). Keeping BOTH the digest-size knowledge and the canonical algorithm name here (not
// duplicated per consumer) means the scorer and the exporter can never disagree: a checksum the exporter
// would DROP as malformed must not inflate the SBOM's "checksum present" score, and both read one table.

// maxDigestChars bounds a raw digest value before any decode/allocate: no known hash encodes longer, so a
// larger value (from an untrusted imported SBOM) is rejected early rather than lower-cased/base64-decoded.
const maxDigestChars = 256

// digestSpec is a recognized hash's hex-digest length plus its canonical algorithm name. The canonical name
// is the domain's SPDX-style spelling (see Checksum.Algorithm), which the SPDX exporter emits directly – so
// there is no second, drift-prone name table in the export path.
type digestSpec struct {
	hexLen int
	name   string
	strong bool // a strong (collision-resistant, >=256-bit) modern digest, per the BSI TR-03183-2 "SHA-256 or stronger" bar
}

// digestAlgs maps a NORMALIZED hash-algorithm name (see NormalizeChecksumAlg) to its spec. It is the single
// allowlist of algorithms Synapse treats as real tamper evidence; a token absent here is not a recognized
// digest. Both the quality scorer and the SPDX export gate read this one table, so they accept exactly the
// same digests by construction – nothing to keep in sync across packages.
var digestAlgs = map[string]digestSpec{
	"SHA1": {40, "SHA1", false}, "SHA224": {56, "SHA224", false}, "SHA256": {64, "SHA256", true},
	"SHA384": {96, "SHA384", true}, "SHA512": {128, "SHA512", true},
	"SHA3256": {64, "SHA3-256", true}, "SHA3384": {96, "SHA3-384", true}, "SHA3512": {128, "SHA3-512", true},
	"BLAKE2B256": {64, "BLAKE2b-256", true}, "BLAKE2B384": {96, "BLAKE2b-384", true}, "BLAKE2B512": {128, "BLAKE2b-512", true},
	"MD2": {32, "MD2", false}, "MD4": {32, "MD4", false}, "MD5": {32, "MD5", false}, "ADLER32": {8, "ADLER32", false},
}

// NormalizeChecksumAlg uppercases an algorithm name and strips separators, so "sha-256" / "SHA256" /
// "SHA_256" and Syft's hyphen-stripped "SHA3256" all key consistently into the digest allowlist.
func NormalizeChecksumAlg(alg string) string {
	r := strings.ToUpper(strings.TrimSpace(alg))
	r = strings.ReplaceAll(r, "-", "")
	r = strings.ReplaceAll(r, "_", "")
	return r
}

// CanonicalHexDigest is THE digest acceptance gate, shared by the quality scorer and the SPDX exporter. It
// validates (algorithm, value) and returns the canonical algorithm name plus the digest as lowercase hex
// (converting a base64 Subresource-Integrity value to hex). ok is false for an unrecognized algorithm, or a
// value that is not a right-length hex or base64 digest, or one over maxDigestChars. Because both consumers
// go through this one function and one allowlist, the scorer never counts a digest the exporter would drop,
// or vice versa – the two cannot drift.
func CanonicalHexDigest(alg, value string) (name, hexValue string, ok bool) {
	spec, known := digestAlgs[NormalizeChecksumAlg(alg)]
	if !known {
		return "", "", false
	}
	v := strings.TrimSpace(value)
	if v == "" || len(v) > maxDigestChars {
		return "", "", false
	}
	if lower := strings.ToLower(v); len(lower) == spec.hexLen && isLowerHex(lower) {
		return spec.name, lower, true
	}
	if b, err := base64.StdEncoding.DecodeString(v); err == nil && len(b)*2 == spec.hexLen {
		return spec.name, hex.EncodeToString(b), true
	}
	return "", "", false
}

// ValidChecksum reports whether a checksum carries a REAL digest (a recognized algorithm whose value is a
// right-length hex or base64 digest) – the semantic-quality "checksum present" signal. It is the boolean
// view of CanonicalHexDigest, so a checksum the SPDX exporter would drop does not count toward quality.
func ValidChecksum(c Checksum) bool {
	_, _, ok := CanonicalHexDigest(c.Algorithm, c.Value)
	return ok
}

// StrongAlg reports whether an algorithm is a strong integrity digest: a collision-resistant, >=256-bit
// modern hash (SHA-256/384/512, the SHA-3 family, or BLAKE2b), as opposed to SHA-1, SHA-224, the MD family,
// or ADLER32. It underpins the "SHA-256 or stronger" bar of the BSI TR-03183-2 compliance profile. An
// unrecognized algorithm is not strong (the map miss yields the zero digestSpec, strong=false).
func StrongAlg(alg string) bool {
	return digestAlgs[NormalizeChecksumAlg(alg)].strong
}

// HasStrongChecksum reports whether a component carries a VALID digest from a strong algorithm (see
// StrongAlg). The legacy SHA1 field is a weak digest by definition, so only the Checksums entries count.
func HasStrongChecksum(c Component) bool {
	for _, ck := range c.Checksums {
		if StrongAlg(ck.Algorithm) && ValidChecksum(ck) {
			return true
		}
	}
	return false
}

// isLowerHex reports whether s is non-empty, even-length lowercase hex.
func isLowerHex(s string) bool {
	if s == "" || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
