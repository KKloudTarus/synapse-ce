package secretscan

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// A secret carried inside a base64 value (a Kubernetes Secret, a base64-wrapped credential) is found by
// the decode pass and reported at the encoded line.
func TestDecodesBase64EncodedSecret(t *testing.T) {
	rs := scanDir(t, map[string]string{
		"k8s-secret.yaml": "apiVersion: v1\nkind: Secret\ndata:\n  token: " + base64.StdEncoding.EncodeToString([]byte(ghToken)) + "\n",
		"env.b64":         "GH=" + base64.RawURLEncoding.EncodeToString([]byte(ghToken)) + "\n",
	})
	if f := hasRule(rs, "github-token"); f == nil {
		t.Fatalf("a base64-encoded github token must be found via decoding, got %+v", rs)
	} else if strings.Contains(f.match, ghToken) {
		t.Errorf("the decoded secret must stay redacted, got %q", f.match)
	}
}

// A hex-encoded secret is decoded and found.
func TestDecodesHexEncodedSecret(t *testing.T) {
	rs := scanDir(t, map[string]string{
		"creds.txt": "credential = " + hex.EncodeToString([]byte(ghToken)) + "\n",
	})
	if hasRule(rs, "github-token") == nil {
		t.Fatalf("a hex-encoded github token must be found via decoding, got %+v", rs)
	}
}

// The decode pass is purely additive: an encoded value with no secret inside (a hash, random data)
// produces nothing, so it does not manufacture false positives.
func TestDecodePassIgnoresNonSecretEncodings(t *testing.T) {
	digest := sha256.Sum256([]byte("not a secret, just entropy"))
	rs := scanDir(t, map[string]string{
		// A base64 blob and a hex hash that decode to random bytes with no detector keyword.
		"data.json": "{\"blob\": \"" + base64.StdEncoding.EncodeToString(digest[:]) + "\", \"digest\": \"" + hex.EncodeToString(digest[:]) + "\"}\n",
	})
	if len(rs) != 0 {
		t.Errorf("a base64/hex blob with no embedded secret must produce no finding, got %+v", rs)
	}
}

// An inline allow annotation on the encoded line suppresses the decoded finding, exactly as it does for a
// raw one.
func TestDecodePassHonorsInlineAllow(t *testing.T) {
	rs := scanDir(t, map[string]string{
		"allowed.yaml": "token: " + base64.StdEncoding.EncodeToString([]byte(ghToken)) + " # synapse:allow test fixture\n",
	})
	if hasRule(rs, "github-token") != nil {
		t.Errorf("an inline allow on the encoded line must suppress the decoded finding, got %+v", rs)
	}
}

// A base64 blob larger than the per-token cap is not decoded, bounding the pass against a decode-bomb.
func TestDecodePassBoundsHugeToken(t *testing.T) {
	huge := base64.StdEncoding.EncodeToString([]byte(ghToken + strings.Repeat("A", maxEncodedTokenLen)))
	rs := scanDir(t, map[string]string{
		"big.b64": "x=" + huge + "\n",
	})
	// The oversized token is skipped, so the embedded token is not surfaced through the decode pass.
	if hasRule(rs, "github-token") != nil {
		t.Errorf("a token past the per-token cap must not be decoded, got %+v", rs)
	}
}

func TestDecodeHelpers(t *testing.T) {
	if _, ok := decodeHexToken("abc"); ok { // odd length
		t.Error("odd-length hex must not decode")
	}
	if b, ok := decodeBase64Token(base64.StdEncoding.EncodeToString([]byte("hello world payload"))); !ok || string(b) != "hello world payload" {
		t.Errorf("std base64 must round-trip, got %q ok=%v", b, ok)
	}
	if _, ok := decodeBase64Token("!!!! not base64 !!!!"); ok {
		t.Error("non-base64 must not decode")
	}
	_ = context.Background()
}

// A file packed with many encoded-looking tokens is bounded by the decode caps: it completes without
// manufacturing findings and without unbounded work (regression for the DoS-bounding fix).
func TestDecodePassBoundsManyTokens(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		// Distinct 40-char base64 runs that decode to random-looking bytes with no detector keyword.
		digest := sha256.Sum256([]byte{byte(i), byte(i >> 8), byte(i >> 16)})
		b.WriteString("v")
		b.WriteString(strconv.Itoa(i))
		b.WriteString("=")
		b.WriteString(base64.StdEncoding.EncodeToString(digest[:24]))
		b.WriteString("\n")
	}
	rs := scanDir(t, map[string]string{"packed.txt": b.String()})
	if len(rs) != 0 {
		t.Errorf("a file of non-secret encoded tokens must produce no finding, got %d", len(rs))
	}
}
