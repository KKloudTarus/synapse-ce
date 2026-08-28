package sourcepackage

import (
	"strings"
	"testing"
)

func TestValidFilename(t *testing.T) {
	valid := []string{"source.zip", "source.tar", "source.tar.gz", "source.tgz", `C:\\uploads\\source.ZIP`}
	for _, filename := range valid {
		if !ValidFilename(filename) {
			t.Errorf("ValidFilename(%q) = false", filename)
		}
	}
	invalid := []string{"", ".", "source.rar", "source.zip\nignored", "source"}
	for _, filename := range invalid {
		if ValidFilename(filename) {
			t.Errorf("ValidFilename(%q) = true", filename)
		}
	}
}

func TestDigestFromTarget(t *testing.T) {
	digest := strings.Repeat("a", 64)
	if got := DigestFromTarget(TargetPrefix + digest); got != digest {
		t.Fatalf("DigestFromTarget() = %q, want %q", got, digest)
	}
	if got := DigestFromTarget("https://example.com/source.zip"); got != "" {
		t.Fatalf("invalid target digest = %q", got)
	}
	if got := DigestFromTarget(digest); got != "" {
		t.Fatalf("unprefixed target digest = %q", got)
	}
}
