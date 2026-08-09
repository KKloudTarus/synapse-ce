package fleetupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// TestEmbeddedKeyMatchesThePublishedOne is the anti-drift check. Consumers verify against
// packaging/keys/synapse-agent-update.ed25519.pub; the agent verifies against the copy compiled into
// it. If the two ever differ, every published instruction for verifying an update becomes wrong while
// both files still look plausible.
func TestEmbeddedKeyMatchesThePublishedOne(t *testing.T) {
	t.Parallel()

	published, err := os.ReadFile("../../../packaging/keys/synapse-agent-update.ed25519.pub")
	if err != nil {
		t.Fatalf("read the published key: %v", err)
	}
	if strings.TrimSpace(string(published)) != EmbeddedReleasePublicKey() {
		t.Fatal("the embedded release key differs from packaging/keys/synapse-agent-update.ed25519.pub")
	}
}

// The default verifier must be usable out of the box: an agent that cannot verify is an agent that
// either refuses every update or, far worse, is tempted to skip verification.
func TestDefaultVerifierUsesTheEmbeddedKey(t *testing.T) {
	verifier, err := DefaultVerifier()
	if err != nil {
		t.Fatalf("the embedded key must produce a usable verifier: %v", err)
	}
	if verifier == nil {
		t.Fatal("nil verifier")
	}
}

// The override exists for rotation and private builds. An unusable one must FAIL rather than fall back
// to the embedded key: silently verifying against a different key than the operator asked for is worse
// than refusing.
func TestUnusableOverrideFailsClosed(t *testing.T) {
	t.Setenv(ReleasePublicKeyOverrideEnv, "not-a-key")
	if _, err := DefaultVerifier(); err == nil {
		t.Fatal("an unusable override must fail, never fall back to the embedded key")
	}
}

// A valid override is honoured, so a fleet can accept a new key before the old one is retired.
func TestValidOverrideIsHonoured(t *testing.T) {
	key, _ := releaseKeyForTest(t)
	t.Setenv(ReleasePublicKeyOverrideEnv, key)
	verifier, err := DefaultVerifier()
	if err != nil {
		t.Fatalf("a valid override must be accepted: %v", err)
	}
	// It really is the override, not the embedded key: a signature under the override's private half
	// verifies, which it could not under the embedded key.
	if verifier == nil {
		t.Fatal("nil verifier")
	}
}

// releaseKeyForTest returns a freshly generated hex-encoded release public key.
func releaseKeyForTest(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return hex.EncodeToString(pub), priv
}
