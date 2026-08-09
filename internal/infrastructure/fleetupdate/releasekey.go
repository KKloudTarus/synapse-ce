package fleetupdate

import (
	_ "embed"
	"fmt"
	"os"
	"strings"
)

// The release verifier key is COMPILED INTO the agent, not fetched.
//
// That is the whole point of it. A self-update verifier key delivered by the control plane would be
// worthless: the control plane is one of the things this signature defends against. An agent that
// learned its trust root from the same channel that serves it updates could be told to trust anything.
//
//go:embed release_key.pub
var embeddedReleaseKey string

// ReleasePublicKeyOverrideEnv lets an operator point an agent at a different release key.
//
// It exists for two real cases — key rotation, where a fleet must accept the new key before the old one
// is retired, and a private build with its own signing key — and for nothing else. It is deliberately
// an OPERATOR-side setting on the host, not something the control plane can set, for the same reason
// the key is embedded.
const ReleasePublicKeyOverrideEnv = "SYNAPSE_UPDATE_PUBLIC_KEY"

// DefaultVerifier returns the verifier an agent uses to gate a self-update.
//
// It fails closed: a build with no embedded key, or an unusable override, returns an error rather than
// a permissive verifier. An agent that cannot verify an update must refuse to update, never update
// without verifying.
func DefaultVerifier() (*Ed25519Verifier, error) {
	key := strings.TrimSpace(embeddedReleaseKey)
	source := "embedded release key"
	if override := strings.TrimSpace(os.Getenv(ReleasePublicKeyOverrideEnv)); override != "" {
		key, source = override, ReleasePublicKeyOverrideEnv
	}
	if key == "" {
		return nil, fmt.Errorf("fleetupdate: no release public key (%s is empty); refusing to verify updates", source)
	}
	verifier, err := NewEd25519Verifier(key)
	if err != nil {
		return nil, fmt.Errorf("fleetupdate: %s is not a usable release public key: %w", source, err)
	}
	return verifier, nil
}

// EmbeddedReleasePublicKey returns the compiled-in key, so a build can report what it trusts.
func EmbeddedReleasePublicKey() string { return strings.TrimSpace(embeddedReleaseKey) }
