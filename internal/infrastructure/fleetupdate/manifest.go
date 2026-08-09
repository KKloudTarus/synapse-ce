package fleetupdate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// A release manifest BINDS the version to the artifact.
//
// This closes the gap the Plan doc comment flagged. Verifying a detached signature over the artifact
// bytes alone proves the bytes are ours; it proves nothing about the version LABEL attached to them.
// An attacker who can influence the offer — a compromised control plane, a man in the middle on an
// unauthenticated field, an operator tricked into a bad plan — could therefore pair a genuinely signed
// OLDER artifact with a higher target version. The agent's not-newer guard compares labels, so it
// would accept the swap and the fleet would move backwards onto a build whose vulnerabilities are
// already published. A downgrade primitive over a fleet is worth more to an attacker than most
// exploits.
//
// So the signed object is the manifest, not the artifact: {version, sha256, size, url}. The signature
// covers the binding, and the artifact is then checked against the sha256 the signed manifest names.
// Relabelling now requires forging a signature, which is the property we actually wanted.

// maxManifestBytes bounds a manifest document. It is small by construction; anything larger is not a
// manifest and is refused before parsing.
const maxManifestBytes = 8 << 10

// Manifest is the signed statement that a specific artifact IS a specific version.
type Manifest struct {
	// Version is the release this artifact is. It is the field an agent compares against its own.
	Version string `json:"version"`
	// SHA256 is the lowercase-hex digest of the artifact bytes.
	SHA256 string `json:"sha256"`
	// Size is the artifact length in bytes, checked before hashing so a hostile length cannot be used
	// to force unbounded work.
	Size int64 `json:"size"`
	// URL is the authenticated download location. It is inside the signature so an offer cannot point
	// a correctly-versioned agent at someone else's bytes.
	URL string `json:"url"`
	// Platform and Arch make a manifest specific to one artifact in a multi-platform release, so a
	// linux/amd64 build cannot be offered to a windows/arm64 host under the same version.
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
}

// Validate reports whether the manifest is internally usable. It is checked BEFORE the signature so a
// malformed document is refused cheaply, and again implicitly by the signature covering these bytes.
func (m Manifest) Validate() error {
	if strings.TrimSpace(m.Version) == "" {
		return errors.New("fleetupdate: manifest names no version")
	}
	if len(m.SHA256) != sha256.Size*2 {
		return fmt.Errorf("fleetupdate: manifest sha256 must be %d hex characters, got %d", sha256.Size*2, len(m.SHA256))
	}
	if _, err := hex.DecodeString(m.SHA256); err != nil {
		return errors.New("fleetupdate: manifest sha256 is not hex")
	}
	if m.SHA256 != strings.ToLower(m.SHA256) {
		return errors.New("fleetupdate: manifest sha256 must be lowercase hex, so one artifact has one representation")
	}
	if m.Size <= 0 {
		return errors.New("fleetupdate: manifest declares no artifact size")
	}
	if strings.TrimSpace(m.URL) == "" {
		return errors.New("fleetupdate: manifest names no download location")
	}
	// Only an authenticated transport. A plain-http offer would let anyone on the path serve the
	// bytes; the signature would still catch a substitution, but there is no reason to accept it.
	if !strings.HasPrefix(m.URL, "https://") {
		return errors.New("fleetupdate: manifest download location must be https")
	}
	if strings.TrimSpace(m.Platform) == "" || strings.TrimSpace(m.Arch) == "" {
		return errors.New("fleetupdate: manifest must name the platform and architecture it is for")
	}
	return nil
}

// Canonical returns the exact bytes that are signed and verified.
//
// It is a deterministic marshal of the manifest's own fields rather than the received document, so a
// signature cannot be made to cover something other than what the agent will act on: a document
// carrying extra members, different key order or different whitespace re-serialises to the same bytes
// as the manifest it parsed into, and any difference in a MEANINGFUL field changes them.
func (m Manifest) Canonical() ([]byte, error) {
	// json.Marshal of a struct emits fields in declaration order with no insignificant whitespace,
	// which is the determinism this needs.
	return json.Marshal(m)
}

// ParseSignedManifest verifies a manifest document under the release key and returns it.
//
// The order is deliberate: bound the document, parse it, validate its shape, re-canonicalise, and only
// then verify the signature over the canonical bytes. Verifying the RECEIVED bytes instead would let a
// document with duplicate or unknown members verify while parsing into something else.
func ParseSignedManifest(document, signature []byte, verifier Verifier) (Manifest, error) {
	if verifier == nil {
		return Manifest{}, errors.New("fleetupdate: no verifier, refusing to trust a manifest")
	}
	if len(document) == 0 {
		return Manifest{}, errors.New("fleetupdate: empty manifest")
	}
	if len(document) > maxManifestBytes {
		return Manifest{}, fmt.Errorf("fleetupdate: manifest is %d bytes, over the %d byte bound", len(document), maxManifestBytes)
	}
	var m Manifest
	decoder := json.NewDecoder(strings.NewReader(string(document)))
	// An unknown member means the signer and this agent do not agree on what was signed. Refusing is
	// the fail-closed reading; accepting would let a future field be silently ignored.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return Manifest{}, errors.New("fleetupdate: manifest is not a valid manifest document")
	}
	if decoder.More() {
		return Manifest{}, errors.New("fleetupdate: manifest has trailing content")
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	canonical, err := m.Canonical()
	if err != nil {
		return Manifest{}, fmt.Errorf("fleetupdate: canonicalise manifest: %w", err)
	}
	if err := verifier.Verify(canonical, signature); err != nil {
		return Manifest{}, fmt.Errorf("fleetupdate: manifest signature does not verify: %w", err)
	}
	return m, nil
}

// PlanFromManifest turns a verified manifest into an update plan.
//
// The plan's version and checksum now come from inside the signature, so the not-newer guard in Apply
// is comparing a version an attacker cannot relabel.
func PlanFromManifest(m Manifest) Plan {
	return Plan{TargetVersion: m.Version, URL: m.URL, SHA256: m.SHA256}
}

// MatchesArtifact reports whether the downloaded bytes are the artifact this manifest names.
//
// Size is checked first: a length mismatch is a cheap, certain rejection, and it stops a hostile
// server from making the agent hash gigabytes to learn the same thing.
func (m Manifest) MatchesArtifact(artifact []byte) error {
	if int64(len(artifact)) != m.Size {
		return fmt.Errorf("fleetupdate: artifact is %d bytes, manifest declares %d", len(artifact), m.Size)
	}
	sum := sha256.Sum256(artifact)
	if got := hex.EncodeToString(sum[:]); got != m.SHA256 {
		return errors.New("fleetupdate: artifact checksum does not match the signed manifest")
	}
	return nil
}

// SignManifest produces the canonical bytes and their signature. It exists so the release pipeline and
// the tests sign exactly what the agent verifies, rather than reimplementing the canonical form.
func SignManifest(m Manifest, key ed25519.PrivateKey) (document, signature []byte, err error) {
	if err := m.Validate(); err != nil {
		return nil, nil, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("fleetupdate: release private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(key))
	}
	canonical, err := m.Canonical()
	if err != nil {
		return nil, nil, fmt.Errorf("fleetupdate: canonicalise manifest: %w", err)
	}
	return canonical, ed25519.Sign(key, canonical), nil
}
