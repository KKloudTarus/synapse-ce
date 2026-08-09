package fleetupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func releaseKey(t *testing.T) (ed25519.PrivateKey, *Ed25519Verifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	verifier, err := NewEd25519Verifier(hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	return priv, verifier
}

func manifestFor(artifact []byte, version string) Manifest {
	sum := sha256.Sum256(artifact)
	return Manifest{
		Version:  version,
		SHA256:   hex.EncodeToString(sum[:]),
		Size:     int64(len(artifact)),
		URL:      "https://releases.example/synapse-agent-" + version + "-linux-amd64.tar.gz",
		Platform: "linux",
		Arch:     "amd64",
	}
}

// TestSignedManifestBindsVersionToArtifact is the whole reason this file exists.
//
// Signing the artifact bytes alone proves the bytes are ours and says nothing about the version label
// attached to them. An attacker who can influence the offer could then pair a genuinely signed OLDER
// artifact with a higher target version; the agent's not-newer guard compares labels, so the fleet
// moves backwards onto a build whose vulnerabilities are already published.
func TestSignedManifestBindsVersionToArtifact(t *testing.T) {
	t.Parallel()

	key, verifier := releaseKey(t)
	oldArtifact := []byte("this is the 1.0.0 agent binary")

	// The attacker has a legitimately signed manifest for the OLD version.
	document, signature, err := SignManifest(manifestFor(oldArtifact, "1.0.0"), key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := ParseSignedManifest(document, signature, verifier); err != nil {
		t.Fatalf("the genuine manifest must verify: %v", err)
	}

	// They relabel it as a newer version, keeping the real signature.
	var relabelled Manifest
	if err := json.Unmarshal(document, &relabelled); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	relabelled.Version = "9.9.9"
	forged, err := relabelled.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if _, err := ParseSignedManifest(forged, signature, verifier); err == nil {
		t.Fatal("a relabelled manifest must NOT verify — this is the downgrade-via-relabel attack")
	}

	// Repointing the download at someone else's bytes is the same class and must also fail.
	repointed := relabelled
	repointed.Version = "1.0.0"
	repointed.URL = "https://evil.example/payload.tar.gz"
	repointedDoc, err := repointed.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if _, err := ParseSignedManifest(repointedDoc, signature, verifier); err == nil {
		t.Fatal("repointing the download location must not verify")
	}

	// And so is swapping the checksum, which would let signed metadata vouch for unsigned bytes.
	swapped := relabelled
	swapped.Version = "1.0.0"
	swapped.SHA256 = strings.Repeat("a", sha256.Size*2)
	swappedDoc, err := swapped.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if _, err := ParseSignedManifest(swappedDoc, signature, verifier); err == nil {
		t.Fatal("swapping the artifact checksum must not verify")
	}
}

// The artifact is checked against the digest the SIGNED manifest names, so signed metadata can never
// vouch for bytes it did not describe.
func TestArtifactMustMatchTheSignedManifest(t *testing.T) {
	t.Parallel()

	artifact := []byte("the real agent binary")
	m := manifestFor(artifact, "1.2.3")
	if err := m.MatchesArtifact(artifact); err != nil {
		t.Fatalf("the genuine artifact must match: %v", err)
	}
	if err := m.MatchesArtifact([]byte("a different binary of the same length!")); err == nil {
		t.Fatal("different bytes must not match the signed digest")
	}
	// A length mismatch is rejected before hashing, so a hostile server cannot make the agent hash
	// gigabytes to learn what the declared size already told it.
	if err := m.MatchesArtifact(append(artifact, 'x')); err == nil {
		t.Fatal("a size mismatch must be refused")
	}
}

func TestManifestValidation(t *testing.T) {
	t.Parallel()

	good := manifestFor([]byte("x"), "1.0.0")
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"no version", func(m *Manifest) { m.Version = " " }},
		{"short digest", func(m *Manifest) { m.SHA256 = "abcd" }},
		{"non-hex digest", func(m *Manifest) { m.SHA256 = strings.Repeat("z", 64) }},
		{"uppercase digest", func(m *Manifest) { m.SHA256 = strings.ToUpper(m.SHA256) }},
		{"no size", func(m *Manifest) { m.Size = 0 }},
		{"negative size", func(m *Manifest) { m.Size = -1 }},
		{"no url", func(m *Manifest) { m.URL = "" }},
		{"plain http url", func(m *Manifest) { m.URL = "http://releases.example/a.tar.gz" }},
		{"no platform", func(m *Manifest) { m.Platform = "" }},
		{"no arch", func(m *Manifest) { m.Arch = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			m := good
			test.mutate(&m)
			if err := m.Validate(); err == nil {
				t.Fatalf("%s must be refused", test.name)
			}
		})
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("a complete manifest must validate: %v", err)
	}
}

// A document carrying members this agent does not know about means the signer and the agent disagree
// about what was signed. Refusing is the fail-closed reading.
func TestUnknownAndTrailingContentAreRefused(t *testing.T) {
	t.Parallel()

	key, verifier := releaseKey(t)
	artifact := []byte("binary")
	document, signature, err := SignManifest(manifestFor(artifact, "1.0.0"), key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	withExtra := strings.TrimSuffix(string(document), "}") + `,"rollout":"everyone"}`
	if _, err := ParseSignedManifest([]byte(withExtra), signature, verifier); err == nil {
		t.Fatal("an unknown member must be refused rather than silently ignored")
	}
	if _, err := ParseSignedManifest(append(document, ' ', '{'), signature, verifier); err == nil {
		t.Fatal("trailing content must be refused")
	}
	if _, err := ParseSignedManifest(nil, signature, verifier); err == nil {
		t.Fatal("an empty manifest must be refused")
	}
	oversized := make([]byte, maxManifestBytes+1)
	if _, err := ParseSignedManifest(oversized, signature, verifier); err == nil {
		t.Fatal("an oversized manifest must be refused before parsing")
	}
	if _, err := ParseSignedManifest(document, signature, nil); err == nil {
		t.Fatal("no verifier means no trust — a nil verifier must refuse, never pass")
	}
	if _, err := ParseSignedManifest(document, nil, verifier); err == nil {
		t.Fatal("a missing signature must be refused")
	}
}

// A manifest signed by a different key is not ours.
func TestManifestFromAnotherKeyIsRefused(t *testing.T) {
	t.Parallel()

	_, verifier := releaseKey(t)
	otherKey, _ := releaseKey(t)
	document, signature, err := SignManifest(manifestFor([]byte("binary"), "1.0.0"), otherKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := ParseSignedManifest(document, signature, verifier); err == nil {
		t.Fatal("a manifest signed by another key must not verify under the release key")
	}
}

// The canonical form must be stable: the same manifest signs to the same bytes every time, and a
// document that differs only in key order or whitespace verifies, because it re-canonicalises.
func TestCanonicalFormIsStable(t *testing.T) {
	t.Parallel()

	key, verifier := releaseKey(t)
	m := manifestFor([]byte("binary"), "1.0.0")
	document, signature, err := SignManifest(m, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, _, err := SignManifest(m, key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if string(again) != string(document) {
			t.Fatal("the canonical form must not vary between calls")
		}
	}
	// Re-ordered keys and added whitespace parse into the same manifest and therefore still verify.
	reordered := `{ "url": "` + m.URL + `" , "size": ` + string(document[strings.Index(string(document), `"size":`)+7:strings.Index(string(document), `,"url"`)]) +
		` , "sha256": "` + m.SHA256 + `", "version": "` + m.Version + `", "platform": "` + m.Platform + `", "arch": "` + m.Arch + `" }`
	if _, err := ParseSignedManifest([]byte(reordered), signature, verifier); err != nil {
		t.Fatalf("a semantically identical document must still verify: %v", err)
	}
}

func TestPlanFromManifestCarriesTheSignedFields(t *testing.T) {
	t.Parallel()

	m := manifestFor([]byte("binary"), "2.0.0")
	plan := PlanFromManifest(m)
	if plan.TargetVersion != m.Version || plan.SHA256 != m.SHA256 || plan.URL != m.URL {
		t.Fatalf("plan %+v must carry the signed version, digest and url", plan)
	}
}
