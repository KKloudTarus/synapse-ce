package fleetagent

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func mkKey(t *testing.T, agent shared.ID, purpose SigningPurpose, nb, na time.Time) (AgentSigningKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	k, err := NewSigningKey(agent, purpose, pub, nb, na)
	if err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}
	return k, priv
}

func TestNewSigningKeyDerivesKeyIDAndValidates(t *testing.T) {
	nb := time.Unix(1000, 0)
	na := nb.Add(time.Hour)
	pub, _, _ := ed25519.GenerateKey(nil)
	k, err := NewSigningKey("agent:1", PurposeDetectionBatch, pub, nb, na)
	if err != nil {
		t.Fatal(err)
	}
	if k.KeyID != evidence.KeyFingerprint(pub) {
		t.Errorf("KeyID must be the fingerprint of the public key")
	}
	if k.Algorithm != SigningAlgorithm {
		t.Errorf("algorithm must default to %q", SigningAlgorithm)
	}
	if err := k.Validate(); err != nil {
		t.Errorf("a freshly minted key must validate: %v", err)
	}
}

func TestNewSigningKeyRejectsBadInput(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	nb := time.Unix(1000, 0)
	na := nb.Add(time.Hour)
	cases := map[string]func() (AgentSigningKey, error){
		"empty agent": func() (AgentSigningKey, error) { return NewSigningKey("", PurposeDetectionBatch, pub, nb, na) },
		"bad purpose": func() (AgentSigningKey, error) { return NewSigningKey("a", "no-such", pub, nb, na) },
		"short key": func() (AgentSigningKey, error) {
			return NewSigningKey("a", PurposeDetectionBatch, ed25519.PublicKey{1, 2, 3}, nb, na)
		},
		"zero window": func() (AgentSigningKey, error) {
			return NewSigningKey("a", PurposeDetectionBatch, pub, time.Time{}, na)
		},
		"inverted window": func() (AgentSigningKey, error) {
			return NewSigningKey("a", PurposeDetectionBatch, pub, na, nb)
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := fn(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

func TestSigningKeyValidateRejectsCorruptRow(t *testing.T) {
	base, _ := mkKey(t, "agent:1", PurposeDetectionBatch, time.Unix(1000, 0), time.Unix(5000, 0))
	otherPub, _, _ := ed25519.GenerateKey(nil)
	mutate := map[string]func(*AgentSigningKey){
		"keyid does not match key": func(k *AgentSigningKey) { k.PublicKey = otherPub },
		"bad algorithm":            func(k *AgentSigningKey) { k.Algorithm = "rsa" },
		"unknown purpose":          func(k *AgentSigningKey) { k.Purpose = "nope" },
		"revoked before valid":     func(k *AgentSigningKey) { k.RevokedAt = k.NotBefore.Add(-time.Second) },
	}
	for name, m := range mutate {
		t.Run(name, func(t *testing.T) {
			k := base
			m(&k)
			if err := k.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

func TestSigningKeyStatusAndUsability(t *testing.T) {
	nb := time.Unix(1000, 0)
	na := time.Unix(2000, 0)
	k, _ := mkKey(t, "agent:1", PurposeDetectionBatch, nb, na)

	if got := k.StatusAt(nb.Add(-time.Second)); got != KeyPending {
		t.Errorf("before NotBefore = pending, got %s", got)
	}
	if got := k.StatusAt(nb.Add(time.Second)); got != KeyActive {
		t.Errorf("inside window = active, got %s", got)
	}
	if got := k.StatusAt(na); got != KeyExpired {
		t.Errorf("at NotAfter = expired, got %s", got)
	}
	if err := k.UsableAt(nb.Add(time.Second)); err != nil {
		t.Errorf("active key must be usable: %v", err)
	}
	for _, at := range []time.Time{nb.Add(-time.Second), na} {
		if err := k.UsableAt(at); !errors.Is(err, shared.ErrForbidden) {
			t.Errorf("a non-active key must fail closed at %v, got %v", at, err)
		}
	}

	// Revocation takes precedence over the window: revoked mid-window reads Revoked from RevokedAt on.
	revoked := k
	revoked.RevokedAt = time.Unix(1500, 0)
	if got := revoked.StatusAt(time.Unix(1400, 0)); got != KeyActive {
		t.Errorf("before revocation, still active, got %s", got)
	}
	if got := revoked.StatusAt(time.Unix(1500, 0)); got != KeyRevoked {
		t.Errorf("at revocation = revoked, got %s", got)
	}
	if err := revoked.UsableAt(time.Unix(1600, 0)); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("a revoked key must fail closed, got %v", err)
	}
}

func TestKeyPossessionProofRoundTrip(t *testing.T) {
	k, priv := mkKey(t, "agent:1", PurposeDetectionBatch, time.Unix(1000, 0), time.Unix(5000, 0))
	proof := ProveKeyPossession(priv, k)
	if err := VerifyKeyPossession(k, proof); err != nil {
		t.Fatalf("a genuine possession proof must verify: %v", err)
	}

	// A proof made with a DIFFERENT private key must not verify (no possession).
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	if err := VerifyKeyPossession(k, ProveKeyPossession(otherPriv, k)); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a proof from a different key must be rejected, got %v", err)
	}

	// A binding tampered AFTER the proof (different agent / purpose) must not verify: the proof commits
	// to the exact binding, so re-pointing the key at another agent breaks it.
	reagent := k
	reagent.AgentID = "agent:2"
	if err := VerifyKeyPossession(reagent, proof); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a proof must not verify against a re-bound agent, got %v", err)
	}

	// A malformed proof is rejected.
	if err := VerifyKeyPossession(k, "not-base64!!"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a malformed proof must be rejected, got %v", err)
	}
}

func TestVerifyBatchWithKeyGate(t *testing.T) {
	now := time.Unix(1500, 0)
	k, priv := mkKey(t, "agent:1", PurposeDetectionBatch, time.Unix(1000, 0), time.Unix(2000, 0))
	b := AgentBatch{AgentID: "agent:1", EngagementID: "eng-1", Sequence: 1, KeyID: k.KeyID,
		Detections: []DetectionRef{{ID: "d1", ContentSHA256: "h1"}}}
	b.Signature = SignBatch(priv, b)

	if err := VerifyBatchWithKey(k, PurposeDetectionBatch, now, b); err != nil {
		t.Fatalf("a well-formed batch under an active, bound, matching key must verify: %v", err)
	}

	// Wrong purpose: a telemetry key must not verify a detection batch.
	wrongPurpose := k
	wrongPurpose.Purpose = PurposeTelemetryBatch
	if err := VerifyBatchWithKey(wrongPurpose, PurposeDetectionBatch, now, b); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("cross-purpose key must fail closed, got %v", err)
	}

	// Key bound to a different agent.
	wrongAgent := k
	wrongAgent.AgentID = "agent:2"
	if err := VerifyBatchWithKey(wrongAgent, PurposeDetectionBatch, now, b); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("key bound to another agent must fail closed, got %v", err)
	}

	// Envelope names a different KeyID than the resolved key.
	mismatch := b
	mismatch.KeyID = "some-other-kid"
	mismatch.Signature = SignBatch(priv, mismatch)
	if err := VerifyBatchWithKey(k, PurposeDetectionBatch, now, mismatch); !errors.Is(err, ErrBadBatchSignature) {
		t.Errorf("a KeyID mismatch must be refused, got %v", err)
	}

	// Outside the validity window (expired at now).
	if err := VerifyBatchWithKey(k, PurposeDetectionBatch, time.Unix(3000, 0), b); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("an expired key must fail closed, got %v", err)
	}

	// Tampered payload: the signature no longer verifies.
	tampered := b
	tampered.Sequence = 2
	if err := VerifyBatchWithKey(k, PurposeDetectionBatch, now, tampered); !errors.Is(err, ErrBadBatchSignature) {
		t.Errorf("a tampered batch must fail the signature check, got %v", err)
	}
}

func TestActiveKeyForPrefersNewestDuringOverlap(t *testing.T) {
	now := time.Unix(1500, 0)
	old, _ := mkKey(t, "agent:1", PurposeDetectionBatch, time.Unix(1000, 0), time.Unix(2000, 0))
	newer, _ := mkKey(t, "agent:1", PurposeDetectionBatch, time.Unix(1400, 0), time.Unix(2400, 0)) // overlaps old
	telem, _ := mkKey(t, "agent:1", PurposeTelemetryBatch, time.Unix(1000, 0), time.Unix(2000, 0))
	expired, _ := mkKey(t, "agent:1", PurposeDetectionBatch, time.Unix(100, 0), time.Unix(200, 0))

	ring := []AgentSigningKey{old, telem, expired, newer}
	got, ok := ActiveKeyFor(ring, PurposeDetectionBatch, now)
	if !ok {
		t.Fatal("an active detection key must be found during overlap")
	}
	if got.KeyID != newer.KeyID {
		t.Errorf("overlap must select the newest-NotBefore active key")
	}

	// No usable key of that purpose → not found.
	if _, ok := ActiveKeyFor([]AgentSigningKey{expired, telem}, PurposeDetectionBatch, now); ok {
		t.Error("no usable detection key must report not-found")
	}
}
