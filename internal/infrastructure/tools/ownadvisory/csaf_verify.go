package ownadvisory

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// allowedSignatureHashes restricts CSAF detached signatures to SHA-256 and stronger. The go-crypto v1
// detached-signature path does not consult the library's weak-hash rejection policy, so without this a SHA-1,
// MD5, or RIPEMD-160 signature would verify; CheckDetachedSignatureAndHash rejects any signature whose hash is
// not in this list. CSAF providers sign with SHA-256/384/512, so a conforming provider is unaffected.
var allowedSignatureHashes = []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}

// CSAF 2.0 requires a conforming provider to publish, for every advisory, an OpenPGP signature so a consumer
// can verify integrity (the bytes were not corrupted) and authenticity (they were signed by the provider's
// key). This helper implements that check for the owned ingester. It is fail-closed: a signature that does
// not verify is an error, so a tampered or unsigned document is never ingested rather than being trusted.
// (EPIC #860 D1.8.)

// VerifyDetachedSignature checks that data carries a valid OpenPGP detached signature made by a key in the
// provided armored public keyring. Both the signature and the keyring are ASCII-armored (the CSAF .asc and
// provider public_openpgp_keys forms). Any failure to parse the key or the signature, or a signature that
// does not verify against the keyring, is fail-closed.
func VerifyDetachedSignature(data []byte, armoredSignature, armoredPublicKey string) error {
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPublicKey))
	if err != nil {
		return fmt.Errorf("%w: cannot read CSAF provider public key: %v", shared.ErrValidation, err)
	}
	block, err := armor.Decode(strings.NewReader(armoredSignature))
	if err != nil {
		return fmt.Errorf("%w: cannot read CSAF signature: %v", shared.ErrValidation, err)
	}
	// CheckDetachedSignatureAndHash (not the ...ArmoredDetachedSignature convenience) so the hash of the
	// signature that actually verifies is constrained to allowedSignatureHashes, closing the weak-hash gap.
	if _, err := openpgp.CheckDetachedSignatureAndHash(keyring, bytes.NewReader(data), block.Body, allowedSignatureHashes, nil); err != nil {
		return fmt.Errorf("%w: CSAF signature does not verify: %v", shared.ErrValidation, err)
	}
	return nil
}

// ValidateArmoredPublicKey returns an error if key is not a readable armored OpenPGP public key, so a
// misconfigured source fails at construction rather than silently rejecting every document at sync time.
func ValidateArmoredPublicKey(key string) error {
	if _, err := openpgp.ReadArmoredKeyRing(strings.NewReader(key)); err != nil {
		return fmt.Errorf("%w: invalid armored OpenPGP public key: %v", shared.ErrValidation, err)
	}
	return nil
}

// ExtractKeyByFingerprint returns an armored public key containing ONLY the entity from armoredKey whose
// primary-key fingerprint equals want (hex, spaces and case ignored), or "" when no entity matches. CSAF
// trusted-provider discovery publishes each key's fingerprint in the provider-metadata.json (fetched over
// TLS); the caller trusts only the extracted single-entity key, never the whole fetched blob. That is the
// critical distinction: a fetched keyring may legitimately or maliciously carry extra entities, and verifying
// against the full blob would let a document signed by an unbound (attacker) key in the same blob verify. By
// returning just the fingerprint-bound entity, verification is bound to exactly the key the metadata attests.
// want must be non-empty; a key with no published fingerprint cannot be bound and must not be trusted (D1.8).
func ExtractKeyByFingerprint(armoredKey, want string) (string, error) {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(want), " ", ""))
	if normalized == "" {
		return "", fmt.Errorf("%w: empty key fingerprint", shared.ErrValidation)
	}
	ring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredKey))
	if err != nil {
		return "", fmt.Errorf("%w: invalid armored OpenPGP public key: %v", shared.ErrValidation, err)
	}
	for _, entity := range ring {
		if entity.PrimaryKey == nil || hex.EncodeToString(entity.PrimaryKey.Fingerprint) != normalized {
			continue
		}
		var buf bytes.Buffer
		writer, aerr := armor.Encode(&buf, openpgp.PublicKeyType, nil)
		if aerr != nil {
			return "", fmt.Errorf("%w: cannot re-encode bound key: %v", shared.ErrValidation, aerr)
		}
		if serr := entity.Serialize(writer); serr != nil {
			return "", fmt.Errorf("%w: cannot serialize bound key: %v", shared.ErrValidation, serr)
		}
		if cerr := writer.Close(); cerr != nil {
			return "", fmt.Errorf("%w: cannot finalize bound key: %v", shared.ErrValidation, cerr)
		}
		return buf.String(), nil
	}
	return "", nil
}
