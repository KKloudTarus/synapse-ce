package ownadvisory

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

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
	if _, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(data), strings.NewReader(armoredSignature), nil); err != nil {
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
