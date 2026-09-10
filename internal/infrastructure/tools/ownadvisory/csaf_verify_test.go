package ownadvisory

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// These fixtures were produced with gpg: a 2048-bit RSA key signs csafFixtureMsg with a detached armored
// signature; csafFixtureOtherPub is an unrelated key. They pin the verifier's behaviour without gpg at test
// time.
const csafFixtureMsg = `{"document":{"category":"csaf_vex","title":"test"}}`

const csafFixtureSig = `-----BEGIN PGP SIGNATURE-----

iQEzBAABCgAdFiEEskoqIL3PDxcH4Nm6VUA+aadBa1cFAmqipaUACgkQVUA+aadB
a1fuHgf+OFmIWRbi/PGGsWTE+lcBwuB9SrarfPCwGS3djPVR2VEf7CiqO4eDug/m
0SZLBb+6xU2XtajR7R2bCGiuPJH9ik3YG/+bT5Va41iXjSUxyutxgmir7h3wfd9e
/qoL7baN7yrfZ/ZseHDG77Bnl7bCsGOmNxxAGziNIJzsQc2zfhNUN8yu1pMH4IJN
2b7SOjhPfZ6csJvigvUzvo1KNlyLKBWUlPZiNxNc5wielPSR21Q0k8pVmM4zKo+m
0u54SpzHoAwz1tL+e9WxNkAozAllg+12K4A4Rj8WaHQisPAy9THa/bs6tk5H6DUW
YhUHy3z+5Ph/yZYpbwl4AyMVjc8dyQ==
=eCqT
-----END PGP SIGNATURE-----
`

const csafFixturePub = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBGqipaUBCADj7nL/9iHFcrYiuUgQsjS7LpoG2VFpKss7izVw4+VAACPNLKWo
h6dYoAjdJCvzkQulXLUTZDWhvJj9mURHkpO3JxFHgl7aanHhTIy0yZdn5jQDeshs
L76bN/BINjZdv7AHUgmKuCD0qEXg3NZLJLCg+o8fspvaZRWmd3PlOAFKWTJRF4wK
Jfui0gm6ObgWgdaLgVTq8xkcS8bDUTsm7BruPdN9MQiCPvPjPpHyIQ36pKsP5FTA
kXBC6X87ijit2ym3VmgAblidvceUbI+pZZHYWOU97RdE7H1cJvjdn1ewNYjS67ld
+9hLhsSaT3aq3ewHzmxlA97S4vnlA61ygIwlABEBAAG0KVN5bmFwc2UgQ1NBRiBU
ZXN0IDxjc2FmLXRlc3RAZXhhbXBsZS5jb20+iQFSBBMBCgA8FiEEskoqIL3PDxcH
4Nm6VUA+aadBa1cFAmqipaUDGy8EBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA
AAoJEFVAPmmnQWtXRQEIAJPcSoN/IBGUPhbWQkGm7C38mhE9WbsjWbSAVKkXjU/7
UOYiBFB2//zbF0DcFV969go+6vM/YgjeEOlI9WaTED8t+aamHx+eU/BorHkP2mag
S8+mDdtWwPVoUumrXhWAire5xT359sPzCWLsm23AyOeB1+zcfYaOgLMzzOJyK/vr
grWeeG86HOn8lc6RoTcA6wiylUtG9rW8RtS+aISjBATuBYhK3vIxNJvb2IvfilhU
z+8g+yS37lMx5qQ6EZh1x5gKS7ce9F6QXI4N+twuUaX9bXZd+KMS5VkdgNiGAGuR
nmx0xDniVguQAYvQsxqWa11cfEnqSkQTTO11fjbRcy0=
=FGVn
-----END PGP PUBLIC KEY BLOCK-----
`

const csafFixtureOtherPub = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBGqipbgBCADW/4yz8nvVF67RQL81FR9kptmfKWru5nXEtgD0d3WUncteedJ/
jmzhdnMFxNBkXCYEAFpi+6ZC1xMSk4QIBOskdHNlH6UD/FiryOYS9vfVfcp9lFT5
IZ2uz/5Rai3bXc2MzCVIilElKM4wbqkjL66r99NA2X+JiM8eW5pR7UuO4+e2tqAR
KT/ZGrRCNgvVNJn2u7cP0B9K+ay8QsjjEJUz16N4NUpVupsfxUNNY/yKXyxc/OSV
Fh9vCCh0ehhtjUSeKb9uLxX3J6YAzZt9grcgXSOFkZPJZa0Wx6nNlzUxr23mwg3f
FPJblMOmjjVMV4EcrXogL0q6539E8qJo9wsnABEBAAG0HU90aGVyIEtleSA8b3Ro
ZXJAZXhhbXBsZS5jb20+iQFSBBMBCgA8FiEE3BLMHOaO2CI4FOWqynafzEyA29QF
AmqipbgDGy8EBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEMp2n8xMgNvU
BwwH/igb7dM0nxJnhFLlNFM96ZHZMrlx4uDPLir5TRryu43OZzKumQuFNsrY/Icx
rFZQAGq/bTJcbW479OPtAz+/UjkPG/6IiZ4yriGIc/aQoRldI/6BXpZSQYBZYZKs
Mr5cF0P+OCHCpOuAssbACSCabk1HLi7ziiuV1excNU0SDNGQnXPplCsFkfM4Y/YE
gxB1Zxn7Cpv7tpOtXz/gCVbfDFYyyMebcIJe2jctGFmSSezSV7xnKGU/v65+UJqh
T0WTrDgE94Oo3kutItZreugq+8112TBJcLGoblfonbcXCtkt+F7YLZm3Cw5fvt+7
SFaDK5SbZYQDEeiaGciQCPIgkM0=
=ZB0O
-----END PGP PUBLIC KEY BLOCK-----
`

// TestVerifyDetachedSignature covers EPIC #860 D1.8: a valid provider signature passes; a tampered document,
// the wrong key, or a malformed signature/key is fail-closed.
func TestVerifyDetachedSignature(t *testing.T) {
	if err := VerifyDetachedSignature([]byte(csafFixtureMsg), csafFixtureSig, csafFixturePub); err != nil {
		t.Fatalf("a valid signature must verify: %v", err)
	}
	if err := VerifyDetachedSignature([]byte(csafFixtureMsg+" tampered"), csafFixtureSig, csafFixturePub); err == nil {
		t.Fatal("a tampered document must fail closed")
	}
	if err := VerifyDetachedSignature([]byte(csafFixtureMsg), csafFixtureSig, csafFixtureOtherPub); err == nil {
		t.Fatal("a signature from an unrelated key must fail closed")
	}
	if err := VerifyDetachedSignature([]byte(csafFixtureMsg), "not-a-signature", csafFixturePub); err == nil {
		t.Fatal("a malformed signature must fail closed")
	}
	if err := VerifyDetachedSignature([]byte(csafFixtureMsg), csafFixtureSig, "not-a-key"); err == nil {
		t.Fatal("a malformed key must fail closed")
	}
}

// TestExtractKeyByFingerprint covers the D1.8 trust binding: discovery trusts ONLY the entity whose primary-key
// fingerprint matches the fingerprint the provider-metadata published, never the whole fetched blob. The
// critical case is a keyring that carries the legitimate key PLUS an extra (attacker) key: extraction must
// return a single-entity key bound to the requested fingerprint, so a document signed by the extra key cannot
// verify against it.
func TestExtractKeyByFingerprint(t *testing.T) {
	const realFP = "b24a2a20bdcf0f1707e0d9ba55403e69a7416b57"
	const decoyFP = "dc12cc1ce68ed8223814e5aaca769fcc4c80dbd4"

	// A two-entity keyring: the real signing key and an unrelated (attacker) key in one armored blob.
	var blob bytes.Buffer
	writer, err := armor.Encode(&blob, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, armored := range []string{csafFixturePub, csafFixtureOtherPub} {
		ring, rerr := openpgp.ReadArmoredKeyRing(strings.NewReader(armored))
		if rerr != nil {
			t.Fatal(rerr)
		}
		if serr := ring[0].Serialize(writer); serr != nil {
			t.Fatal(serr)
		}
	}
	if cerr := writer.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	twoEntity := blob.String()

	// Extract by the real fingerprint (with case/space variants): the result is a single-entity key bound to
	// the real fingerprint, and it verifies the real signature.
	for _, want := range []string{realFP, "B24A2A20BDCF0F1707E0D9BA55403E69A7416B57", "B24A 2A20 BDCF 0F17 07E0  D9BA 5540 3E69 A741 6B57"} {
		bound, berr := ExtractKeyByFingerprint(twoEntity, want)
		if berr != nil || bound == "" {
			t.Fatalf("real key must extract for %q: bound=%q err=%v", want, bound, berr)
		}
		ring, rerr := openpgp.ReadArmoredKeyRing(strings.NewReader(bound))
		if rerr != nil || len(ring) != 1 {
			t.Fatalf("extracted key must be single-entity: n=%d err=%v", len(ring), rerr)
		}
		if verr := VerifyDetachedSignature([]byte(csafFixtureMsg), csafFixtureSig, bound); verr != nil {
			t.Fatalf("real signature must verify against the extracted real key: %v", verr)
		}
	}

	// The bypass proof: extracting the decoy entity from the SAME blob yields a key the real signature does
	// NOT verify against. If extraction returned the whole blob, the real signature would verify here.
	decoyBound, err := ExtractKeyByFingerprint(twoEntity, decoyFP)
	if err != nil || decoyBound == "" {
		t.Fatalf("decoy key must extract: bound=%q err=%v", decoyBound, err)
	}
	if verr := VerifyDetachedSignature([]byte(csafFixtureMsg), csafFixtureSig, decoyBound); verr == nil {
		t.Fatal("real signature must NOT verify against the extracted decoy key (whole-blob trust bug)")
	}

	// A fingerprint present in neither entity yields no key.
	if bound, err := ExtractKeyByFingerprint(twoEntity, "00"+realFP[2:]); err != nil || bound != "" {
		t.Fatalf("an absent fingerprint must yield no key: bound=%q err=%v", bound, err)
	}
	// An empty fingerprint and a malformed key are rejected.
	if _, err := ExtractKeyByFingerprint(csafFixturePub, "  "); err == nil {
		t.Fatal("an empty fingerprint must error")
	}
	if _, err := ExtractKeyByFingerprint("not-a-key", realFP); err == nil {
		t.Fatal("a malformed key must error")
	}
}

// TestExtractKeyByFingerprintRejectsForeignSubkeyBinding pins the last trust-binding guarantee: an attacker who
// takes a provider's fingerprint-matching primary key and injects their OWN signing subkey cannot get it
// trusted, because forging a subkey binding needs the primary's private key. go-crypto validates subkey binding
// signatures on read, so a subkey bound by a foreign key fails the read and ExtractKeyByFingerprint fails closed
// rather than admitting an attacker signing subkey under the matched primary.
func TestExtractKeyByFingerprintRejectsForeignSubkeyBinding(t *testing.T) {
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}
	entA, err := openpgp.NewEntity("A", "", "a@example.com", cfg)
	if err != nil {
		t.Fatal(err)
	}
	entB, err := openpgp.NewEntity("B", "", "b@example.com", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(entA.Subkeys) == 0 || len(entB.Subkeys) == 0 {
		t.Skip("key generation produced no subkey to graft")
	}
	fpA := hex.EncodeToString(entA.PrimaryKey.Fingerprint)

	// A clean entA extracts.
	var clean bytes.Buffer
	cw, err := armor.Encode(&clean, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entA.Serialize(cw); err != nil {
		t.Fatal(err)
	}
	if err := cw.Close(); err != nil {
		t.Fatal(err)
	}
	if bound, err := ExtractKeyByFingerprint(clean.String(), fpA); err != nil || bound == "" {
		t.Fatalf("a clean key must extract: bound=%q err=%v", bound, err)
	}

	// Graft entB's subkey binding onto entA's subkey (a binding made by a foreign primary), then serialize entA.
	entA.Subkeys[0].Sig = entB.Subkeys[0].Sig
	var tampered bytes.Buffer
	tw, err := armor.Encode(&tampered, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entA.Serialize(tw); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractKeyByFingerprint(tampered.String(), fpA); err == nil {
		t.Fatal("a subkey with a foreign binding signature must fail closed on read")
	}
}
