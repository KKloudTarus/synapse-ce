package ownadvisory

import (
	"testing"
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
