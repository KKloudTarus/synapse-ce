package secretscan

import "testing"

// TestWordlikePathTokenSeparatesPathsFromBase64 pins the discriminator found by profiling the whole estate:
// 1,999 of 2,844 keyword-free entropy findings came from one notebook whose cell output held a printed
// catalogue dump, and every one was a CDN asset path read as base64 because "/" is in the rule's character
// class. Base64 of random bytes carries mixed case throughout; a path's segments are words and numbers.
func TestWordlikePathTokenSeparatesPathsFromBase64(t *testing.T) {
	paths := []string{
		"//prod-unicorn-asset/bi/202603/urban",
		"prod-unicorn-asset/bi/202603/weekend",
		"static/images/catalog/2026/03/product-hero",
		"deploy/kubernetes/overlays/production/values",
	}
	for _, p := range paths {
		if !wordlikePathToken(p) {
			t.Errorf("%q is a path and must not be reported as a credential", p)
		}
	}

	// A credential shape must survive, including one that contains a slash, which real base64 does.
	secrets := []string{
		"kjZ8xQ2mNp4rLw7sTv3yBc6dEf1gHi0aB/xQ2m",
		"aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV/w==",
		"sha512-UrcABB4bUrFABwbluTIBErXwvbsU7TZWfmbg",
		"AKIAQRSTUVWX2345YZ67",
		"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345",
	}
	for _, s := range secrets {
		if wordlikePathToken(s) {
			t.Errorf("%q has base64's mixed-case signature and must still be reported", s)
		}
	}
}

// TestWordlikePathTokenIgnoresSlashlessValues pins that the discriminator only ever speaks about a
// slash-bearing candidate. A token with no slash cannot be a path and must not be judged by this.
func TestWordlikePathTokenIgnoresSlashlessValues(t *testing.T) {
	for _, s := range []string{"alllowercasetokenwithnoslashes", "ALLUPPERCASENOSLASH", "202603"} {
		if wordlikePathToken(s) {
			t.Errorf("%q has no slash; the path discriminator must stay out of it", s)
		}
	}
}
