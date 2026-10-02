package identityfoundation

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestClassifier(t *testing.T) {
	const issuer = "https://idp.example.test"
	digest := strings.Repeat("a", 64)
	link := []ports.IdentityLegacyLink{{Issuer: issuer, Subject: "s"}}
	foreign := []ports.IdentityLegacyLink{{Issuer: "https://other.test", Subject: "s"}}
	cases := []struct {
		name   string
		in     ports.IdentityLegacyUser
		class  ports.IdentityBackfillClass
		cred   ports.IdentityCredentialClass
		proj   bool
		key    bool
		active bool
	}{
		{"bootstrap", ports.IdentityLegacyUser{ID: ports.IdentityBootstrapUserID, APIKeyHash: digest, KeyEvidence: ports.IdentityKeyIssued}, ports.IdentityBackfillBootstrapSkipped, ports.IdentityCredentialNone, false, false, false},
		{"issued", ports.IdentityLegacyUser{ID: "u", APIKeyHash: digest, KeyEvidence: ports.IdentityKeyIssued}, ports.IdentityBackfillMigrated, ports.IdentityCredentialReal, true, true, true},
		{"issued disabled keeps revoked", ports.IdentityLegacyUser{ID: "u", APIKeyHash: digest, Disabled: true, KeyEvidence: ports.IdentityKeyIssued}, ports.IdentityBackfillSuspended, ports.IdentityCredentialReal, true, true, false},
		{"replaced by disable", ports.IdentityLegacyUser{ID: "u", APIKeyHash: digest, Disabled: true, KeyEvidence: ports.IdentityKeyRevokedByDisable}, ports.IdentityBackfillSuspended, ports.IdentityCredentialDisabled, true, false, false},
		{"placeholder", ports.IdentityLegacyUser{ID: "u", APIKeyHash: digest, KeyEvidence: ports.IdentityKeyNoEvidence, Links: link}, ports.IdentityBackfillMigrated, ports.IdentityCredentialPlaceholder, true, false, false},
		{"unproven", ports.IdentityLegacyUser{ID: "u", APIKeyHash: digest, KeyEvidence: ports.IdentityKeyNoEvidence}, ports.IdentityBackfillAmbiguousUnprovenKey, ports.IdentityCredentialAmbiguous, true, false, false},
		{"corrupt", ports.IdentityLegacyUser{ID: "u", APIKeyHash: "xyz", KeyEvidence: ports.IdentityKeyIssued}, ports.IdentityBackfillAmbiguousCorrupt, ports.IdentityCredentialAmbiguous, false, false, false},
		{"duplicate", ports.IdentityLegacyUser{ID: "u", APIKeyHash: digest, DuplicateHash: true, KeyEvidence: ports.IdentityKeyIssued}, ports.IdentityBackfillAmbiguousDuplicate, ports.IdentityCredentialAmbiguous, false, false, false},
		{"foreign link", ports.IdentityLegacyUser{ID: "u", APIKeyHash: digest, KeyEvidence: ports.IdentityKeyIssued, Links: foreign}, ports.IdentityBackfillAmbiguousForeignLink, ports.IdentityCredentialReal, true, true, true},
	}
	classify := NewClassifier(issuer)
	for _, c := range cases {
		d := classify(c.in)
		if d.Class != c.class || d.CredentialClass != c.cred || d.Project != c.proj || d.ProjectCredential != c.key || d.CredentialActive != c.active {
			t.Errorf("%s: got %+v", c.name, d)
		}
		if d.Class.Ambiguous() != strings.HasPrefix(string(d.Class), "ambiguous") {
			t.Errorf("%s: Ambiguous() disagrees with class %s", c.name, d.Class)
		}
	}
	// Without a configured issuer every link is foreign.
	if d := NewClassifier("")(ports.IdentityLegacyUser{ID: "u", APIKeyHash: digest, KeyEvidence: ports.IdentityKeyIssued, Links: link}); d.Class != ports.IdentityBackfillAmbiguousForeignLink {
		t.Fatalf("no issuer: %+v", d)
	}
}
