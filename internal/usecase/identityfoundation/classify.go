// Package identityfoundation runs the fenced legacy-user backfill, its shadow parity report and the
// bounded person-audit delivery pass. Enterprise identity stays disabled: nothing here changes how
// a request authenticates, and users remains the writer of record.
package identityfoundation

import (
	"regexp"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var legacyDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// NewClassifier returns the pure legacy-user classifier for the configured fixed OIDC issuer. An
// empty issuer means fixed-tenant OIDC is not configured, so every link is foreign.
//
// Rules, in order:
//   - the bootstrap operator is skipped;
//   - a digest shared with another user or credential is ambiguous and not projected;
//   - a value that is not a SHA-256 hex digest is ambiguous and not projected;
//   - otherwise the person and membership are projected, suspended when the user is disabled;
//   - a link to an issuer other than the configured one is ambiguous (the membership is still
//     projected, but the link is not imported);
//   - the credential follows durable issuance evidence: an issued key (latest create or rotate
//     audit) is a real credential, a key replaced by disable gets none, an OIDC-linked user with no
//     issuance evidence holds the random placeholder written at provisioning and gets none, and an
//     unlinked user with no evidence is ambiguous (no credential) because its key cannot be proven.
func NewClassifier(issuer string) ports.IdentityBackfillClassifier {
	return func(u ports.IdentityLegacyUser) ports.IdentityBackfillDecision {
		if u.ID == ports.IdentityBootstrapUserID {
			return ports.IdentityBackfillDecision{Class: ports.IdentityBackfillBootstrapSkipped, CredentialClass: ports.IdentityCredentialNone}
		}
		if u.DuplicateHash {
			return ports.IdentityBackfillDecision{Class: ports.IdentityBackfillAmbiguousDuplicate, CredentialClass: ports.IdentityCredentialAmbiguous}
		}
		if !legacyDigestPattern.MatchString(u.APIKeyHash) {
			return ports.IdentityBackfillDecision{Class: ports.IdentityBackfillAmbiguousCorrupt, CredentialClass: ports.IdentityCredentialAmbiguous}
		}
		d := ports.IdentityBackfillDecision{Class: ports.IdentityBackfillMigrated, Project: true, ImportLinks: true}
		if u.Disabled {
			d.Class = ports.IdentityBackfillSuspended
		}
		for _, link := range u.Links {
			if issuer == "" || link.Issuer != issuer {
				d.Class = ports.IdentityBackfillAmbiguousForeignLink
			}
		}
		switch {
		case u.KeyEvidence == ports.IdentityKeyIssued:
			d.CredentialClass, d.ProjectCredential, d.CredentialActive = ports.IdentityCredentialReal, true, !u.Disabled
		case u.KeyEvidence == ports.IdentityKeyRevokedByDisable:
			d.CredentialClass = ports.IdentityCredentialDisabled
		case len(u.Links) > 0:
			d.CredentialClass = ports.IdentityCredentialPlaceholder
		default:
			d.CredentialClass = ports.IdentityCredentialAmbiguous
			if d.Class != ports.IdentityBackfillAmbiguousForeignLink {
				d.Class = ports.IdentityBackfillAmbiguousUnprovenKey
			}
		}
		return d
	}
}
