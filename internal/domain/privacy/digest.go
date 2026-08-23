package privacy

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
)

// redactionPolicyContext domain-separates the redaction-policy digest so it can never be confused with the
// sampling-policy digest (#611/#594) or any other digest — they identify DIFFERENT concerns.
const redactionPolicyContext = "synapse-redaction-policy:v1"

// secretPatternSetID versions the built-in secret-pattern set, so a policy digest changes when the patterns
// that scrubbed the data change — the digest attributes the FULL redaction behavior, not just the config.
const secretPatternSetID = "secret-patterns:v1"

// RedactionPolicyDigest is a deterministic, domain-separated identity for a redaction policy, recorded with
// the scrubbed data so a reader knows exactly how it was redacted. It is DISTINCT from the sampling policy
// digest. The HashSalt is folded in as its own digest (not raw) so the identity is stable without echoing
// the salt into the commitment.
func RedactionPolicyDigest(p Policy) string {
	h := sha256.New()
	write := func(s string) { h.Write([]byte(s)); h.Write([]byte{0x1e}) }
	write(redactionPolicyContext)
	write(p.Version)
	write(secretPatternSetID)
	write(strconv.FormatBool(p.RedactSecrets))
	write(strconv.Itoa(p.MaxArgLen))
	write(strconv.Itoa(p.MaxArgCount))
	write(strconv.Itoa(p.MaxPathLen))
	cats := make([]string, 0, len(p.Dispositions))
	for cat := range p.Dispositions {
		cats = append(cats, string(cat))
	}
	sort.Strings(cats)
	for _, cat := range cats {
		write(cat + "=" + string(p.Dispositions[FieldCategory(cat)]))
	}
	saltDigest := sha256.Sum256([]byte(p.HashSalt))
	write("salt:" + hex.EncodeToString(saltDigest[:8]))
	return hex.EncodeToString(h.Sum(nil))
}
