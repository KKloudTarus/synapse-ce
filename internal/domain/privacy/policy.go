// Package privacy is the SOURCE-SIDE telemetry redaction classifier (A6, #627 — the A0.6 privacy half of
// #611). It is pure domain: given a field category and value it decides allow / redact / hash / drop, and
// Scrub applies a Policy to a telemetry envelope on the agent BEFORE the spool/ship, so unredacted secrets
// never persist or leave the host. Safe-by-default: no environment collected, bounded argv/path, and known
// secret patterns (tokens, keys, passwords, connection strings) redacted even inside otherwise-allowed
// fields. The policy is attributed by a distinct RedactionPolicyDigest recorded with the data — separate
// from the sampling policy digest.
package privacy

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// FieldDisposition is what the policy does with a field's value.
type FieldDisposition string

const (
	// DispositionAllow keeps the value, but (when Policy.RedactSecrets) still scrubs embedded secret
	// patterns — an allowed field is never a bypass for a token pasted into an argument.
	DispositionAllow FieldDisposition = "allow"
	// DispositionRedact replaces the whole value with the redaction placeholder.
	DispositionRedact FieldDisposition = "redact"
	// DispositionHash replaces the value with a keyed digest — correlation without the cleartext.
	DispositionHash FieldDisposition = "hash"
	// DispositionDrop removes the value entirely.
	DispositionDrop FieldDisposition = "drop"
)

// Valid reports whether d is a known disposition.
func (d FieldDisposition) Valid() bool {
	switch d {
	case DispositionAllow, DispositionRedact, DispositionHash, DispositionDrop:
		return true
	default:
		return false
	}
}

// FieldCategory names a logical telemetry field the policy reasons about, so a policy is field-aware
// without coupling to concrete struct layouts.
type FieldCategory string

const (
	CategoryProcessArg  FieldCategory = "process.arg"
	CategoryProcessPath FieldCategory = "process.path"
	CategoryProcessComm FieldCategory = "process.comm"
	// CategoryProcessEnv is reserved: the schema collects no environment today, and the default policy
	// drops it, so if an env field is ever added it is redacted-by-omission by default.
	CategoryProcessEnv    FieldCategory = "process.env"
	CategoryFilePath      FieldCategory = "file.path"
	CategoryFileComm      FieldCategory = "file.comm"
	CategoryNetworkComm   FieldCategory = "network.comm"
	CategoryPrivilegeComm FieldCategory = "privilege.comm"
)

// RedactionPlaceholder replaces a redacted value or secret span. It is a stable, distinctive ASCII marker
// so a reader (and a test) can tell redaction happened without guessing.
const RedactionPlaceholder = "[redacted]"

// Policy is a tenant-configurable source-side redaction policy. The zero value is NOT safe to use; call
// DefaultPolicy (or Normalize on a partially-built one) so caps and secret scanning are set.
type Policy struct {
	// Dispositions maps a category to its disposition; a category absent here uses DispositionAllow.
	Dispositions map[FieldCategory]FieldDisposition
	// RedactSecrets scans allowed/redacted string values for known secret patterns and scrubs the matches.
	RedactSecrets bool
	// MaxArgLen / MaxArgCount bound argv so a pathological command line cannot exfiltrate unbounded data;
	// MaxPathLen bounds a path. <=0 means unbounded for that dimension.
	MaxArgLen   int
	MaxArgCount int
	MaxPathLen  int
	// HashSalt keys the DispositionHash digest. It is NOT a secret store; it only prevents trivial
	// dictionary correlation across policies. Same salt+value → same hash (correlation preserved).
	HashSalt string
	// Version identifies the policy lineage for the RedactionPolicyDigest.
	Version string
}

// DefaultPolicy is the safe default: no environment collected, argv/path bounded, comms/paths/args allowed
// but secret-scanned. It never drops argv wholesale (that would destroy forensic value); instead it redacts
// only the secret spans within.
func DefaultPolicy() Policy {
	return Policy{
		Dispositions: map[FieldCategory]FieldDisposition{
			CategoryProcessEnv: DispositionDrop,
		},
		RedactSecrets: true,
		MaxArgLen:     4096,
		MaxArgCount:   512,
		MaxPathLen:    4096,
		HashSalt:      "synapse-default-redaction",
		Version:       "default:v1",
	}
}

// dispositionFor returns the configured disposition for a category, defaulting to allow.
func (p Policy) dispositionFor(cat FieldCategory) FieldDisposition {
	if d, ok := p.Dispositions[cat]; ok && d.Valid() {
		return d
	}
	return DispositionAllow
}

// Validate checks the policy is well-formed.
func (p Policy) Validate() error {
	if p.Version == "" {
		return fmt.Errorf("%w: redaction policy needs a version", shared.ErrValidation)
	}
	for cat, d := range p.Dispositions {
		if !d.Valid() {
			return fmt.Errorf("%w: redaction policy has an unknown disposition %q for %q", shared.ErrValidation, d, cat)
		}
		if d == DispositionHash && p.HashSalt == "" {
			return fmt.Errorf("%w: redaction policy uses hash for %q but has no salt", shared.ErrValidation, cat)
		}
	}
	if p.MaxArgLen < 0 || p.MaxArgCount < 0 || p.MaxPathLen < 0 {
		return fmt.Errorf("%w: redaction policy caps cannot be negative", shared.ErrValidation)
	}
	return nil
}

// RedactArgv redacts a whole argv slice as a unit (positions preserved). Each element is classified as a
// process arg (disposition + per-element secret scan), AND — the reason this is slice-aware — when an
// element is a lone credential flag its FOLLOWING element (the space-separated value) is redacted
// wholesale, which no per-element scan can do. Returns the scrubbed argv and how many elements were
// redacted/hashed vs dropped.
func (p Policy) RedactArgv(args []string) (out []string, redacted, dropped int) {
	out = make([]string, len(args))
	redactValue := false
	for i, a := range args {
		v, disp := p.Classify(CategoryProcessArg, a)
		if redactValue && disp == DispositionAllow {
			// This element is the value of a preceding credential flag; force it redacted even though it
			// carries no secret pattern of its own (it IS the secret).
			v, disp = RedactionPlaceholder, DispositionRedact
		}
		redactValue = disp != DispositionDrop && IsCredentialFlag(a)
		out[i] = v
		switch disp {
		case DispositionDrop:
			dropped++
		case DispositionRedact, DispositionHash:
			redacted++
		}
	}
	return out, redacted, dropped
}

// Classify applies the category's disposition to a single value and reports the disposition actually
// applied (an allowed value with a scrubbed secret reports DispositionRedact, so the caller can flag it).
func (p Policy) Classify(cat FieldCategory, value string) (string, FieldDisposition) {
	switch p.dispositionFor(cat) {
	case DispositionDrop:
		return "", DispositionDrop
	case DispositionHash:
		return hashValue(p.HashSalt, value), DispositionHash
	case DispositionRedact:
		return RedactionPlaceholder, DispositionRedact
	default: // allow
		if p.RedactSecrets {
			if scrubbed, changed := scrubSecrets(value); changed {
				return scrubbed, DispositionRedact
			}
		}
		return value, DispositionAllow
	}
}
