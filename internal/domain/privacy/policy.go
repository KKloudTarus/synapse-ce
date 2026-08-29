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

func (c FieldCategory) Valid() bool {
	switch c {
	case CategoryProcessArg,
		CategoryProcessPath,
		CategoryProcessComm,
		CategoryProcessEnv,
		CategoryFilePath,
		CategoryFileComm,
		CategoryNetworkComm,
		CategoryPrivilegeComm:
		return true
	default:
		return false
	}
}

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
	// Version is the immutable policy-version alias and lineage label. It is not part of the redaction-content digest.
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
		if !cat.Valid() {
			return fmt.Errorf("%w: redaction policy has an unknown field category %q", shared.ErrValidation, cat)
		}
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

// ValidateSourceFloor enforces the non-relaxable source-privacy floor. Tenant
// policy may collect less data than the default, but it cannot enable process
// environments, disable known-secret scrubbing, or loosen argv/path bounds.
func (p Policy) ValidateSourceFloor() error {
	if err := p.Validate(); err != nil {
		return err
	}
	floor := DefaultPolicy()
	if p.dispositionFor(CategoryProcessEnv) != DispositionDrop {
		return fmt.Errorf("%w: redaction policy must drop process environments", shared.ErrValidation)
	}
	if !p.RedactSecrets {
		return fmt.Errorf("%w: redaction policy cannot disable known-secret scrubbing", shared.ErrValidation)
	}
	if p.MaxArgLen <= 0 || p.MaxArgLen > floor.MaxArgLen {
		return fmt.Errorf("%w: redaction policy max argument length must be within 1..%d", shared.ErrValidation, floor.MaxArgLen)
	}
	if p.MaxArgCount <= 0 || p.MaxArgCount > floor.MaxArgCount {
		return fmt.Errorf("%w: redaction policy max argument count must be within 1..%d", shared.ErrValidation, floor.MaxArgCount)
	}
	if p.MaxPathLen <= 0 || p.MaxPathLen > floor.MaxPathLen {
		return fmt.Errorf("%w: redaction policy max path length must be within 1..%d", shared.ErrValidation, floor.MaxPathLen)
	}
	return nil
}

// RedactArgv redacts a whole argv slice as a unit (positions preserved). Each element is classified as a
// process arg (disposition + per-element secret scan), AND — the reason this is slice-aware — when an
// element is a lone credential flag its FOLLOWING element (the space-separated value) is redacted
// wholesale. It also handles command-scoped MySQL/MariaDB -pPASSWORD when argv[0] identifies that client.
// Source scrubbers additionally pass the authoritative Process.Path/Comm so this does not rely on argv[0].
func (p Policy) RedactArgv(args []string) (out []string, redacted, dropped int) {
	return p.redactArgvForCommand(args, "")
}

// redactArgvForCommand is the source-aware form of RedactArgv. command is the original process executable
// path/name from the observation and wins over argv shape for ambiguous short-option interpretation. argv[0]
// remains a fallback for callers that only have argv.
func (p Policy) redactArgvForCommand(args []string, command string) (out []string, redacted, dropped int) {
	out = make([]string, len(args))
	redactValue := false
	mysqlPasswordClient := isMySQLPasswordClient(command)
	if !mysqlPasswordClient && len(args) > 0 {
		mysqlPasswordClient = isMySQLPasswordClient(args[0])
	}
	for i, a := range args {
		v, disp := p.Classify(CategoryProcessArg, a)
		if p.RedactSecrets && mysqlPasswordClient {
			if scrubbed, changed := scrubMySQLGluedPassword(a); changed {
				v, disp = scrubbed, DispositionRedact
			}
		}
		if redactValue && disp == DispositionAllow && v != RedactionPlaceholder {
			// This element is the value of a preceding credential flag; force it redacted even though it
			// carries no secret pattern of its own (it IS the secret). Already-redacted values remain a
			// no-op so replaying an envelope does not falsely report another redaction.
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
	case DispositionRedact:
		return RedactionPlaceholder, DispositionRedact
	case DispositionHash:
		// A known secret must be redacted before hashing so the result cannot be a direct hash of
		// credential material.
		if p.RedactSecrets {
			if scrubbed, changed := scrubSecrets(value); changed {
				return scrubbed, DispositionRedact
			}
		}
		return hashValue(p.HashSalt, value), DispositionHash
	default: // allow
		if p.RedactSecrets {
			if cat == CategoryProcessArg {
				if scrubbed, changed := scrubWholeCredentialArg(value); changed {
					return scrubbed, DispositionRedact
				}
			}
			if scrubbed, changed := scrubSecrets(value); changed {
				return scrubbed, DispositionRedact
			}
		}
		return value, DispositionAllow
	}
}
