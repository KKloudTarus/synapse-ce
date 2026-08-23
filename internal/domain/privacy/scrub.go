package privacy

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

// Report summarizes what a Scrub did, for honesty signals and tests. PolicyDigest is the
// RedactionPolicyDigest of the applied policy (also stamped onto the returned envelope).
type Report struct {
	PolicyDigest string
	Redacted     int // values redacted, hashed, or secret-scrubbed
	Dropped      int // values dropped entirely
}

// Changed reports whether the scrub altered any value.
func (r Report) Changed() bool { return r.Redacted > 0 || r.Dropped > 0 }

// Scrub applies the policy to a telemetry envelope on the SOURCE side, returning a scrubbed copy (the input
// is never mutated — it operates on env.Clone()), a Report, and any error. It stamps the envelope's
// RedactionPolicyDigest and sets QualityRedacted when anything changed, so the redaction travels with the
// data. Callers apply it BEFORE the spool/ship so unredacted secrets never persist or leave the host.
func Scrub(env telemetry.TelemetryEnvelope, policy Policy) (telemetry.TelemetryEnvelope, Report, error) {
	if err := policy.Validate(); err != nil {
		return telemetry.TelemetryEnvelope{}, Report{}, fmt.Errorf("scrub: %w", err)
	}
	out := env.Clone()
	rep := Report{PolicyDigest: RedactionPolicyDigest(policy)}

	apply := func(cat FieldCategory, value string) string {
		if value == "" {
			return value
		}
		scrubbed, disp := policy.Classify(cat, value)
		switch disp {
		case DispositionDrop:
			rep.Dropped++
		case DispositionRedact, DispositionHash:
			rep.Redacted++
		}
		return scrubbed
	}

	// markArgvTruncated / markPathTruncated set BOTH honesty channels for a Scrub-introduced cut: the
	// per-field struct flag AND the envelope DataQuality bit, so a reader keying on either sees the same
	// truth (the normalizer already set these for sensor-time cuts; Scrub's own tighter caps must too).
	markArgvTruncated := func() {
		out.DataQuality = out.DataQuality.With(telemetry.QualityTruncatedArgv)
	}
	markPathTruncated := func() {
		out.DataQuality = out.DataQuality.With(telemetry.QualityTruncatedPath)
	}

	if p := out.Event.Process; p != nil {
		if v, cut := boundLen(apply(CategoryProcessPath, p.Path), policy.MaxPathLen); true {
			p.Path = v
			if cut {
				p.PathTruncated = true
				markPathTruncated()
			}
		}
		p.Comm = apply(CategoryProcessComm, p.Comm)
		if policy.MaxArgCount > 0 && len(p.Args) > policy.MaxArgCount {
			p.Args = p.Args[:policy.MaxArgCount]
			p.ArgsTruncated = true
			markArgvTruncated()
		}
		// Slice-aware argv redaction: per-element secret scan PLUS cross-element (a lone credential flag
		// redacts the following value element — the space-separated `--password secret` form).
		scrubbedArgs, red, drop := policy.RedactArgv(p.Args)
		rep.Redacted += red
		rep.Dropped += drop
		for i := range scrubbedArgs {
			v, cut := boundLen(scrubbedArgs[i], policy.MaxArgLen)
			scrubbedArgs[i] = v
			if cut {
				p.ArgsTruncated = true
				markArgvTruncated()
			}
		}
		p.Args = scrubbedArgs
	}
	if f := out.Event.File; f != nil {
		if v, cut := boundLen(apply(CategoryFilePath, f.Path), policy.MaxPathLen); true {
			f.Path = v
			if cut {
				f.PathTruncated = true
				markPathTruncated()
			}
		}
		f.Comm = apply(CategoryFileComm, f.Comm)
	}
	if n := out.Event.Network; n != nil {
		n.Comm = apply(CategoryNetworkComm, n.Comm)
	}
	if pr := out.Event.Privilege; pr != nil {
		pr.Comm = apply(CategoryPrivilegeComm, pr.Comm)
	}

	out.RedactionPolicyDigest = rep.PolicyDigest
	if rep.Changed() {
		out.DataQuality = out.DataQuality.With(telemetry.QualityRedacted)
	}
	return out, rep, nil
}

// boundLen truncates s to max runes (max<=0 means unbounded), returning the result and whether it was cut.
// Truncation is rune-safe so a multibyte value is never split mid-rune. The caller records both honesty
// channels (the per-field struct flag AND the envelope DataQuality bit) when cut is true.
func boundLen(s string, max int) (string, bool) {
	if max <= 0 {
		return s, false
	}
	r := []rune(s)
	if len(r) <= max {
		return s, false
	}
	return string(r[:max]), true
}
