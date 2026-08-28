package privacy

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
)

// ScrubDetection redacts a confirmed detection's EVIDENCE at the source (A6, #627) before it is persisted
// and shipped. A detection embeds the raw events that triggered it (argv, paths, comms), so without this a
// rule firing on a credential-bearing command line would ship the exact secret the telemetry path already
// scrubs — and, once sealed into the permanent evidence chain (A5), unredactably so. It returns a redacted
// DEEP COPY (the caller's Detection, still held by the engine, is never mutated) and a Report.
//
// It applies the same field classifier and argv/path bounds as telemetry Scrub. Detection evidence has no\n// per-field truncation-honesty flags, but its evidence is already bounded by the rule window.
func ScrubDetection(det detection.Detection, policy Policy) (detection.Detection, Report, error) {
	if err := policy.ValidateSourceFloor(); err != nil {
		return detection.Detection{}, Report{}, fmt.Errorf("scrub detection: %w", err)
	}
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

	out := det
	out.Evidence = make([]detection.Event, len(det.Evidence))
	for i, ev := range det.Evidence {
		e := ev // struct copy (shares payload pointers until we replace the touched one)
		switch {
		case ev.Process != nil:
			p := *ev.Process
			if policy.MaxArgCount > 0 && len(p.Args) > policy.MaxArgCount {
				p.Args = p.Args[:policy.MaxArgCount]
			}
			// Slice-aware argv redaction is performed before length bounds, so a bound cannot split a
			// recognized credential. It also retains the telemetry path's cross-element credential flag handling.
			scrubbedArgs, red, drop := policy.RedactArgv(p.Args)
			rep.Redacted += red
			rep.Dropped += drop
			for i := range scrubbedArgs {
				scrubbedArgs[i], _ = boundLen(scrubbedArgs[i], policy.MaxArgLen)
			}
			p.Args = scrubbedArgs
			p.Path, _ = boundLen(apply(CategoryProcessPath, p.Path), policy.MaxPathLen)
			p.Comm = apply(CategoryProcessComm, p.Comm)
			e.Process = &p
		case ev.File != nil:
			f := *ev.File
			f.Path, _ = boundLen(apply(CategoryFilePath, f.Path), policy.MaxPathLen)
			f.Comm = apply(CategoryFileComm, f.Comm)
			e.File = &f
		case ev.Network != nil:
			n := *ev.Network
			n.Comm = apply(CategoryNetworkComm, n.Comm)
			e.Network = &n
		case ev.Privilege != nil:
			pr := *ev.Privilege
			pr.Comm = apply(CategoryPrivilegeComm, pr.Comm)
			e.Privilege = &pr
		}
		out.Evidence[i] = e
	}
	return out, rep, nil
}
