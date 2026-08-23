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
// It applies the same field classifier as the telemetry Scrub, but only the redact/hash/drop/secret-scan
// transforms — it does NOT length-bound, because detection.Event carries no per-field truncation-honesty
// flag and a silent truncation would be dishonest; the evidence window is already bounded by the rule.
func ScrubDetection(det detection.Detection, policy Policy) (detection.Detection, Report, error) {
	if err := policy.Validate(); err != nil {
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
			// Slice-aware argv redaction (fresh slice — non-mutating): per-element scan + cross-element
			// credential-flag → next-value redaction, same as the telemetry path.
			scrubbedArgs, red, drop := policy.RedactArgv(ev.Process.Args)
			rep.Redacted += red
			rep.Dropped += drop
			p.Args = scrubbedArgs
			p.Path = apply(CategoryProcessPath, p.Path)
			p.Comm = apply(CategoryProcessComm, p.Comm)
			e.Process = &p
		case ev.File != nil:
			f := *ev.File
			f.Path = apply(CategoryFilePath, f.Path)
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
