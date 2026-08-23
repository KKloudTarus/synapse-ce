// Package incident owns the event-sourced runtime Incident aggregate for Phase C of the security data
// plane (#638). It is deliberately pure domain code: correlation decides which detections belong to an
// incident, stores append the immutable events, and this package validates commands and reconstructs the
// authoritative projection without I/O or a clock of its own.
//
// This aggregate is distinct from detection.Incident, which is a read-only rule/asset rollup. A runtime
// Incident has an auditable lifecycle, an independent analyst disposition, optimistic revisions, and
// append-only links to the detections that support it.
package incident
