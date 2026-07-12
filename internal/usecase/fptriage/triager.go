package fptriage

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Triager adapts a Coordinator to the ports.FPTriager the scan pipeline injects, so the SAME triage runs
// for both the CLI (synchronous) and the durable API scan job. It owns the mapping from a Coordinator
// Critique to the advisory ports.AICritique DTO (dropping best-effort failures, which then gate normally)
// and builds a per-workspace source reader through the injected factory (the fs read stays in
// infrastructure, never here).
type Triager struct {
	coord     *Coordinator
	readerFor func(root string) ports.SourceSnippetReader
	minConf   int
}

var _ ports.FPTriager = (*Triager)(nil)

// NewTriager wraps a Coordinator. readerFor returns the source reader rooted at a scan's workspace dir
// (nil-safe: a nil factory means the coordinator critiques on metadata only).
func NewTriager(coord *Coordinator, readerFor func(root string) ports.SourceSnippetReader) *Triager {
	mc := 0
	if coord != nil {
		mc = coord.MinConfidence()
	}
	return &Triager{coord: coord, readerFor: readerFor, minConf: mc}
}

// Triage critiques each candidate and returns the advisory verdicts. A best-effort failure (Err set) is
// dropped so that finding gates normally. Never mutates a finding.
func (t *Triager) Triage(ctx context.Context, candidates []finding.Finding, workspaceDir string) []ports.AICritique {
	if t == nil || t.coord == nil || len(candidates) == 0 {
		return nil
	}
	var reader ports.SourceSnippetReader
	if t.readerFor != nil {
		reader = t.readerFor(workspaceDir)
	}
	crits := t.coord.Assess(ctx, candidates, reader)
	out := make([]ports.AICritique, 0, len(crits))
	for _, c := range crits {
		if c.Err != nil {
			continue
		}
		fp := c.SuspectedFP(t.minConf)
		out = append(out, ports.AICritique{
			FindingID:   c.FindingID,
			DedupKey:    c.DedupKey,
			Verdict:     string(c.Claim.Verdict),
			Driver:      c.Claim.Driver,
			Confidence:  c.Claim.Confidence,
			SuspectedFP: fp,
			Verified:    fp && c.VerifyAttempted, // a suspected-FP a DISTINCT verifier confirmed
		})
	}
	return out
}
