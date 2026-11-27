package siem

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/audit"
)

// TestVerifyAuditContentHonoursEachRowsScheme pins that the SIEM export recomputes a row under the
// scheme it was stored with. A reader that dropped the scheme would verify a framed row as legacy and
// block the sink on a healthy chain.
func TestVerifyAuditContentHonoursEachRowsScheme(t *testing.T) {
	at := time.UnixMicro(1_700_000_000_000_000).UTC()
	meta := map[string]string{"severity": "high"}
	first := audit.ComputeHash(audit.HashSchemeLegacy, "", "ada", "finding.created", "asset-1", meta, at)
	second := audit.ComputeHash(audit.HashSchemeFramed, first, "ada", "finding.updated", "asset-1", meta, at)
	row := func(id int64, action, hash, prev string, scheme int) AuditFact {
		return AuditFact{ID: id, Actor: "ada", Action: action, Target: "asset-1", AtUnixMicro: at.UnixMicro(), Hash: hash, PreviousHash: prev, HashVersion: 2, HashScheme: scheme, Severity: "high"}
	}
	cases := []struct {
		name     string
		rows     []AuditFact
		accepted int
		broken   bool
	}{
		{name: "legacy then framed", rows: []AuditFact{row(1, "finding.created", first, "", 0), row(2, "finding.updated", second, first, audit.HashSchemeFramed)}, accepted: 2},
		{name: "framed row read as legacy", rows: []AuditFact{row(1, "finding.created", first, "", 0), row(2, "finding.updated", second, first, audit.HashSchemeLegacy)}, accepted: 1, broken: true},
		{name: "empty hash with an unknown scheme", rows: []AuditFact{row(1, "finding.created", first, "", 0), row(2, "finding.updated", "", first, 9)}, accepted: 1, broken: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			metas := make([]map[string]string, len(tc.rows))
			for i := range metas {
				metas[i] = meta
			}
			accepted, problem := VerifyAuditContent(Position{Source: SourceAudit}, tc.rows, metas, AuditAnchor{})
			if len(accepted) != tc.accepted || problem.None() == tc.broken {
				t.Fatalf("accepted %d, problem %+v; want %d accepted, broken=%v", len(accepted), problem, tc.accepted, tc.broken)
			}
		})
	}
}
