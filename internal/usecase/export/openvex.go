package export

import (
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const vexContext = "https://openvex.dev/ns/v0.2.0"

// OpenVEX 0.2 document (the subset Synapse emits).

type VEXDoc struct {
	Context    string         `json:"@context"`
	ID         string         `json:"@id"`
	Author     string         `json:"author"`
	Timestamp  string         `json:"timestamp"`
	Version    int            `json:"version"`
	Tooling    string         `json:"tooling,omitempty"`
	Statements []VEXStatement `json:"statements"`
}

type VEXStatement struct {
	Vulnerability VEXVuln      `json:"vulnerability"`
	Products      []VEXProduct `json:"products"`
	Status        string       `json:"status"`
	Justification string       `json:"justification,omitempty"`
}

type VEXVuln struct {
	Name string `json:"name"`
}

type VEXProduct struct {
	ID string `json:"@id"`
}

func buildOpenVEX(engagementID shared.ID, findings []finding.Finding, notReachable map[string]judgment.ReachabilityTier, vexJust map[string]string, now time.Time, version string) *VEXDoc {
	stmts := make([]VEXStatement, 0)
	for _, f := range findings {
		p := parseDedup(f.DedupKey)
		// VEX asserts exploitability against a PRODUCT, not licenses; skip non-vuln
		// findings and any vuln without a resolvable component (no valid product @id).
		if p.kind != "vuln" || p.component == "" {
			continue
		}
		status, justification := vexStatus(f.Status)
		// Justification precedence for a not_affected finding: (1) a PUBLISHABLE not_reachable
		// reachability judgment gives a tier-grounded justification (deterministic proof);
		// else (2) a human-confirmed OpenVEX justification judgment; else (3) the vexStatus
		// default. Reachability wins because it is a proof, not a human assertion.
		if status == "not_affected" {
			if tier, ok := notReachable[f.ID.String()]; ok {
				justification = reachabilityJustification(tier)
			} else if j, ok := vexJust[f.ID.String()]; ok {
				justification = j
			}
		}
		product := p.component
		if p.version != "" {
			product += "@" + p.version
		}
		stmts = append(stmts, VEXStatement{
			Vulnerability: VEXVuln{Name: p.advisory},
			Products:      []VEXProduct{{ID: product}},
			Status:        status,
			Justification: justification,
		})
	}
	ts := now.Format(time.RFC3339)
	return &VEXDoc{
		Context:    vexContext,
		ID:         infoURI + "/vex/" + engagementID.String() + "#" + ts,
		Author:     "Synapse",
		Timestamp:  ts,
		Version:    1, // first-issue revision (P-later: bump on re-export / supersession)
		Tooling:    "synapse@" + version,
		Statements: stmts,
	}
}

// reachabilityJustification maps a confirmed not_reachable reachability tier to the OpenVEX
// justification: an import/source/call-graph proof (tier-1..2) shows the vulnerable code is present but
// not on the execute path (e.g. a declared package first-party code never imports); a dependency-graph
// determination (tier-0) shows the vulnerable code is not present in what ships at all.
func reachabilityJustification(tier judgment.ReachabilityTier) string {
	switch tier {
	case judgment.Tier1, judgment.Tier1_5, judgment.Tier2:
		// Tier-1 (direct import) .. Tier-2 (call path): the vulnerable code IS present (a declared
		// dependency) but is not on the execute path — e.g. a package first-party code never imports.
		return "vulnerable_code_not_in_execute_path"
	default:
		// Tier-0 (not in the dependency graph at all): the vulnerable code is not present.
		return "vulnerable_code_not_present"
	}
}
