package export

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
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
	Supersedes []VEXDocRef    `json:"supersedes,omitempty"`
	Statements []VEXStatement `json:"statements"`
}

// VEXDocRef references a prior document this one supersedes.
type VEXDocRef struct {
	ID string `json:"@id"`
}

type VEXStatement struct {
	Vulnerability VEXVuln      `json:"vulnerability"`
	Products      []VEXProduct `json:"products"`
	Status        string       `json:"status"`
	Justification string       `json:"justification,omitempty"`
	// Timestamp is the per-statement assertion time (when the finding's status was last evaluated). Per the
	// OpenVEX spec a statement without one inherits the document timestamp; emitting it explicitly lets a
	// consumer age each assertion independently.
	Timestamp string `json:"timestamp,omitempty"`
}

type VEXVuln struct {
	Name string `json:"name"`
}

type VEXProduct struct {
	ID string `json:"@id"`
}

// vexRecord is the format-neutral projection of one publishable vuln finding into a VEX assertion, shared
// by the OpenVEX and CSAF emitters so both formats say exactly the same thing about the same finding.
type vexRecord struct {
	advisory      string // CVE/GHSA id
	product       string // component@version
	status        string // OpenVEX status: affected / not_affected / fixed / under_investigation
	justification string // set only for not_affected
	timestamp     time.Time
}

// collectVEXRecords projects the publishable findings into deterministic, deduplicated, sorted VEX records.
// It emits ONE record per (advisory, product): when the same product carries conflicting statuses for the
// same advisory (a data anomaly), the more-exploitable status wins (affected > under_investigation > fixed
// > not_affected), so the export can never assert not_affected while an affected finding for the same
// product exists — a false suppression is impossible. Sorting makes the statement order and the
// content-addressed id reproducible regardless of finding read order.
func collectVEXRecords(findings []finding.Finding, notReachable map[string]judgment.ReachabilityTier, vexJust map[string]string, now time.Time) []vexRecord {
	byKey := map[string]vexRecord{}
	for _, f := range findings {
		p := parseDedup(f.DedupKey)
		// VEX asserts exploitability against a PRODUCT, not licenses; skip non-vuln findings and any vuln
		// without a resolvable component (no valid product id).
		if p.kind != "vuln" || p.component == "" {
			continue
		}
		status, justification := vexStatus(f.Status)
		// Justification precedence for a not_affected finding: (1) a PUBLISHABLE not_reachable reachability
		// judgment gives a tier-grounded justification (a deterministic proof); else (2) a human-confirmed
		// OpenVEX justification; else (3) the vexStatus default. Reachability wins because it is a proof.
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
		ts := now
		if f.EvaluatedAt != nil {
			ts = f.EvaluatedAt.UTC()
		}
		rec := vexRecord{advisory: canonicalAdvisory(p.advisory), product: product, status: status, justification: justification, timestamp: ts}
		key := rec.advisory + "\x00" + rec.product
		if prev, ok := byKey[key]; ok && !vexMoreAuthoritative(rec, prev) {
			continue // a same-or-more-authoritative record already stands for this product
		}
		byKey[key] = rec
	}
	records := make([]vexRecord, 0, len(byKey))
	for _, r := range byKey {
		records = append(records, r)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].advisory != records[j].advisory {
			return records[i].advisory < records[j].advisory
		}
		return records[i].product < records[j].product // (advisory, product) is unique after dedup
	})
	return records
}

// vexMoreAuthoritative decides, deterministically, which of two records for the same (advisory, product)
// wins: the more-exploitable status first (so an affected finding always beats a not_affected one — no
// false suppression), then the lexicographically-smaller justification, then the earlier timestamp. The
// tie-breaks make the winner independent of finding read order, so the content-addressed id is stable.
func vexMoreAuthoritative(a, b vexRecord) bool {
	ra, rb := vexStatusRank(a.status), vexStatusRank(b.status)
	if ra != rb {
		return ra > rb
	}
	if a.justification != b.justification {
		return a.justification < b.justification
	}
	return a.timestamp.Before(b.timestamp)
}

// vexStatusRank orders VEX statuses from most to least exploitable, so a conflict resolves to the status
// that asserts the most risk and can never silently suppress an affected finding.
func vexStatusRank(status string) int {
	switch status {
	case "affected":
		return 3
	case "under_investigation":
		return 2
	case "fixed":
		return 1
	default: // not_affected
		return 0
	}
}

// canonicalAdvisory upper-cases a CVE id to its canonical CVE-YYYY-NNNN form; other identifiers (GHSA, OSV)
// are left as written.
func canonicalAdvisory(advisory string) string {
	if len(advisory) >= 4 && strings.EqualFold(advisory[:4], "CVE-") {
		return strings.ToUpper(advisory)
	}
	return advisory
}

// vexContentID derives a stable, content-addressed document id: the same set of assertions always yields
// the same id (an idempotent re-export), and any change to the assertions yields a new id. This gives the
// document a durable identity without a server-side export-history store.
func vexContentID(engagementID shared.ID, records []vexRecord) string {
	h := sha256.New()
	for _, r := range records {
		h.Write([]byte(r.advisory))
		h.Write([]byte{0})
		h.Write([]byte(r.product))
		h.Write([]byte{0})
		h.Write([]byte(r.status))
		h.Write([]byte{0})
		h.Write([]byte(r.justification))
		h.Write([]byte{0})
	}
	return infoURI + "/vex/" + engagementID.String() + "@" + hex.EncodeToString(h.Sum(nil))[:16]
}

// buildOpenVEX renders the publishable findings as an OpenVEX 0.2 document. supersedes, when non-empty, is
// the @id of a prior document this one replaces.
func buildOpenVEX(engagementID shared.ID, findings []finding.Finding, notReachable map[string]judgment.ReachabilityTier, vexJust map[string]string, now time.Time, version, supersedes string) *VEXDoc {
	records := collectVEXRecords(findings, notReachable, vexJust, now)
	stmts := make([]VEXStatement, 0, len(records))
	for _, r := range records {
		stmts = append(stmts, VEXStatement{
			Vulnerability: VEXVuln{Name: r.advisory},
			Products:      []VEXProduct{{ID: r.product}},
			Status:        r.status,
			Justification: r.justification,
			Timestamp:     r.timestamp.UTC().Format(time.RFC3339),
		})
	}
	var supersededBy []VEXDocRef
	if supersedes != "" {
		supersededBy = []VEXDocRef{{ID: supersedes}}
	}
	return &VEXDoc{
		Context:    vexContext,
		ID:         vexContentID(engagementID, records),
		Author:     "Synapse",
		Timestamp:  now.Format(time.RFC3339),
		Version:    1, // each distinct content-addressed @id is version 1 of its own identity
		Tooling:    "synapse@" + version,
		Supersedes: supersededBy,
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
