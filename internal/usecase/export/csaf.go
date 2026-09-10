package export

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// CSAF 2.0 VEX profile (OASIS Common Security Advisory Framework), the enterprise-standard companion to the
// OpenVEX output. It is templated from the SAME publishable findings and says exactly what the OpenVEX
// document says, in the shape CSAF-VEX consumers (Snyk, Sonatype, distro trackers) expect.

type CSAFDoc struct {
	Document CSAFDocument `json:"document"`
	// product_tree and vulnerabilities are omitted when empty rather than emitted as `[]`, which CSAF
	// rejects (its arrays must be non-empty when present).
	ProductTree     *CSAFProductTree    `json:"product_tree,omitempty"`
	Vulnerabilities []CSAFVulnerability `json:"vulnerabilities,omitempty"`
}

type CSAFDocument struct {
	Category    string        `json:"category"`
	CSAFVersion string        `json:"csaf_version"`
	Publisher   CSAFPublisher `json:"publisher"`
	Title       string        `json:"title"`
	Tracking    CSAFTracking  `json:"tracking"`
}

type CSAFPublisher struct {
	Category  string `json:"category"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type CSAFTracking struct {
	ID                 string         `json:"id"`
	Status             string         `json:"status"`
	Version            string         `json:"version"`
	InitialReleaseDate string         `json:"initial_release_date"`
	CurrentReleaseDate string         `json:"current_release_date"`
	Generator          CSAFGenerator  `json:"generator"`
	RevisionHistory    []CSAFRevision `json:"revision_history"`
}

type CSAFGenerator struct {
	Engine CSAFEngine `json:"engine"`
}

type CSAFEngine struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CSAFRevision struct {
	Number  string `json:"number"`
	Date    string `json:"date"`
	Summary string `json:"summary"`
}

type CSAFProductTree struct {
	FullProductNames []CSAFProductName `json:"full_product_names"`
}

type CSAFProductName struct {
	ProductID string `json:"product_id"`
	Name      string `json:"name"`
}

type CSAFVulnerability struct {
	CVE           string            `json:"cve,omitempty"`
	IDs           []CSAFVulnID      `json:"ids,omitempty"`
	Flags         []CSAFFlag        `json:"flags,omitempty"`
	ProductStatus CSAFProductStatus `json:"product_status"`
}

type CSAFVulnID struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

type CSAFFlag struct {
	Label      string   `json:"label"`
	ProductIDs []string `json:"product_ids"`
}

type CSAFProductStatus struct {
	KnownAffected      []string `json:"known_affected,omitempty"`
	KnownNotAffected   []string `json:"known_not_affected,omitempty"`
	Fixed              []string `json:"fixed,omitempty"`
	UnderInvestigation []string `json:"under_investigation,omitempty"`
}

// buildCSAFVEX renders the publishable findings as a CSAF 2.0 VEX document. It reuses collectVEXRecords so
// the CSAF assertions are identical to the OpenVEX ones, then reshapes them into CSAF's product-tree +
// per-vulnerability product-status model.
func buildCSAFVEX(engagementID shared.ID, findings []finding.Finding, notReachable map[string]judgment.ReachabilityTier, vexJust map[string]string, now time.Time, version string) *CSAFDoc {
	records := collectVEXRecords(findings, notReachable, vexJust, now)

	// Assign a stable CSAF product id per unique product, ordered for determinism.
	products := map[string]bool{}
	for _, r := range records {
		products[r.product] = true
	}
	ordered := make([]string, 0, len(products))
	for p := range products {
		ordered = append(ordered, p)
	}
	sort.Strings(ordered)
	productID := make(map[string]string, len(ordered))
	fullNames := make([]CSAFProductName, 0, len(ordered))
	for i, p := range ordered {
		id := "CSAFPID-" + strconv.Itoa(i+1)
		productID[p] = id
		fullNames = append(fullNames, CSAFProductName{ProductID: id, Name: p})
	}

	// Group records by advisory, bucketing product ids by status and collecting not_affected flags.
	type vulnAgg struct {
		status CSAFProductStatus
		flags  map[string][]string // justification label -> product ids
	}
	byAdvisory := map[string]*vulnAgg{}
	advisoryOrder := make([]string, 0)
	for _, r := range records {
		agg, ok := byAdvisory[r.advisory]
		if !ok {
			agg = &vulnAgg{flags: map[string][]string{}}
			byAdvisory[r.advisory] = agg
			advisoryOrder = append(advisoryOrder, r.advisory)
		}
		pid := productID[r.product]
		switch r.status {
		case "not_affected":
			agg.status.KnownNotAffected = append(agg.status.KnownNotAffected, pid)
			label := r.justification
			if label == "" {
				label = "vulnerable_code_not_present"
			}
			agg.flags[label] = append(agg.flags[label], pid)
		case "fixed":
			agg.status.Fixed = append(agg.status.Fixed, pid)
		case "under_investigation":
			agg.status.UnderInvestigation = append(agg.status.UnderInvestigation, pid)
		default: // affected
			agg.status.KnownAffected = append(agg.status.KnownAffected, pid)
		}
	}
	sort.Strings(advisoryOrder)

	vulns := make([]CSAFVulnerability, 0, len(advisoryOrder))
	for _, advisory := range advisoryOrder {
		agg := byAdvisory[advisory]
		v := CSAFVulnerability{ProductStatus: agg.status}
		if strings.HasPrefix(strings.ToUpper(advisory), "CVE-") {
			v.CVE = advisory
		} else {
			v.IDs = []CSAFVulnID{{SystemName: advisorySystemName(advisory), Text: advisory}}
		}
		labels := make([]string, 0, len(agg.flags))
		for label := range agg.flags {
			labels = append(labels, label)
		}
		sort.Strings(labels)
		for _, label := range labels {
			v.Flags = append(v.Flags, CSAFFlag{Label: label, ProductIDs: agg.flags[label]})
		}
		vulns = append(vulns, v)
	}

	ts := now.Format(time.RFC3339)
	doc := &CSAFDoc{
		Document: CSAFDocument{
			Category:    "csaf_vex",
			CSAFVersion: "2.0",
			Publisher:   CSAFPublisher{Category: "vendor", Name: "Synapse", Namespace: infoURI},
			Title:       "Synapse VEX for engagement " + engagementID.String(),
			Tracking: CSAFTracking{
				ID:                 csafTrackingID(engagementID, records),
				Status:             "final",
				Version:            "1",
				InitialReleaseDate: ts,
				CurrentReleaseDate: ts,
				Generator:          CSAFGenerator{Engine: CSAFEngine{Name: "synapse", Version: version}},
				RevisionHistory:    []CSAFRevision{{Number: "1", Date: ts, Summary: "Initial release"}},
			},
		},
		Vulnerabilities: vulns,
	}
	if len(fullNames) > 0 {
		doc.ProductTree = &CSAFProductTree{FullProductNames: fullNames}
	}
	return doc
}

// advisorySystemName names the identifier system for a non-CVE advisory id.
func advisorySystemName(advisory string) string {
	switch {
	case strings.HasPrefix(strings.ToUpper(advisory), "GHSA-"):
		return "GitHub Security Advisory"
	case strings.HasPrefix(strings.ToUpper(advisory), "OSV-"):
		return "OSV"
	default:
		return "Advisory"
	}
}

// csafTrackingID derives a stable, content-addressed CSAF tracking id, matching the OpenVEX @id property:
// the same assertions always yield the same id.
func csafTrackingID(engagementID shared.ID, records []vexRecord) string {
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
	return "SYNAPSE-VEX-" + safeCSAFID(engagementID.String()) + "-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// safeCSAFID keeps only characters valid in a CSAF tracking id (per the spec's id pattern).
func safeCSAFID(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.', r == '+':
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "engagement"
	}
	return b.String()
}
