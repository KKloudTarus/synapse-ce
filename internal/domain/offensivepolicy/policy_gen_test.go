package offensivepolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const policyDocPath = "../../../docs/redteam/offensive-policy.md"

// docEntry is one row of the document's §10 register table, reduced to the fields the table carries.
// The YAML carries the same fields plus the cleanup structure, which the table renders as prose.
type docEntry struct {
	Technique      string
	TaxonomyRef    string
	Disruption     string
	Reversibility  string
	RiskClass      string
	Approval       string
	Radius         string
	Cleanup        string
	ProductionSafe string
}

// TestRegisterMatchesPolicyDocument is the drift test required by issue #418.
//
// The document is the source of truth and policy.yaml mirrors it. Two artifacts that must agree will
// eventually disagree unless something fails the build when they do — a governance policy whose
// machine-readable half has quietly drifted from the reviewed text is worse than having only the text,
// because the code enforces the copy nobody reviewed.
//
// It compares in BOTH directions: an entry in the document but not the register, an entry in the
// register but not the document, and any field differing between them.
func TestRegisterMatchesPolicyDocument(t *testing.T) {
	doc := parseDocRegister(t)
	reg, err := Load()
	if err != nil {
		t.Fatalf("load embedded register: %v", err)
	}

	if len(doc) == 0 {
		t.Fatal("parsed no rows from the document register table; the drift test would pass vacuously")
	}

	docNames := make([]string, 0, len(doc))
	for name := range doc {
		docNames = append(docNames, name)
	}
	sort.Strings(docNames)

	if got := reg.TechniqueIDs(); !reflect.DeepEqual(got, docNames) {
		t.Fatalf("register and document disagree on which techniques exist:\n  register: %v\n  document: %v", got, docNames)
	}

	for _, name := range docNames {
		row := doc[name]
		entry, ok := reg.Lookup(name)
		if !ok {
			t.Errorf("%s is in the document but not the register", name)
			continue
		}
		if entry.TaxonomyRef != row.TaxonomyRef {
			t.Errorf("%s taxonomy: register %q, document %q", name, entry.TaxonomyRef, row.TaxonomyRef)
		}
		if string(entry.Disruption) != row.Disruption {
			t.Errorf("%s disruption: register %q, document %q", name, entry.Disruption, row.Disruption)
		}
		if string(entry.Reversibility) != row.Reversibility {
			t.Errorf("%s reversibility: register %q, document %q", name, entry.Reversibility, row.Reversibility)
		}
		if string(entry.RiskClass) != row.RiskClass {
			t.Errorf("%s risk class: register %q, document %q", name, entry.RiskClass, row.RiskClass)
		}
		if want := docApproval(row.Approval); string(entry.Approval) != want {
			t.Errorf("%s approval: register %q, document %q", name, entry.Approval, want)
		}
		if string(entry.BlastRadius) != row.Radius {
			t.Errorf("%s blast radius: register %q, document %q", name, entry.BlastRadius, row.Radius)
		}
		if got, want := cleanupProse(entry.Cleanup), row.Cleanup; got != want {
			t.Errorf("%s cleanup: register %q, document %q", name, got, want)
		}
		if got, want := yesNo(entry.ProductionSafe), row.ProductionSafe; got != want {
			t.Errorf("%s production safe: register %q, document %q", name, got, want)
		}
	}
}

// TestLegalReviewStatusMatchesDocument keeps the review status from drifting too. The register refuses
// ProductionSafe while the review is unrecorded, so a register that claimed "reviewed" while the
// document said otherwise would unlock production readiness that nobody signed.
func TestLegalReviewStatusMatchesDocument(t *testing.T) {
	raw := readDoc(t)
	reg, err := Load()
	if err != nil {
		t.Fatalf("load embedded register: %v", err)
	}
	docReviewed := !strings.Contains(raw, "| Legal review status | **Not reviewed** |")
	if docReviewed != reg.LegalReview.Reviewed {
		t.Fatalf("legal review status: register reviewed=%v, document reviewed=%v", reg.LegalReview.Reviewed, docReviewed)
	}
}

// TestDocumentNamesEveryProhibitedCategory pins the acceptance criterion that the excluded categories
// are named EXPLICITLY. A governance document that gestures at "destructive actions" without naming
// denial of service, exfiltration and unauthorised persistence leaves the engineer to guess.
func TestDocumentNamesEveryProhibitedCategory(t *testing.T) {
	raw := strings.ToLower(readDoc(t))
	for _, phrase := range []string{
		"denial of service",
		"destructive actions",
		"exfiltration beyond a bounded proof sample",
		"unauthorised persistence",
		"lateral movement into out-of-scope estate",
		"third-party impact",
	} {
		if !strings.Contains(raw, phrase) {
			t.Errorf("the policy document does not name the prohibited category %q", phrase)
		}
	}
}

// TestDocumentStatesTheKillSwitchBoundAndItsLimit checks that the halt bound is stated AND that the
// document is honest about what it does not cover. A bound of "5 seconds" that reads as estate-wide
// would be false: an agent mid-technique learns of the cancellation on its next poll.
func TestDocumentStatesTheKillSwitchBoundAndItsLimit(t *testing.T) {
	raw := readDoc(t)
	if !strings.Contains(raw, "within 5 seconds") {
		t.Error("the document does not state the kill-switch bound")
	}
	if !strings.Contains(raw, "plus one agent poll interval") {
		t.Error("the document states a bound without stating that the estate-wide stop also costs one agent poll interval")
	}
}

func readDoc(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(policyDocPath))
	if err != nil {
		t.Fatalf("read policy document: %v", err)
	}
	return string(raw)
}

// parseDocRegister extracts the §10 table. It keys on the header row rather than a line number so
// editing prose above the table cannot silently break the drift test into passing vacuously.
func parseDocRegister(t *testing.T) map[string]docEntry {
	t.Helper()
	out := map[string]docEntry{}
	inTable := false
	for _, line := range strings.Split(readDoc(t), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "| Technique | Taxonomy | Disruption |") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		if !strings.HasPrefix(trimmed, "|") {
			break // the table ended
		}
		if strings.HasPrefix(trimmed, "|---") {
			continue
		}
		cells := splitRow(trimmed)
		if len(cells) != 9 {
			t.Fatalf("register row has %d cells, want 9: %q", len(cells), trimmed)
		}
		name := strings.Trim(cells[0], "`")
		if name == "" {
			t.Fatalf("register row has no technique: %q", trimmed)
		}
		out[name] = docEntry{
			Technique: name, TaxonomyRef: cells[1], Disruption: cells[2], Reversibility: cells[3],
			RiskClass: cells[4], Approval: cells[5], Radius: strings.Trim(cells[6], "`"),
			Cleanup: cells[7], ProductionSafe: cells[8],
		}
	}
	return out
}

func splitRow(row string) []string {
	parts := strings.Split(strings.Trim(row, "|"), "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(strings.ReplaceAll(p, "`", "")))
	}
	return out
}

// docApproval maps the document's em-dash (no approval mode, used for prohibited techniques) to the
// register's empty ApprovalMode.
func docApproval(cell string) string {
	if cell == "—" || cell == "-" {
		return string(ApprovalNone)
	}
	return cell
}

// cleanupProse renders a CleanupSpec the way the document's table writes it, so the two are comparable
// without the document having to carry YAML.
func cleanupProse(c CleanupSpec) string {
	if c.IsZero() {
		return "—"
	}
	return fmt.Sprintf("%s; %s", strings.Join(c.Steps, "; "), c.Verification)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
