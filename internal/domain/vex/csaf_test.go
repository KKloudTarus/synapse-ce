package vex

import "testing"

// A CSAF 2.0 VEX document exercising: a PURL-helper product, a branch-nested product, a not_affected
// justification via a per-product flag, a not_affected justification via a group-scoped flag, a fixed
// status, and an affected status.
const sampleCSAF = `{
  "document": {"category": "csaf_vex", "csaf_version": "2.0"},
  "product_tree": {
    "full_product_names": [
      {"product_id": "PID-1", "name": "lodash 4.17.21", "product_identification_helper": {"purl": "pkg:npm/lodash@4.17.21"}},
      {"product_id": "PID-4", "name": "left-pad 1.0.0", "product_identification_helper": {"purl": "pkg:npm/left-pad@1.0.0"}}
    ],
    "product_groups": [
      {"group_id": "GRP-A", "product_ids": ["PID-4"]}
    ],
    "branches": [
      {"category": "vendor", "name": "acme", "branches": [
        {"category": "product_name", "name": "express", "branches": [
          {"category": "product_version", "name": "4.0.0", "product": {"product_id": "PID-2", "name": "express 4.0.0", "product_identification_helper": {"purl": "pkg:npm/express@4.0.0"}}}
        ]}
      ]}
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2024-1",
      "product_status": {"known_not_affected": ["PID-1", "PID-4"], "fixed": ["PID-2"]},
      "flags": [
        {"label": "vulnerable_code_not_in_execute_path", "product_ids": ["PID-1"]},
        {"label": "component_not_present", "group_ids": ["GRP-A"]}
      ]
    },
    {
      "cve": "CVE-2024-2",
      "product_status": {"known_affected": ["PID-2"], "under_investigation": ["PID-1"]}
    }
  ]
}`

func TestParseCSAF(t *testing.T) {
	doc, err := ParseCSAF([]byte(sampleCSAF))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	// PID-1 not_affected, PID-4 not_affected, PID-2 fixed, PID-2 affected, PID-1 under_investigation = 5.
	if len(doc.Statements) != 5 {
		t.Fatalf("want 5 statements, got %d: %+v", len(doc.Statements), doc.Statements)
	}

	find := func(adv, comp, ver, wantStatus, wantJust string) {
		t.Helper()
		for _, st := range doc.Statements {
			if st.Status != wantStatus {
				continue
			}
			if st.MatchesFinding(adv, comp, ver) {
				if st.Justification != wantJust {
					t.Errorf("%s %s@%s: justification=%q want %q", adv, comp, ver, st.Justification, wantJust)
				}
				return
			}
		}
		t.Errorf("no %s statement matched %s %s@%s", wantStatus, adv, comp, ver)
	}

	find("CVE-2024-1", "lodash", "4.17.21", "not_affected", "vulnerable_code_not_in_execute_path")
	// PID-4 gets its justification through a group-scoped flag (GRP-A → PID-4).
	find("CVE-2024-1", "left-pad", "1.0.0", "not_affected", "component_not_present")
	// Branch-nested product resolves, fixed carries no justification.
	find("CVE-2024-1", "express", "4.0.0", "fixed", "")
	find("CVE-2024-2", "express", "4.0.0", "affected", "")
	find("CVE-2024-2", "lodash", "4.17.21", "under_investigation", "")
}

func TestParseCSAFRelationship(t *testing.T) {
	// A default_component_of relationship: the composite id PID-REL resolves to its component PID-C's PURL.
	// Both endpoints (component PID-C, container PID-APP) are defined, as CSAF requires.
	const doc = `{
      "document": {"category": "csaf_vex", "csaf_version": "2.0"},
      "product_tree": {
        "full_product_names": [
          {"product_id": "PID-C", "name": "log4j", "product_identification_helper": {"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}},
          {"product_id": "PID-APP", "name": "the application"}
        ],
        "relationships": [
          {"category": "default_component_of", "product_reference": "PID-C", "relates_to_product_reference": "PID-APP",
           "full_product_name": {"product_id": "PID-REL", "name": "log4j as component of app"}}
        ]
      },
      "vulnerabilities": [
        {"cve": "CVE-2021-44228", "product_status": {"known_not_affected": ["PID-REL"]},
         "flags": [{"label": "inline_mitigations_already_exist", "product_ids": ["PID-REL"]}]}
      ]
    }`
	parsed, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	if len(parsed.Statements) != 1 {
		t.Fatalf("want 1 statement, got %d", len(parsed.Statements))
	}
	st := parsed.Statements[0]
	if !st.MatchesFinding("CVE-2021-44228", "log4j-core", "2.14.1") {
		t.Errorf("relationship product did not resolve to component PURL: %+v", st)
	}
	if !st.Suppresses() || st.Justification != "inline_mitigations_already_exist" {
		t.Errorf("statement not suppressing with justification: %+v", st)
	}
}

// An out-of-order / chained component-of relationship must resolve by fixed point, not array order.
func TestParseCSAFRelationshipFixedPoint(t *testing.T) {
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {
        "full_product_names": [
          {"product_id": "PID-C", "product_identification_helper": {"purl": "pkg:npm/foo@1.0.0"}},
          {"product_id": "PID-APP", "name": "app"}
        ],
        "relationships": [
          {"category": "default_component_of", "product_reference": "PID-MID", "relates_to_product_reference": "PID-APP",
           "full_product_name": {"product_id": "PID-TOP"}},
          {"category": "default_component_of", "product_reference": "PID-C", "relates_to_product_reference": "PID-APP",
           "full_product_name": {"product_id": "PID-MID"}}
        ]
      },
      "vulnerabilities": [
        {"cve": "CVE-1", "product_status": {"known_not_affected": ["PID-TOP"]}}
      ]
    }`
	parsed, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	if len(parsed.Statements) != 1 || !parsed.Statements[0].MatchesFinding("CVE-1", "foo", "1.0.0") {
		t.Errorf("chained relationship did not resolve regardless of order: %+v", parsed.Statements)
	}
}

// A malformed component-of relationship (container not defined) must NOT resolve, so it cannot suppress.
func TestParseCSAFMalformedRelationshipNotSuppressed(t *testing.T) {
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {
        "full_product_names": [
          {"product_id": "PID-C", "product_identification_helper": {"purl": "pkg:npm/foo@1.0.0"}}
        ],
        "relationships": [
          {"category": "default_component_of", "product_reference": "PID-C", "relates_to_product_reference": "PID-GHOST",
           "full_product_name": {"product_id": "PID-REL"}}
        ]
      },
      "vulnerabilities": [
        {"cve": "CVE-1", "product_status": {"known_not_affected": ["PID-REL"]}}
      ]
    }`
	parsed, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("a defined relationship id with an undefined container must not error: %v", err)
	}
	for _, st := range parsed.Statements {
		if st.Suppresses() && st.MatchesFinding("CVE-1", "foo", "1.0.0") {
			t.Errorf("malformed relationship wrongly suppressed the component: %+v", st)
		}
	}
}

// An environment relationship (installed_on) must NOT suppress: its product is defined (no dangling error)
// but unmatchable, so no statement is emitted for it.
func TestParseCSAFEnvironmentRelationshipNotSuppressed(t *testing.T) {
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {
        "full_product_names": [
          {"product_id": "PID-AGENT", "product_identification_helper": {"purl": "pkg:generic/agent@1.0.0"}},
          {"product_id": "PID-OS", "name": "Windows"}
        ],
        "relationships": [
          {"category": "installed_on", "product_reference": "PID-AGENT", "relates_to_product_reference": "PID-OS",
           "full_product_name": {"product_id": "PID-AGENT-ON-OS", "name": "agent on windows"}}
        ]
      },
      "vulnerabilities": [
        {"cve": "CVE-9", "product_status": {"known_not_affected": ["PID-AGENT-ON-OS"]}}
      ]
    }`
	parsed, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("ParseCSAF must not error on a defined environment product: %v", err)
	}
	for _, st := range parsed.Statements {
		if st.Suppresses() && st.MatchesFinding("CVE-9", "agent", "1.0.0") {
			t.Errorf("environment-scoped not_affected wrongly suppressed the bare component: %+v", st)
		}
	}
}

func TestParseCSAFRejectsContradiction(t *testing.T) {
	// PID-1 is both known_not_affected and known_affected → contradictory, must be rejected whole.
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {"full_product_names": [{"product_id": "PID-1", "product_identification_helper": {"purl": "pkg:npm/foo@1.0.0"}}]},
      "vulnerabilities": [{"cve": "CVE-1", "product_status": {"known_not_affected": ["PID-1"], "known_affected": ["PID-1"]}}]
    }`
	if _, err := ParseCSAF([]byte(doc)); err == nil {
		t.Error("a product with contradictory status must be rejected (no partial suppression)")
	}
}

// known_not_affected vs first_affected (a non-known_affected variant) must also be caught as contradictory.
func TestParseCSAFRejectsBoundaryContradiction(t *testing.T) {
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {"full_product_names": [{"product_id": "PID-1", "product_identification_helper": {"purl": "pkg:npm/foo@1.0.0"}}]},
      "vulnerabilities": [{"cve": "CVE-1", "product_status": {"known_not_affected": ["PID-1"], "first_affected": ["PID-1"]}}]
    }`
	if _, err := ParseCSAF([]byte(doc)); err == nil {
		t.Error("known_not_affected vs first_affected on one product must be rejected")
	}
}

// The same CVE split across two vulnerabilities[] entries must not slip a contradiction past a per-entry check.
func TestParseCSAFRejectsCrossEntryContradiction(t *testing.T) {
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {"full_product_names": [{"product_id": "PID-1", "product_identification_helper": {"purl": "pkg:npm/foo@1.0.0"}}]},
      "vulnerabilities": [
        {"cve": "CVE-1", "product_status": {"known_not_affected": ["PID-1"]}},
        {"cve": "CVE-1", "product_status": {"known_affected": ["PID-1"]}}
      ]
    }`
	if _, err := ParseCSAF([]byte(doc)); err == nil {
		t.Error("the same CVE with contradictory status across two entries must be rejected")
	}
}

func TestParseCSAFRejectsDuplicateProductID(t *testing.T) {
	// PID-1 defined twice with different PURLs → a suppression could point at the wrong component.
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {"full_product_names": [
        {"product_id": "PID-1", "product_identification_helper": {"purl": "pkg:npm/foo@1.0.0"}},
        {"product_id": "PID-1", "product_identification_helper": {"purl": "pkg:npm/bar@2.0.0"}}
      ]},
      "vulnerabilities": [{"cve": "CVE-1", "product_status": {"known_not_affected": ["PID-1"]}}]
    }`
	if _, err := ParseCSAF([]byte(doc)); err == nil {
		t.Error("a duplicate product_id definition must be rejected")
	}
}

func TestParseCSAFRejectsDanglingProduct(t *testing.T) {
	// GHOST is referenced by product_status but defined nowhere in the product_tree.
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {"full_product_names": [{"product_id": "PID-1", "product_identification_helper": {"purl": "pkg:npm/foo@1.0.0"}}]},
      "vulnerabilities": [{"cve": "CVE-1", "product_status": {"known_affected": ["GHOST"]}}]
    }`
	if _, err := ParseCSAF([]byte(doc)); err == nil {
		t.Error("a product_status reference to an undefined product must be rejected")
	}
}

func TestParseCSAFRejectsJunk(t *testing.T) {
	if _, err := ParseCSAF([]byte(`not json`)); err == nil {
		t.Error("invalid JSON must error")
	}
	if _, err := ParseCSAF([]byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`)); err == nil {
		t.Error("an OpenVEX document (no document.csaf_version) must error as non-CSAF")
	}
	if _, err := ParseCSAF([]byte(`{"document":{"csaf_version":"1.0"},"vulnerabilities":[]}`)); err == nil {
		t.Error("a non-2.x csaf_version must error")
	}
	if _, err := ParseCSAF([]byte(`{"document":{"csaf_version":"2.0"},"vulnerabilities":[]}`)); err == nil {
		t.Error("a CSAF doc with no product statements must error")
	}
}

func TestCSAFUnscopedFlagIgnored(t *testing.T) {
	// A flag with neither product_ids nor group_ids is not a CSAF "default" — it must not assign a
	// justification to every not_affected product.
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {"full_product_names": [{"product_id": "PID-1", "product_identification_helper": {"purl": "pkg:npm/foo@1.0.0"}}]},
      "vulnerabilities": [{"cve": "CVE-1", "product_status": {"known_not_affected": ["PID-1"]},
        "flags": [{"label": "component_not_present"}]}]
    }`
	parsed, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	if len(parsed.Statements) != 1 {
		t.Fatalf("want 1 statement, got %d", len(parsed.Statements))
	}
	if parsed.Statements[0].Justification != "" {
		t.Errorf("an unscoped flag must not assign a justification, got %q", parsed.Statements[0].Justification)
	}
}

// Two DIFFERENT product ids resolving to the SAME component with conflicting status must be rejected:
// validation is at the resolved match-target level, not the raw product id, or suppress-on-any would hide
// the finding.
func TestParseCSAFRejectsSameComponentDifferentIDs(t *testing.T) {
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {"full_product_names": [
        {"product_id": "PID-A", "product_identification_helper": {"purl": "pkg:npm/foo@1.0.0"}},
        {"product_id": "PID-B", "product_identification_helper": {"purl": "pkg:npm/foo@1.0.0"}}
      ]},
      "vulnerabilities": [{"cve": "CVE-1", "product_status": {"known_not_affected": ["PID-A"], "known_affected": ["PID-B"]}}]
    }`
	if _, err := ParseCSAF([]byte(doc)); err == nil {
		t.Error("two ids resolving to one component with conflicting status must be rejected")
	}
}

// A not_affected wildcard (no version) that overlaps an affected concrete version for the same component
// name must be rejected (the wildcard would suppress the affected version's finding).
func TestParseCSAFRejectsVersionWildcardOverlap(t *testing.T) {
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {"full_product_names": [
        {"product_id": "PID-A", "product_identification_helper": {"purl": "pkg:npm/foo"}},
        {"product_id": "PID-B", "product_identification_helper": {"purl": "pkg:npm/foo@1.0.0"}}
      ]},
      "vulnerabilities": [{"cve": "CVE-1", "product_status": {"known_not_affected": ["PID-A"], "known_affected": ["PID-B"]}}]
    }`
	if _, err := ParseCSAF([]byte(doc)); err == nil {
		t.Error("a suppressing wildcard overlapping an affected concrete version must be rejected")
	}
}

// A self-referential component-of relationship (relates_to equals the relationship's own id) must not
// resolve, so it cannot suppress.
func TestParseCSAFRejectsSelfCyclicRelationship(t *testing.T) {
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {
        "full_product_names": [{"product_id": "PID-C", "product_identification_helper": {"purl": "pkg:npm/foo@1.0.0"}}],
        "relationships": [
          {"category": "default_component_of", "product_reference": "PID-C", "relates_to_product_reference": "PID-REL",
           "full_product_name": {"product_id": "PID-REL"}}
        ]
      },
      "vulnerabilities": [{"cve": "CVE-1", "product_status": {"known_not_affected": ["PID-REL"]}}]
    }`
	parsed, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("a defined but unresolvable self-cyclic relationship must not error: %v", err)
	}
	for _, st := range parsed.Statements {
		if st.Suppresses() && st.MatchesFinding("CVE-1", "foo", "1.0.0") {
			t.Errorf("self-cyclic relationship wrongly suppressed: %+v", st)
		}
	}
}

// A free-text-name-only product (no PURL) must NOT emit a suppressing statement — only PURL-identified
// products can hide a finding — but may still emit a non-suppressing (affected) one.
func TestParseCSAFNameOnlyDoesNotSuppress(t *testing.T) {
	const suppressDoc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {"full_product_names": [{"product_id": "PID-1", "name": "lodash"}]},
      "vulnerabilities": [{"cve": "CVE-1", "product_status": {"known_not_affected": ["PID-1"]}}]
    }`
	parsed, err := ParseCSAF([]byte(suppressDoc))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	for _, st := range parsed.Statements {
		if st.Suppresses() {
			t.Errorf("a name-only product must not emit a suppressing statement: %+v", st)
		}
	}
	// The same product under an affected status still emits (non-suppressing, harmless).
	const affectedDoc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {"full_product_names": [{"product_id": "PID-1", "name": "lodash"}]},
      "vulnerabilities": [{"cve": "CVE-1", "product_status": {"known_affected": ["PID-1"]}}]
    }`
	parsed2, err := ParseCSAF([]byte(affectedDoc))
	if err != nil {
		t.Fatalf("ParseCSAF affected: %v", err)
	}
	if len(parsed2.Statements) != 1 || parsed2.Statements[0].Status != "affected" {
		t.Errorf("name-only affected should still emit one non-suppressing statement, got %+v", parsed2.Statements)
	}
}

// A malformed helper.purl (a free-text value, not a real pkg: URL) must NOT be trusted as a machine
// identity, so it cannot carry a suppressing statement.
func TestParseCSAFInvalidPURLDoesNotSuppress(t *testing.T) {
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {"full_product_names": [{"product_id": "PID-1", "product_identification_helper": {"purl": "lodash"}}]},
      "vulnerabilities": [{"cve": "CVE-1", "product_status": {"known_not_affected": ["PID-1"]}}]
    }`
	parsed, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	for _, st := range parsed.Statements {
		if st.Suppresses() {
			t.Errorf("a malformed purl must not carry a suppressing statement: %+v", st)
		}
	}
}

// A valid PURL that happens to carry no version still suppresses (wildcard) — the guard is about shape, not
// presence of a version.
func TestParseCSAFValidPURLNoVersionSuppresses(t *testing.T) {
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {"full_product_names": [{"product_id": "PID-1", "product_identification_helper": {"purl": "pkg:npm/lodash"}}]},
      "vulnerabilities": [{"cve": "CVE-1", "product_status": {"known_not_affected": ["PID-1"]}}]
    }`
	parsed, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	if len(parsed.Statements) != 1 || !parsed.Statements[0].Suppresses() {
		t.Errorf("a valid version-less purl should still suppress, got %+v", parsed.Statements)
	}
	if !parsed.Statements[0].MatchesFinding("CVE-1", "lodash", "9.9.9") {
		t.Errorf("version-less purl should match any version: %+v", parsed.Statements[0])
	}
}

// Two mutually-nested component-of relationships (a container cycle) must not resolve into a suppression.
func TestParseCSAFContainerCycleNotSuppressed(t *testing.T) {
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {
        "full_product_names": [{"product_id": "PID-C", "product_identification_helper": {"purl": "pkg:npm/foo@1.0.0"}}],
        "relationships": [
          {"category": "default_component_of", "product_reference": "PID-C", "relates_to_product_reference": "PID-B",
           "full_product_name": {"product_id": "PID-A"}},
          {"category": "default_component_of", "product_reference": "PID-C", "relates_to_product_reference": "PID-A",
           "full_product_name": {"product_id": "PID-B"}}
        ]
      },
      "vulnerabilities": [{"cve": "CVE-1", "product_status": {"known_not_affected": ["PID-A", "PID-B"]}}]
    }`
	parsed, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("a defined but container-cyclic relationship must not error: %v", err)
	}
	for _, st := range parsed.Statements {
		if st.Suppresses() && st.MatchesFinding("CVE-1", "foo", "1.0.0") {
			t.Errorf("container-cyclic relationship wrongly suppressed: %+v", st)
		}
	}
}

// The exact malformed-PURL bypasses from review: an empty path segment and a whitespace type must NOT be
// trusted as machine identity, so they cannot suppress.
func TestParseCSAFMalformedPURLShapesDoNotSuppress(t *testing.T) {
	for _, purl := range []string{"pkg:npm//lodash", "pkg: /lodash", "pkg:npm/", "pkg:/lodash", "pkg:npm/lodash/"} {
		doc := `{
          "document": {"csaf_version": "2.0"},
          "product_tree": {"full_product_names": [{"product_id": "PID-1", "product_identification_helper": {"purl": "` + purl + `"}}]},
          "vulnerabilities": [{"cve": "CVE-1", "product_status": {"known_not_affected": ["PID-1"]}}]
        }`
		parsed, err := ParseCSAF([]byte(doc))
		if err != nil {
			t.Fatalf("ParseCSAF(%q): %v", purl, err)
		}
		for _, st := range parsed.Statements {
			if st.Suppresses() {
				t.Errorf("malformed purl %q must not carry a suppressing statement: %+v", purl, st)
			}
		}
	}
}

func TestValidPURL(t *testing.T) {
	valid := []string{"pkg:npm/lodash@4.17.21", "pkg:npm/lodash", "pkg:npm/%40scope/name@1.0.0", "pkg:maven/org.apache/log4j-core@2.1", "pkg:golang/github.com/foo/bar@v1", "pkg:pypi/django"}
	for _, v := range valid {
		if !validPURL(v) {
			t.Errorf("validPURL(%q) = false, want true", v)
		}
	}
	invalid := []string{"lodash", "", "pkg:", "pkg:npm", "pkg:npm/", "pkg:npm//lodash", "pkg: /lodash", "pkg:/lodash", "pkg:npm/lodash/", "pkg:1npm/lodash", "pkg:np m/lodash",
		"pkg:npm/na@me/leaf", "pkg:npm/lodash@", "pkg:npm/%40s/lodash@1.0.0@evil", "pkg:npm/lodash@1.0/x",
		"pkg:npm/notascope/lodash@4.17.21", "pkg:npm/%40/lodash", "pkg:npm/a/b/c"}
	for _, v := range invalid {
		if validPURL(v) {
			t.Errorf("validPURL(%q) = true, want false", v)
		}
	}

	// canonicalPURL normalizes to the bare coordinate the matcher parses.
	norm := map[string]string{
		"pkg:npm/lodash@4.17.21?repository_url=x#sub": "pkg:npm/lodash@4.17.21",
		"pkg:npm/real?x=/%40safe/lodash":              "pkg:npm/real",
		"pkg:npm/%40safe/lodash@4.17.21":              "pkg:npm/%40safe/lodash@4.17.21",
		"pkg:npm/lodash":                              "pkg:npm/lodash",
	}
	for in, want := range norm {
		if got := canonicalPURL(in); got != want {
			t.Errorf("canonicalPURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// A container cycle that runs THROUGH a non-component_of (installed_on) relationship must still be detected,
// so the component_of relationship on the cycle does not resolve into a suppression.
func TestParseCSAFCrossCategoryContainerCycleNotSuppressed(t *testing.T) {
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {
        "full_product_names": [
          {"product_id": "PID-C", "product_identification_helper": {"purl": "pkg:npm/foo@1.0.0"}},
          {"product_id": "PID-HOST", "name": "host"}
        ],
        "relationships": [
          {"category": "default_component_of", "product_reference": "PID-C", "relates_to_product_reference": "PID-B",
           "full_product_name": {"product_id": "PID-A"}},
          {"category": "installed_on", "product_reference": "PID-HOST", "relates_to_product_reference": "PID-A",
           "full_product_name": {"product_id": "PID-B"}}
        ]
      },
      "vulnerabilities": [{"cve": "CVE-1", "product_status": {"known_not_affected": ["PID-A"]}}]
    }`
	parsed, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("a defined but cross-category container-cyclic relationship must not error: %v", err)
	}
	for _, st := range parsed.Statements {
		if st.Suppresses() && st.MatchesFinding("CVE-1", "foo", "1.0.0") {
			t.Errorf("cross-category container cycle wrongly suppressed: %+v", st)
		}
	}
}

// End to end: a CSAF not_affected about a SCOPED npm package must not suppress the unscoped package of the
// same leaf name (the review-6 false-suppression).
func TestParseCSAFScopedPurlDoesNotSuppressUnscoped(t *testing.T) {
	const doc = `{
      "document": {"category": "csaf_vex", "csaf_version": "2.0"},
      "product_tree": {"full_product_names": [
        {"product_id": "PID-1", "name": "@safe/lodash 4.17.21", "product_identification_helper": {"purl": "pkg:npm/%40safe/lodash@4.17.21"}}
      ]},
      "vulnerabilities": [{"cve": "CVE-2024-9999", "product_status": {"known_not_affected": ["PID-1"]},
        "flags": [{"label": "component_not_present", "product_ids": ["PID-1"]}]}]
    }`
	parsed, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	for _, st := range parsed.Statements {
		if st.Suppresses() && st.MatchesFinding("CVE-2024-9999", "lodash", "4.17.21") {
			t.Errorf("scoped @safe/lodash wrongly suppressed unscoped lodash: %+v", st)
		}
	}
	// It DOES still suppress its own scoped finding.
	ok := false
	for _, st := range parsed.Statements {
		if st.Suppresses() && st.MatchesFinding("CVE-2024-9999", "@safe/lodash", "4.17.21") {
			ok = true
		}
	}
	if !ok {
		t.Error("scoped product should still suppress its own @safe/lodash finding")
	}
}

// A crafted PURL whose ?qualifier embeds "/%40scope/leaf" must not smuggle a fake npm scope into the match
// target: validPURL sees name "real", and the stored coordinate must too, so it suppresses only "real".
func TestParseCSAFQualifierInjectionDoesNotForgeScope(t *testing.T) {
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {"full_product_names": [
        {"product_id": "PID-REAL", "name": "real", "product_identification_helper": {"purl": "pkg:npm/real?x=/%40safe/lodash"}}
      ]},
      "vulnerabilities": [{"cve": "CVE-2026-0001", "product_status": {"known_not_affected": ["PID-REAL"]}}]
    }`
	parsed, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	for _, st := range parsed.Statements {
		if st.Suppresses() && st.MatchesFinding("CVE-2026-0001", "@safe/lodash", "4.17.21") {
			t.Errorf("qualifier-injected purl forged an @safe/lodash suppression: %+v", st)
		}
	}
	// It legitimately suppresses its real coordinate, "real" (any version).
	ok := false
	for _, st := range parsed.Statements {
		if st.Suppresses() && st.MatchesFinding("CVE-2026-0001", "real", "1.0.0") {
			ok = true
		}
	}
	if !ok {
		t.Error("the cleaned coordinate pkg:npm/real should still suppress component real")
	}
}

// A subpath (#) and a version-plus-qualifier are stripped to the bare coordinate for matching.
func TestParseCSAFQualifierAndSubpathStripped(t *testing.T) {
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {"full_product_names": [
        {"product_id": "PID-1", "name": "lodash", "product_identification_helper": {"purl": "pkg:npm/lodash@4.17.21?repository_url=x#sub"}}
      ]},
      "vulnerabilities": [{"cve": "CVE-1", "product_status": {"known_not_affected": ["PID-1"]}}]
    }`
	parsed, err := ParseCSAF([]byte(doc))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	if len(parsed.Statements) != 1 || !parsed.Statements[0].MatchesFinding("CVE-1", "lodash", "4.17.21") {
		t.Errorf("qualifier/subpath should be stripped to lodash@4.17.21, got %+v", parsed.Statements)
	}
	// The version must be parsed (not a wildcard): a different version must NOT match.
	if parsed.Statements[0].MatchesFinding("CVE-1", "lodash", "3.0.0") {
		t.Errorf("version must be parsed from the cleaned coordinate, not treated as wildcard: %+v", parsed.Statements[0])
	}
}

// A malformed npm namespace (npm has no arbitrary namespace, only @scope) must not collapse to the bare
// leaf and suppress a different unscoped package.
func TestParseCSAFMalformedNpmNamespaceDoesNotSuppress(t *testing.T) {
	for _, purl := range []string{"pkg:npm/notascope/lodash@4.17.21", "pkg:npm/%40/lodash@4.17.21"} {
		doc := `{
          "document": {"csaf_version": "2.0"},
          "product_tree": {"full_product_names": [{"product_id": "PID-1", "name": "x", "product_identification_helper": {"purl": "` + purl + `"}}]},
          "vulnerabilities": [{"cve": "CVE-2026-4242", "product_status": {"known_not_affected": ["PID-1"]}}]
        }`
		parsed, err := ParseCSAF([]byte(doc))
		if err != nil {
			t.Fatalf("ParseCSAF(%q): %v", purl, err)
		}
		for _, st := range parsed.Statements {
			if st.Suppresses() && st.MatchesFinding("CVE-2026-4242", "lodash", "4.17.21") {
				t.Errorf("malformed npm purl %q wrongly suppressed unscoped lodash: %+v", purl, st)
			}
		}
	}
}

// A scoped-PURL not_affected and a name-only "@scope/name" affected match the SAME finding via different
// match paths (purlName reconstruction vs exact equality); the contradiction must still be caught.
func TestParseCSAFScopedSuppressVsNameOnlyAffected(t *testing.T) {
	const doc = `{
      "document": {"csaf_version": "2.0"},
      "product_tree": {"full_product_names": [
        {"product_id": "PID-S", "product_identification_helper": {"purl": "pkg:npm/%40safe/lodash@4.17.21"}},
        {"product_id": "PID-A", "name": "@safe/lodash@4.17.21"}
      ]},
      "vulnerabilities": [{"cve": "CVE-2026-4242", "product_status": {"known_not_affected": ["PID-S"], "known_affected": ["PID-A"]}}]
    }`
	if _, err := ParseCSAF([]byte(doc)); err == nil {
		t.Error("a scoped-purl suppress colliding with a name-only affected must be rejected")
	}
}

func TestParseAnyDispatch(t *testing.T) {
	csaf, err := ParseAny([]byte(sampleCSAF))
	if err != nil {
		t.Fatalf("ParseAny(csaf): %v", err)
	}
	if len(csaf.Statements) != 5 {
		t.Errorf("ParseAny routed CSAF wrong: got %d statements", len(csaf.Statements))
	}
	openvex, err := ParseAny([]byte(sampleVEX))
	if err != nil {
		t.Fatalf("ParseAny(openvex): %v", err)
	}
	if len(openvex.Statements) != 3 {
		t.Errorf("ParseAny routed OpenVEX wrong: got %d statements", len(openvex.Statements))
	}
	if _, err := ParseAny([]byte(`{"garbage": true}`)); err == nil {
		t.Error("ParseAny must reject a document that is neither CSAF nor OpenVEX")
	}
}
