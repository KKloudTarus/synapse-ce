package vex

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Document is the subset of an OpenVEX 0.2 document Synapse CONSUMES: each statement asserts a status for a
// vulnerability against one or more products. It is the shared parse + match core for BOTH the post-scan
// VEX apply (usecase/vex) and the in-scan .vex consumption (the SCA pipeline), so the two can never drift.
type Document struct {
	Context    string
	Statements []Statement
}

// Statement is one VEX assertion.
type Statement struct {
	Vulnerability string   // advisory id, e.g. "CVE-2024-1234"
	Products      []string // product ids, e.g. "pkg:npm/foo@1.0.0" or "foo@1.0.0"
	Status        string   // OpenVEX status: not_affected | fixed | affected | under_investigation
	Justification string
}

// wire mirrors the OpenVEX JSON shape for unmarshalling.
type wire struct {
	Context    string `json:"@context"`
	Statements []struct {
		Vulnerability struct {
			Name string `json:"name"`
		} `json:"vulnerability"`
		Products []struct {
			ID string `json:"@id"`
		} `json:"products"`
		Status        string `json:"status"`
		Justification string `json:"justification"`
	} `json:"statements"`
}

// Parse decodes an OpenVEX document. It errors on invalid JSON or a non-OpenVEX / empty document, so a
// caller never silently treats junk as an empty policy.
func Parse(data []byte) (Document, error) {
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return Document{}, fmt.Errorf("%w: invalid VEX document: %v", shared.ErrValidation, err)
	}
	if !strings.Contains(w.Context, "openvex") || len(w.Statements) == 0 {
		return Document{}, fmt.Errorf("%w: not a non-empty OpenVEX document", shared.ErrValidation)
	}
	doc := Document{Context: w.Context}
	for _, s := range w.Statements {
		st := Statement{Vulnerability: s.Vulnerability.Name, Status: s.Status, Justification: s.Justification}
		for _, p := range s.Products {
			st.Products = append(st.Products, p.ID)
		}
		doc.Statements = append(doc.Statements, st)
	}
	return doc, nil
}

// Suppresses reports whether this statement's status asserts "no action needed" (not_affected or fixed) –
// the two statuses that remove a finding from the actionable set.
func (s Statement) Suppresses() bool {
	switch strings.ToLower(strings.TrimSpace(s.Status)) {
	case "not_affected", "fixed":
		return true
	}
	return false
}

// MatchesFinding reports whether this statement targets the given finding, identified by its advisory id +
// component + version (as parsed from the finding's dedup key). A product matches when its component equals
// the finding's (directly or by PURL name) and its version is absent (matches all versions) or equal.
func (s Statement) MatchesFinding(advisory, component, version string) bool {
	if s.Vulnerability == "" || s.Vulnerability != advisory {
		return false
	}
	return s.targetsProduct(component, version)
}

// targetsProduct reports whether one of the statement's products is component at version: the product names
// the component (directly or by PURL name) and its version is absent (all versions) or equal.
func (s Statement) targetsProduct(component, version string) bool {
	for _, p := range s.Products {
		pComp, pVer := splitProduct(p)
		if !componentMatches(component, pComp) {
			continue
		}
		if pVer == "" || pVer == version {
			return true
		}
	}
	return false
}

// AdvisoryIndex maps an advisory id, case-folded, to the positions of the findings that go by it: the id each
// finding is reported under and any alias it may be matched by. A statement then reaches its candidate
// findings with one map read instead of a pass over every finding.
type AdvisoryIndex map[string][]int

// Add records that the finding at pos goes by ids. Empty and repeated ids are skipped.
func (x AdvisoryIndex) Add(pos int, ids ...string) {
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		key := strings.ToUpper(strings.TrimSpace(id))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		x[key] = append(x[key], pos)
	}
}

// Candidates returns, in ascending order, the positions of the findings that go by this statement's advisory
// id. A candidate is a target when TargetsProduct also holds for its component and version.
func (s Statement) Candidates(x AdvisoryIndex) []int {
	return x[strings.ToUpper(strings.TrimSpace(s.Vulnerability))]
}

// TargetsProduct reports whether one of the statement's products is component at version: the product names
// the component (directly or by PURL name) and its version is absent (all versions) or equal.
func (s Statement) TargetsProduct(component, version string) bool {
	return s.targetsProduct(component, version)
}

func splitProduct(id string) (component, version string) {
	if i := strings.LastIndex(id, "@"); i > 0 {
		return id[:i], id[i+1:]
	}
	return id, ""
}

// componentMatches matches a finding component to a VEX product component: exact, or the product's
// path-bounded PURL name segment equals it. Matching the bounded name (not a raw substring) avoids
// over-matching – a product "pkg:npm/foobar" must NOT match a finding component "foo".
func componentMatches(findingComp, productComp string) bool {
	if findingComp == "" || productComp == "" {
		return false
	}
	return findingComp == productComp || purlName(productComp) == findingComp
}

// purlName reduces a product identifier to the package name a finding is keyed by. For most ecosystems the
// finding component is the bare last path segment (Debian "bash", Go "gin"), so that segment is returned.
// The exception is an npm SCOPED package: its purl carries the scope as a leading namespace segment
// ("@scope", percent-encoded "%40scope"), and the finding component keeps the full "@scope/name" (see the
// ownsbom npm parser). Collapsing it to the bare name would let a statement about "@scope/name" match — and
// wrongly suppress — a DIFFERENT, unscoped package of the same leaf name, so the scope is reconstructed.
func purlName(product string) string {
	i := strings.LastIndex(product, "/")
	if i < 0 {
		return product
	}
	leaf := product[i+1:]
	// Scope reconstruction is npm-only: a "%40scope" segment is an npm scope solely under the npm purl type.
	// The same segment under another type (pkg:generic/%40safe/lodash) is an ordinary namespace and must
	// still collapse to the bare leaf, or a non-npm product would wrongly match an npm scoped finding.
	if strings.HasPrefix(strings.ToLower(product), "pkg:npm/") {
		if j := strings.LastIndex(product[:i], "/"); j >= 0 {
			if scope, ok := npmScopeSegment(product[j+1 : i]); ok {
				return scope + "/" + leaf
			}
		}
	}
	return leaf
}

// npmScopeSegment recognizes an npm scope namespace segment ("@scope" or its percent-encoded "%40scope"
// form) and returns it in canonical "@scope" shape. A non-npm namespace segment (a Debian/Go/Maven path
// component) is not a scope, so it returns ok=false and the bare-leaf collapse stands.
func npmScopeSegment(seg string) (string, bool) {
	if len(seg) > 1 && seg[0] == '@' {
		return seg, true
	}
	if len(seg) > 3 && strings.EqualFold(seg[:3], "%40") {
		return "@" + seg[3:], true
	}
	return "", false
}
