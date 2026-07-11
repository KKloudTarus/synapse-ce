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

func purlName(product string) string {
	if i := strings.LastIndex(product, "/"); i >= 0 {
		return product[i+1:]
	}
	return product
}
