package sca

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// CycloneDX 1.6 EXPORT document — a pure, deterministic projection of the stored SBOM (templated from data,
// no LLM), the CycloneDX peer of the SPDX 2.3 / 3.0 exporters. Synapse consumes CycloneDX on import (the
// cdxBOM/cdxComponent types in sbom_import.go); these cdxOut* types are the distinct EMIT shape, so it emits
// its own enriched model rather than relaying a generator's bytes.
type cdxOutDoc struct {
	BOMFormat    string             `json:"bomFormat"`
	SpecVersion  string             `json:"specVersion"`
	Version      int                `json:"version"`
	Metadata     cdxOutMetadata     `json:"metadata"`
	Components   []cdxOutComponent  `json:"components,omitempty"`
	Dependencies []cdxOutDependency `json:"dependencies,omitempty"`
}

type cdxOutMetadata struct {
	Timestamp string           `json:"timestamp"`
	Tools     cdxOutTools      `json:"tools"`
	Component *cdxOutComponent `json:"component,omitempty"` // the subject of the BOM (the scan target)
}

// cdxOutTools uses the CycloneDX 1.5+ tools-as-components form (the legacy tools array is deprecated).
type cdxOutTools struct {
	Components []cdxOutComponent `json:"components"`
}

type cdxOutComponent struct {
	Type     string          `json:"type"`
	BOMRef   string          `json:"bom-ref,omitempty"`
	Name     string          `json:"name"`
	Version  string          `json:"version,omitempty"`
	PURL     string          `json:"purl,omitempty"`
	Supplier *cdxOutOrg      `json:"supplier,omitempty"`
	Licenses []cdxOutLicense `json:"licenses,omitempty"`
	Hashes   []cdxOutHash    `json:"hashes,omitempty"`
}

type cdxOutOrg struct {
	Name string `json:"name"`
}

// cdxOutLicense is a CycloneDX license choice: an SPDX id when known, else a free-text name (mutually exclusive).
type cdxOutLicense struct {
	License *cdxOutLicenseID `json:"license,omitempty"`
}

type cdxOutLicenseID struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type cdxOutHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxOutDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// CycloneDX returns the engagement's latest scan SBOM as a deterministic CycloneDX 1.6 JSON document.
// shared.ErrNotFound if no scan has run.
func (s *Service) CycloneDX(ctx context.Context, engagementID shared.ID) ([]byte, error) {
	data, err := s.LatestResult(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	var res ScanResult
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("decode scan result: %w", err)
	}
	doc := buildCycloneDX(res.SBOM, res.Target, res.scanTime())
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal cyclonedx: %w", err)
	}
	return out, nil
}

func buildCycloneDX(doc *sbom.SBOM, target string, created time.Time) cdxOutDoc {
	name := target
	if name == "" {
		name = "synapse-sbom"
	}
	out := cdxOutDoc{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: cdxOutMetadata{
			Timestamp: created.Format(time.RFC3339),
			Tools:     cdxOutTools{Components: []cdxOutComponent{{Type: "application", Name: "synapse"}}},
			Component: &cdxOutComponent{Type: "application", Name: name, BOMRef: "synapse:root:" + hash12(name)},
		},
	}
	if doc == nil {
		return out
	}
	comps := append([]sbom.Component(nil), doc.Components...)
	sort.SliceStable(comps, func(i, j int) bool {
		if comps[i].Name != comps[j].Name {
			return comps[i].Name < comps[j].Name
		}
		return comps[i].Version < comps[j].Version
	})
	valid := make(map[string]bool, len(comps)) // component bom-refs, so a dependency edge never dangles
	for i, c := range comps {
		ref := cdxBOMRef(c, i)
		cc := cdxOutComponent{
			Type:     "library",
			BOMRef:   ref,
			Name:     c.Name,
			Version:  c.Version,
			PURL:     c.PURL,
			Licenses: cdxLicenses(c),
			Hashes:   cdxHashes(c),
		}
		// Resolve via SupplierOr (not the raw field) so the export derives the supplier from the PURL namespace
		// for producers/merge paths that leave Supplier empty, matching the SPDX exporters and the scorer.
		if sup := sbom.SupplierOr(c.Supplier, c.PURL); sup != "" {
			cc.Supplier = &cdxOutOrg{Name: sup}
		}
		out.Components = append(out.Components, cc)
		valid[ref] = true
	}
	out.Dependencies = cdxDependencies(doc.Dependencies, valid)
	return out
}

// cdxBOMRef is a stable, unique reference for a component. A PURL already is one (and is what the stored
// dependency edges key on), so it is used directly; a component with no PURL gets a synthesized ref.
func cdxBOMRef(c sbom.Component, i int) string {
	if c.PURL != "" {
		return c.PURL
	}
	return fmt.Sprintf("synapse:comp:%d:%s", i, hash12(c.Name+"@"+c.Version))
}

// cdxDependencies projects the stored dependency edges (keyed by PURL) onto CycloneDX dependency entries,
// dropping any endpoint that has no matching component so a bom-ref never dangles. Deterministic: sorted.
func cdxDependencies(deps []sbom.Dependency, valid map[string]bool) []cdxOutDependency {
	var out []cdxOutDependency
	for _, d := range deps {
		if !valid[d.Ref] {
			continue
		}
		var on []string
		for _, t := range d.DependsOn {
			if valid[t] {
				on = append(on, t)
			}
		}
		sort.Strings(on)
		out = append(out, cdxOutDependency{Ref: d.Ref, DependsOn: on})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

// cdxLicenses renders a component's licenses as CycloneDX license choices: an SPDX id when known, else a
// free-text name. Empty when the component has no license (CDX omits the array rather than asserting one).
func cdxLicenses(c sbom.Component) []cdxOutLicense {
	var out []cdxOutLicense
	for _, l := range c.Licenses {
		switch {
		case l.SPDXID != "":
			out = append(out, cdxOutLicense{License: &cdxOutLicenseID{ID: l.SPDXID}})
		case l.Name != "":
			out = append(out, cdxOutLicense{License: &cdxOutLicenseID{Name: l.Name}})
		}
	}
	return out
}

// cdxHashAlgorithms maps a canonical (SPDX-style) algorithm name to its CycloneDX 1.6 hashAlg enum spelling.
// CycloneDX uses hyphenated SHA names (SHA-256, not SHA256) and defines a NARROWER set than Synapse records:
// SHA-224, MD2, MD4, and ADLER32 have no CycloneDX enum value, so a digest in one of those is dropped on
// export (never emitted non-conformant), mirroring how the SPDX exporter drops unsupported algorithms.
var cdxHashAlgorithms = map[string]string{
	"SHA1": "SHA-1", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512",
	"SHA3-256": "SHA3-256", "SHA3-384": "SHA3-384", "SHA3-512": "SHA3-512",
	"BLAKE2b-256": "BLAKE2b-256", "BLAKE2b-384": "BLAKE2b-384", "BLAKE2b-512": "BLAKE2b-512",
	"MD5": "MD5",
}

// cdxHashes renders a component's integrity digests as CycloneDX hashes: the legacy SHA1 field plus any
// Checksums entry, validated + normalized to lowercase hex through the shared domain gate (so the export
// accepts exactly what the quality scorer counts), then mapped to the CycloneDX algorithm vocabulary.
// Deterministic: one entry per algorithm, sorted; algorithms outside the CycloneDX enum are dropped.
func cdxHashes(c sbom.Component) []cdxOutHash {
	seen := map[string]bool{}
	var out []cdxOutHash
	add := func(alg, val string) {
		name, hexVal, ok := sbom.CanonicalHexDigest(alg, val)
		if !ok {
			return
		}
		cdxAlg, supported := cdxHashAlgorithms[name]
		if !supported || seen[cdxAlg] { // dedup by CycloneDX alg (a SHA1 field + a "SHA-1" entry collapse to one)
			return
		}
		seen[cdxAlg] = true
		out = append(out, cdxOutHash{Alg: cdxAlg, Content: hexVal})
	}
	if c.SHA1 != "" {
		add("SHA1", c.SHA1)
	}
	for _, ck := range c.Checksums {
		add(ck.Algorithm, ck.Value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alg < out[j].Alg })
	return out
}
