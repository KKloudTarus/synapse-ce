package sca

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// SPDX 2.3 minimal document – a pure, deterministic projection of the stored SBOM
// (templated from data, no LLM). PURLs become externalRefs;
// licenses (now registry-enriched) become licenseDeclared.
type spdxDoc struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      spdxCreation   `json:"creationInfo"`
	Packages          []spdxPackage  `json:"packages"`
	Relationships     []spdxRelation `json:"relationships"`
}

type spdxCreation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string         `json:"SPDXID"`
	Name             string         `json:"name"`
	VersionInfo      string         `json:"versionInfo,omitempty"`
	Supplier         string         `json:"supplier,omitempty"` // "Organization: <name>" – NTIA supplier element; omitted when unknown
	DownloadLocation string         `json:"downloadLocation"`
	Checksums        []spdxChecksum `json:"checksums,omitempty"` // integrity digests (SPDX form: lowercase hex per algorithm)
	LicenseDeclared  string         `json:"licenseDeclared"`
	LicenseConcluded string         `json:"licenseConcluded"`
	ExternalRefs     []spdxExtRef   `json:"externalRefs,omitempty"`
}

// spdxChecksum is an SPDX 2.3 package integrity digest. ChecksumValue is lowercase hex (SPDX requires hex,
// so a base64 digest such as npm's Subresource Integrity is converted on the way out).
type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxExtRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelation struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// SPDX returns the engagement's latest scan SBOM as a deterministic SPDX 2.3 JSON
// document. shared.ErrNotFound if no scan has run.
func (s *Service) SPDX(ctx context.Context, engagementID shared.ID) ([]byte, error) {
	data, err := s.LatestResult(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	var res ScanResult
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("decode scan result: %w", err)
	}
	created := res.scanTime()
	doc := buildSPDX(res.SBOM, res.Target, created)
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal spdx: %w", err)
	}
	return out, nil
}

// scanTime derives a stable timestamp from the vuln-DB snapshot marker (which is
// pinned per scan), falling back to the zero time – never time.Now(), so the
// document is byte-reproducible from stored data.
func (r ScanResult) scanTime() time.Time {
	if i := strings.LastIndex(r.VulnDBSnapshot, "@"); i >= 0 {
		if t, err := time.Parse(time.RFC3339, r.VulnDBSnapshot[i+1:]); err == nil {
			return t.UTC()
		}
	}
	return time.Unix(0, 0).UTC()
}

func buildSPDX(doc *sbom.SBOM, target string, created time.Time) spdxDoc {
	name := target
	if name == "" {
		name = "synapse-sbom"
	}
	out := spdxDoc{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              name,
		DocumentNamespace: "https://synapse.local/spdx/" + spdxSlug(name) + "-" + hash12(name+created.Format(time.RFC3339)),
		CreationInfo: spdxCreation{
			Created:  created.Format(time.RFC3339),
			Creators: []string{"Tool: synapse", "Tool: syft"},
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
	for i, c := range comps {
		id := fmt.Sprintf("SPDXRef-Package-%d-%s", i, hash12(c.Name+"@"+c.Version+c.PURL))
		lic := spdxLicense(c)
		pkg := spdxPackage{
			SPDXID:           id,
			Name:             c.Name,
			VersionInfo:      c.Version,
			DownloadLocation: "NOASSERTION",
			LicenseDeclared:  lic,
			LicenseConcluded: lic,
		}
		// Resolve via SupplierOr (not the raw field) so the export derives the supplier from the PURL namespace
		// for producers/merge paths that leave Supplier empty (e.g. the JVM resolver tree) – matching the scorer.
		if sup := sbom.SupplierOr(c.Supplier, c.PURL); sup != "" { // NTIA supplier element; SPDX form "Organization: <name>"
			pkg.Supplier = "Organization: " + sup
		}
		pkg.Checksums = spdxChecksums(c)
		if c.PURL != "" {
			pkg.ExternalRefs = []spdxExtRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  c.PURL,
			}}
		}
		out.Packages = append(out.Packages, pkg)
		out.Relationships = append(out.Relationships, spdxRelation{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: id,
		})
	}
	return out
}

// spdxChecksums renders a component's integrity digests as SPDX 2.3 checksums: the legacy SHA1 field plus any
// Checksums entry, each normalized to lowercase hex (SPDX requires hex, so a base64 SRI digest is converted).
// Deterministic: one entry per algorithm, sorted by algorithm.
func spdxChecksums(c sbom.Component) []spdxChecksum {
	seen := map[string]bool{}
	var out []spdxChecksum
	add := func(alg, val string) {
		spdxAlg, hexVal, ok := spdxHexDigest(alg, val)
		if !ok || seen[spdxAlg] { // dedup by the CANONICAL name (a SHA1 field + a "SHA-1" entry collapse to one)
			return
		}
		seen[spdxAlg] = true
		out = append(out, spdxChecksum{Algorithm: spdxAlg, ChecksumValue: hexVal})
	}
	if c.SHA1 != "" {
		add("SHA1", c.SHA1)
	}
	for _, ck := range c.Checksums {
		add(ck.Algorithm, ck.Value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Algorithm < out[j].Algorithm })
	return out
}

// spdxHexDigest maps (algorithm, value) to a canonical SPDX 2.3 checksum-algorithm name + lowercase-hex
// value. It delegates BOTH the accept decision and the canonical name to sbom.CanonicalHexDigest – the one
// digest gate shared with the quality scorer (HasChecksum) – so the exporter and the scorer accept exactly
// the same digests by construction, with no second algorithm table to drift. Domain checksum algorithm
// names are SPDX-style (see sbom.Checksum), so the returned name is the SPDX spelling. A malformed,
// wrong-length, or non-conformant checksum yields ("", "", false) and is dropped from the output.
func spdxHexDigest(alg, value string) (spdxAlg, hexVal string, ok bool) {
	return sbom.CanonicalHexDigest(alg, value)
}

func spdxLicense(c sbom.Component) string {
	var ids []string
	for _, l := range c.Licenses {
		if l.SPDXID != "" {
			ids = append(ids, l.SPDXID)
		} else if l.Name != "" {
			ids = append(ids, l.Name)
		}
	}
	if len(ids) == 0 {
		return "NOASSERTION"
	}
	return strings.Join(ids, " AND ")
}

func spdxSlug(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := b.String()
	if out == "" {
		return "sbom"
	}
	return out
}

func hash12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)[:12]
}
