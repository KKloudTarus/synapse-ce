package sca

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// spdx3Hashes renders a component's integrity digests as SPDX 3.0 Hash elements, reusing the SPDX 2.x
// normalization (hex value, one per algorithm) and mapping the canonical algorithm name to the SPDX 3.0.1
// HashAlgorithm vocabulary (which is not a plain lower-casing for the SHA-3 and BLAKE2b families).
func spdx3Hashes(c sbom.Component) []spdx3Hash {
	cks := spdxChecksums(c)
	if len(cks) == 0 {
		return nil
	}
	out := make([]spdx3Hash, 0, len(cks))
	for _, ck := range cks {
		out = append(out, spdx3Hash{Type: "Hash", Algorithm: spdx3HashAlg(ck.Algorithm), HashValue: ck.ChecksumValue})
	}
	return out
}

// spdx3HashAlgOverrides maps a canonical (SPDX 2.3-style) algorithm name to its SPDX 3.0.1 HashAlgorithm
// token for the families whose 3.0 spelling is NOT a plain lower-casing: the SHA-3 family uses an underscore
// (sha3_256, not sha3-256) and the BLAKE2b family uses no separator (blake2b256, not blake2b-256).
var spdx3HashAlgOverrides = map[string]string{
	"SHA3-256": "sha3_256", "SHA3-384": "sha3_384", "SHA3-512": "sha3_512",
	"BLAKE2b-256": "blake2b256", "BLAKE2b-384": "blake2b384", "BLAKE2b-512": "blake2b512",
}

// spdx3HashAlg returns the SPDX 3.0.1 HashAlgorithm token for a canonical algorithm name. Most names
// lower-case cleanly (SHA256 -> sha256, MD5 -> md5, ADLER32 -> adler32); the SHA-3 / BLAKE2b families use the
// explicit overrides above.
func spdx3HashAlg(canonical string) string {
	if n, ok := spdx3HashAlgOverrides[canonical]; ok {
		return n
	}
	return strings.ToLower(canonical)
}

// SPDX 3.0.1 minimal JSON-LD projection (CRA-aligned target format) of the stored
// SBOM – core + software profiles. A pure, deterministic function of the stored
// data: sorted components, content-hashed IRIs, the timestamp pinned
// to the scan (never time.Now), so the bytes are byte-reproducible.
const (
	spdx3Context     = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
	spdx3SpecVersion = "3.0.1"
	spdx3IRIBase     = "urn:synapse:spdx:"
)

type spdx3Doc struct {
	Context string `json:"@context"`
	Graph   []any  `json:"@graph"`
}

type spdx3CreationInfo struct {
	Type        string   `json:"type"`
	ID          string   `json:"@id"`
	SpecVersion string   `json:"specVersion"`
	Created     string   `json:"created"`
	CreatedBy   []string `json:"createdBy"`
}

type spdx3Document struct {
	Type               string   `json:"type"`
	SpdxID             string   `json:"spdxId"`
	CreationInfo       string   `json:"creationInfo"`
	Name               string   `json:"name"`
	ProfileConformance []string `json:"profileConformance"`
	RootElement        []string `json:"rootElement"`
	Element            []string `json:"element"`
}

type spdx3Package struct {
	Type           string      `json:"type"`
	SpdxID         string      `json:"spdxId"`
	CreationInfo   string      `json:"creationInfo"`
	Name           string      `json:"name"`
	PackageVersion string      `json:"software_packageVersion,omitempty"`
	PackageURL     string      `json:"software_packageUrl,omitempty"`
	SuppliedBy     string      `json:"suppliedBy,omitempty"`    // IRI of the supplier Agent (NTIA supplier element); SPDX 3.0 models it as a link
	VerifiedUsing  []spdx3Hash `json:"verifiedUsing,omitempty"` // integrity digests, SPDX 3.0 Hash elements (SPDX 3.0.1 HashAlgorithm token, hex value)
	CopyrightText  string      `json:"software_copyrightText"`
}

// spdx3Hash is an SPDX 3.0 Hash integrity method: an SPDX 3.0.1 HashAlgorithm token + a hex digest.
type spdx3Hash struct {
	Type      string `json:"type"`
	Algorithm string `json:"algorithm"`
	HashValue string `json:"hashValue"`
}

// spdx3Agent is an SPDX 3.0 Organization element a package's suppliedBy points to (the NTIA supplier).
type spdx3Agent struct {
	Type         string `json:"type"`
	SpdxID       string `json:"spdxId"`
	CreationInfo string `json:"creationInfo"`
	Name         string `json:"name"`
}

type spdx3Relationship struct {
	Type             string   `json:"type"`
	SpdxID           string   `json:"spdxId"`
	CreationInfo     string   `json:"creationInfo"`
	From             string   `json:"from"`
	RelationshipType string   `json:"relationshipType"`
	To               []string `json:"to"`
}

// SPDX3 returns the engagement's latest scan SBOM as a deterministic SPDX 3.0.1
// JSON-LD document. shared.ErrNotFound if no scan has run.
func (s *Service) SPDX3(ctx context.Context, engagementID shared.ID) ([]byte, error) {
	data, err := s.LatestResult(ctx, engagementID)
	if err != nil {
		return nil, err
	}
	var res ScanResult
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("decode scan result: %w", err)
	}
	doc := buildSPDX3(res.SBOM, res.Target, res.scanTime())
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal spdx3: %w", err)
	}
	return out, nil
}

func buildSPDX3(doc *sbom.SBOM, target string, created time.Time) spdx3Doc {
	name := target
	if name == "" {
		name = "synapse-sbom"
	}
	const ciID = "_:creationInfo"
	ci := spdx3CreationInfo{
		Type:        "CreationInfo",
		ID:          ciID,
		SpecVersion: spdx3SpecVersion,
		Created:     created.Format(time.RFC3339),
		CreatedBy:   []string{spdx3IRIBase + "agent:synapse"},
	}
	docID := spdx3IRIBase + "doc:" + spdxSlug(name) + "-" + hash12(name+created.Format(time.RFC3339))

	graph := []any{ci}

	var pkgIDs []string
	var pkgs []any
	var agentIDs []string
	var agents []any
	if doc != nil {
		comps := append([]sbom.Component(nil), doc.Components...)
		sort.SliceStable(comps, func(i, j int) bool {
			if comps[i].Name != comps[j].Name {
				return comps[i].Name < comps[j].Name
			}
			return comps[i].Version < comps[j].Version
		})
		// Mint one Organization Agent per unique supplier (SupplierOr, so producers/merge paths that left
		// Supplier empty still get the PURL-derived value – matching SPDX 2.x + the scorer). Sorted for a
		// deterministic, content-hashed IRI.
		agentByName := map[string]string{}
		var supplierNames []string
		for _, c := range comps {
			if sup := sbom.SupplierOr(c.Supplier, c.PURL); sup != "" {
				if _, ok := agentByName[sup]; !ok {
					agentByName[sup] = "" // placeholder; IRI assigned after sorting
					supplierNames = append(supplierNames, sup)
				}
			}
		}
		sort.Strings(supplierNames)
		for _, sup := range supplierNames {
			id := spdx3IRIBase + "agent:" + hash12(sup)
			agentByName[sup] = id
			agentIDs = append(agentIDs, id)
			agents = append(agents, spdx3Agent{Type: "Organization", SpdxID: id, CreationInfo: ciID, Name: sup})
		}
		for i, c := range comps {
			id := spdx3IRIBase + "pkg:" + fmt.Sprintf("%d-%s", i, hash12(c.Name+"@"+c.Version+c.PURL))
			pkgIDs = append(pkgIDs, id)
			pkg := spdx3Package{
				Type:           "software_Package",
				SpdxID:         id,
				CreationInfo:   ciID,
				Name:           c.Name,
				PackageVersion: c.Version,
				PackageURL:     c.PURL,
				CopyrightText:  "NOASSERTION",
			}
			if sup := sbom.SupplierOr(c.Supplier, c.PURL); sup != "" {
				pkg.SuppliedBy = agentByName[sup]
			}
			pkg.VerifiedUsing = spdx3Hashes(c)
			pkgs = append(pkgs, pkg)
		}
	}

	graph = append(graph, spdx3Document{
		Type:               "SpdxDocument",
		SpdxID:             docID,
		CreationInfo:       ciID,
		Name:               name,
		ProfileConformance: []string{"core", "software"},
		RootElement:        pkgIDs,
		Element:            append(append([]string(nil), pkgIDs...), agentIDs...),
	})
	graph = append(graph, pkgs...)
	graph = append(graph, agents...)
	if len(pkgIDs) > 0 {
		graph = append(graph, spdx3Relationship{
			Type:             "Relationship",
			SpdxID:           spdx3IRIBase + "rel:contains",
			CreationInfo:     ciID,
			From:             docID,
			RelationshipType: "contains",
			To:               pkgIDs,
		})
	}

	return spdx3Doc{Context: spdx3Context, Graph: graph}
}
