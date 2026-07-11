package ownadvisory

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ParseCSAF normalizes one OASIS CSAF 2.0 document (RedHat/SUSE/Cisco-style vendor security advisories)
// into the owned domain advisory.Advisory model. A CSAF document carries MANY
// vulnerabilities, so it yields a SLICE – one advisory per `vulnerabilities[]` entry that has a CVE id and
// at least one product binding we can resolve to an OSV (ecosystem, package) key.
//
// CSAF is product-centric: a `product_tree` defines products – via BOTH the flat `full_product_names` list
// and the recursive `branches` tree (vendor→product→version, the RedHat/SUSE form) – each carrying a CPE,
// and each vulnerability's `product_status.{known_affected,fixed,first_fixed}` + `remediations[]` (category
// vendor_fix) references those products by id. We resolve product_id → CPE → (ecosystem, package, version)
// via the conservative cpeToEcosystem bridge (see cpe.go) – a binding whose CPE does not map to a
// comparator-backed language ecosystem is SKIPPED (not mis-keyed). This is a pure parser (no I/O), mirroring
// ParseOSV; the feed reads the bytes and the store persists the result.
//
// Limitation (documented, not a defect): CSAF/CPE keys vendor products, the matcher keys OSV
// ecosystem+package – so an advisory only matches when the SBOM carries a CPE-derivable component. A vuln
// with no resolvable binding yields an advisory with empty Affected (inert in the store); the feed skips it.
func ParseCSAF(data []byte) ([]advisory.Advisory, error) {
	if len(data) > maxAdvisoryBytes {
		// Self-protect even when called directly: the exported parser invites callers that bypass the feed's
		// per-file cap (limits.go), so a single CSAF document must fit the same byte budget here too.
		return nil, fmt.Errorf("%w: CSAF document exceeds %d bytes", shared.ErrValidation, maxAdvisoryBytes)
	}
	// Decode-time recursion over the self-referential branches tree is bounded by encoding/json's internal
	// nesting limit (Go >=1.19 returns an error rather than overflowing the stack); maxBranchDepth below
	// guards only the post-decode walk. A future switch to a streaming/custom decoder MUST keep a
	// decode-depth bound, or this fail-closed property is lost.
	var doc csafDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse CSAF advisory: %w", err)
	}
	cpeByProduct := doc.ProductTree.cpeByProductID()
	out := make([]advisory.Advisory, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		id := strings.TrimSpace(v.CVE)
		if id == "" {
			continue // no CVE → no stable store key (slice 1; vuln.ids fallback is a later refinement)
		}
		adv := advisory.Advisory{
			ID:       id,
			Aliases:  v.aliases(),
			Summary:  firstNonEmpty(v.Title, doc.Document.Title),
			Affected: v.affected(cpeByProduct),
		}
		adv.CVSSVector, adv.CVSSScore = v.cvss()
		out = append(out, adv)
	}
	return out, nil
}

// --- CSAF 2.0 JSON shape (the subset the owned store needs) ---

type csafDoc struct {
	Document        csafDocument  `json:"document"`
	ProductTree     csafTree      `json:"product_tree"`
	Vulnerabilities []csafVulnDoc `json:"vulnerabilities"`
}

type csafDocument struct {
	Title string `json:"title"`
}

type csafTree struct {
	FullProductNames []csafProduct `json:"full_product_names"`
	Branches         []csafBranch  `json:"branches"`
}

type csafProduct struct {
	ProductID string `json:"product_id"`
	Helper    struct {
		CPE string `json:"cpe"`
	} `json:"product_identification_helper"`
}

// csafBranch is a node in the recursive product_tree.branches form (vendor → product → version, …): the CPE
// lives in the `product` of a leaf branch, so resolving a product_id means walking the whole tree. This is
// the shape RedHat/SUSE-style vendor advisories use (full_product_names alone is the simpler minority case).
type csafBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Product  *csafProduct `json:"product"`  // present on a leaf branch (e.g. category "product_version")
	Branches []csafBranch `json:"branches"` // child branches
}

// maxBranchDepth bounds product_tree recursion so a hostile, pathologically-deep tree cannot exhaust the
// stack (real CSAF trees are vendor→product→version, ~3-4 levels).
const maxBranchDepth = 64

// cpeByProductID indexes product_id → CPE from BOTH product_tree shapes: the flat full_product_names list
// and the recursive branches tree. full_product_names is indexed first; a branch product with the same id
// refines it (deterministic – both come from the same parsed document).
func (t csafTree) cpeByProductID() map[string]string {
	m := make(map[string]string, len(t.FullProductNames))
	for _, p := range t.FullProductNames {
		if p.ProductID != "" && p.Helper.CPE != "" {
			m[p.ProductID] = p.Helper.CPE
		}
	}
	for _, b := range t.Branches {
		collectBranchCPEs(b, 0, m)
	}
	return m
}

// collectBranchCPEs walks a product_tree branch (depth-bounded) recording every leaf product's id → CPE.
func collectBranchCPEs(b csafBranch, depth int, m map[string]string) {
	if depth >= maxBranchDepth {
		return // bound recursion on an untrusted (possibly hostile) product_tree
	}
	if b.Product != nil && b.Product.ProductID != "" && b.Product.Helper.CPE != "" {
		m[b.Product.ProductID] = b.Product.Helper.CPE
	}
	for _, child := range b.Branches {
		collectBranchCPEs(child, depth+1, m)
	}
}

type csafVulnDoc struct {
	CVE   string `json:"cve"`
	Title string `json:"title"`
	IDs   []struct {
		Text string `json:"text"`
	} `json:"ids"`
	Scores []struct {
		CVSSv3 struct {
			VectorString string  `json:"vectorString"`
			BaseScore    float64 `json:"baseScore"`
		} `json:"cvss_v3"`
	} `json:"scores"`
	ProductStatus struct {
		KnownAffected []string `json:"known_affected"`
		Fixed         []string `json:"fixed"`
		FirstFixed    []string `json:"first_fixed"`
	} `json:"product_status"`
	Remediations []struct {
		Category   string   `json:"category"`
		ProductIDs []string `json:"product_ids"`
	} `json:"remediations"`
}

// fixedProductIDs is the union of product_status.{fixed,first_fixed} and the product_ids of any
// "vendor_fix" remediation – the CSAF places that name a remediated product version.
func (v csafVulnDoc) fixedProductIDs() []string {
	out := append([]string{}, v.ProductStatus.Fixed...)
	out = append(out, v.ProductStatus.FirstFixed...)
	for _, r := range v.Remediations {
		if r.Category == "vendor_fix" {
			out = append(out, r.ProductIDs...)
		}
	}
	return out
}

// aliases collects the vuln's non-CVE ids (e.g. GHSA/vendor ids) for cross-feed reconciliation.
func (v csafVulnDoc) aliases() []string {
	var out []string
	for _, id := range v.IDs {
		if t := strings.TrimSpace(id.Text); t != "" && t != v.CVE {
			out = append(out, t)
		}
	}
	return out
}

// cvss returns the first CVSS v3.x vector + base score (the canonical band source), mirroring ParseOSV.
// The document's baseScore is trusted when > 0; otherwise it is (re)computed from the vector (a genuine
// 0.0 "None" score recomputes to ~0 either way, so the > 0 guard is safe).
func (v csafVulnDoc) cvss() (vector string, score float64) {
	for _, s := range v.Scores {
		vec := strings.TrimSpace(s.CVSSv3.VectorString)
		if !strings.HasPrefix(vec, "CVSS:3.") {
			continue
		}
		vector = vec
		if s.CVSSv3.BaseScore > 0 {
			score = s.CVSSv3.BaseScore
		} else if computed, ok := shared.CVSSv3BaseScore(vec); ok {
			score = computed
		}
		return vector, score
	}
	return "", 0
}

// affectedAccum accumulates a product's affected versions while resolving product bindings, before being
// flattened into a deterministic advisory.AffectedPackage.
type affectedAccum struct {
	ecosystem   string
	pkg         string
	versions    map[string]bool // explicit concrete affected versions (from each known_affected CPE)
	allVersions bool            // a known_affected CPE with version "*" ⇒ every version is affected
	fixed       string          // first concrete fixed version (from fixed/first_fixed CPEs)
}

// affected resolves the vulnerability's product bindings into advisory.AffectedPackage entries via the CPE
// bridge, grouped by (ecosystem, package). known_affected CPEs contribute explicit versions (or an open
// range for "*"); product_status.{fixed,first_fixed} and vendor_fix remediations contribute the remediation
// hint (see fixedProductIDs). Deterministic (sorted).
func (v csafVulnDoc) affected(cpeByProduct map[string]string) []advisory.AffectedPackage {
	groups := map[string]*affectedAccum{}
	key := func(eco, pkg string) string { return eco + "\x00" + pkg }

	for _, pid := range v.ProductStatus.KnownAffected {
		eco, pkg, ver, ok := resolveProductCPE(cpeByProduct, pid)
		if !ok {
			continue
		}
		g := groups[key(eco, pkg)]
		if g == nil {
			g = &affectedAccum{ecosystem: eco, pkg: pkg, versions: map[string]bool{}}
			groups[key(eco, pkg)] = g
		}
		switch ver {
		case "*":
			g.allVersions = true // CPE version ANY ⇒ all versions affected
		case "-", "":
			// NA / unspecified version: the package is named but no version signal – record the group so a
			// fixed version can still attach, but it contributes no match on its own.
		default:
			g.versions[ver] = true
		}
	}
	for _, pid := range v.fixedProductIDs() {
		eco, pkg, ver, ok := resolveProductCPE(cpeByProduct, pid)
		if !ok || ver == "" || ver == "*" || ver == "-" {
			continue
		}
		if g := groups[key(eco, pkg)]; g != nil && g.fixed == "" {
			g.fixed = ver
		}
	}

	out := make([]advisory.AffectedPackage, 0, len(groups))
	for _, g := range groups {
		ap := advisory.AffectedPackage{Ecosystem: g.ecosystem, Package: g.pkg, FixedVersion: g.fixed}
		if g.allVersions {
			// "all versions affected" as an open ECOSYSTEM range (introduced at 0); the fixed event, if any,
			// closes it so the matcher reports versions >= fixed as not-affected. This is the broadest match
			// (every version of the package) – intentionally accepted as OSV's all-versions semantics. It is
			// safe here because targetSWEcosystem is restricted to faithful-name ecosystems, so a mis-key
			// (which an unbounded range would amplify) is prevented at the bridge, not here; it errs toward a
			// false positive on the RIGHT package (conservatively many versions) – the safe direction.
			ev := []advisory.Event{{Introduced: "0"}}
			if g.fixed != "" {
				ev = append(ev, advisory.Event{Fixed: g.fixed})
			}
			ap.Ranges = []advisory.Range{{Type: "ECOSYSTEM", Events: ev}}
		}
		for ver := range g.versions {
			ap.Versions = append(ap.Versions, ver)
		}
		sort.Strings(ap.Versions)
		// Drop a binding that carries no match signal at all (no versions, not all-versions) – it is inert.
		if len(ap.Versions) == 0 && len(ap.Ranges) == 0 {
			continue
		}
		out = append(out, ap)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		return out[i].Package < out[j].Package
	})
	return out
}

// resolveProductCPE looks up a product_id's CPE and runs the conservative ecosystem bridge.
func resolveProductCPE(cpeByProduct map[string]string, productID string) (eco, pkg, version string, ok bool) {
	cpe, found := cpeByProduct[productID]
	if !found {
		return "", "", "", false
	}
	return cpeToEcosystem(cpe)
}
