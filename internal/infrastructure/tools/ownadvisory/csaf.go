package ownadvisory

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
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
	return parseCSAF(data, false)
}

// parseCSAF keeps unbounded Red Hat RPM product status scoped to a complete source snapshot. A streaming
// document is not evidence that a later document will not close that range, so it must not emit one.
func parseCSAF(data []byte, allowUnboundedRPM bool) ([]advisory.Advisory, error) {
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
	purlByProduct := doc.ProductTree.purlByProductID()
	nameByProduct := doc.ProductTree.nameByProductID()
	rels := doc.ProductTree.relationshipsByProductID()
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
			Affected: v.affected(cpeByProduct, purlByProduct, nameByProduct, rels, allowUnboundedRPM),
		}
		adv.CVSSVector, adv.CVSSScore = v.cvss()
		out = append(out, adv)
	}
	return out, nil
}

var csafSnapshotCVEPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// ParseCSAFSnapshot reduces a complete CSAF source snapshot into one deterministic replacement record per CVE.
// Unlike streaming ParseCSAF, every vulnerability must carry a representable CVE and duplicate projections must
// be identical after aliases are intentionally discarded. A complete snapshot can safely retain Red Hat's
// unbounded binary VEX ranges; a single streaming document cannot.
func ParseCSAFSnapshot(documents [][]byte) ([]advisory.Advisory, error) {
	if len(documents) == 0 {
		return nil, fmt.Errorf("%w: CSAF snapshot is empty", shared.ErrValidation)
	}
	byCVE := make(map[string]advisory.Advisory)
	for documentIndex, data := range documents {
		if len(data) > maxAdvisoryBytes {
			return nil, fmt.Errorf("%w: CSAF snapshot document %d exceeds %d bytes", shared.ErrValidation, documentIndex+1, maxAdvisoryBytes)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil || raw == nil {
			return nil, fmt.Errorf("%w: parse CSAF snapshot document %d", shared.ErrValidation, documentIndex+1)
		}
		vulnerabilities, hasVulnerabilities := raw["vulnerabilities"]
		if !hasVulnerabilities || strings.TrimSpace(string(vulnerabilities)) == "null" {
			return nil, fmt.Errorf("%w: CSAF snapshot document %d has no vulnerabilities array", shared.ErrValidation, documentIndex+1)
		}
		var doc csafDoc
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("%w: parse CSAF snapshot document %d: %v", shared.ErrValidation, documentIndex+1, err)
		}
		for vulnerabilityIndex, vulnerability := range doc.Vulnerabilities {
			if _, err := normalizedCSAFCVE(vulnerability.CVE); err != nil {
				return nil, fmt.Errorf("%w: CSAF snapshot document %d vulnerability %d: %v", shared.ErrValidation, documentIndex+1, vulnerabilityIndex+1, err)
			}
		}

		parsed, err := parseCSAF(data, true)
		if err != nil {
			return nil, fmt.Errorf("parse CSAF snapshot document %d: %w", documentIndex+1, err)
		}
		if len(parsed) != len(doc.Vulnerabilities) {
			return nil, fmt.Errorf("%w: CSAF snapshot document %d could not represent every vulnerability", shared.ErrValidation, documentIndex+1)
		}
		for _, advisoryRecord := range parsed {
			cve, err := normalizedCSAFCVE(advisoryRecord.ID)
			if err != nil {
				return nil, fmt.Errorf("%w: CSAF snapshot document %d: %v", shared.ErrValidation, documentIndex+1, err)
			}
			advisoryRecord.ID = cve
			advisoryRecord.Aliases = nil
			if existing, found := byCVE[cve]; found {
				if !reflect.DeepEqual(existing, advisoryRecord) {
					return nil, fmt.Errorf("%w: conflicting CSAF snapshot records for %s", shared.ErrValidation, cve)
				}
				continue
			}
			byCVE[cve] = advisoryRecord
		}
	}

	cves := make([]string, 0, len(byCVE))
	for cve := range byCVE {
		cves = append(cves, cve)
	}
	sort.Strings(cves)
	out := make([]advisory.Advisory, 0, len(cves))
	for _, cve := range cves {
		out = append(out, byCVE[cve])
	}
	return out, nil
}

func normalizedCSAFCVE(raw string) (string, error) {
	cve := strings.ToUpper(strings.TrimSpace(raw))
	if !csafSnapshotCVEPattern.MatchString(cve) {
		return "", fmt.Errorf("invalid or missing CVE %q", raw)
	}
	return cve, nil
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
	FullProductNames []csafProduct      `json:"full_product_names"`
	Branches         []csafBranch       `json:"branches"`
	Relationships    []csafRelationship `json:"relationships"`
}

// csafRelationship is the CSAF product_tree.relationships form that RedHat uses to bind a package version
// (product_reference, carrying a PURL) to a platform (relates_to_product_reference, carrying a CPE) under a
// single composite product_id (full_product_name.product_id). The vulnerability's product_status references
// that COMPOSITE id, so resolving a RedHat rpm binding means: composite → (package_ref, platform_ref) →
// (PURL name+evr, CPE RHEL major). Without this, the package's ecosystem (rpm name+version) and the platform
// (RHEL major) live in two different products and can never be joined.
type csafRelationship struct {
	Category                  string      `json:"category"`
	ProductReference          string      `json:"product_reference"`
	RelatesToProductReference string      `json:"relates_to_product_reference"`
	FullProductName           csafProduct `json:"full_product_name"`
}

type csafProduct struct {
	Name      string `json:"name"`
	ProductID string `json:"product_id"`
	Helper    struct {
		CPE  string `json:"cpe"`
		PURL string `json:"purl"`
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

func (t csafTree) nameByProductID() map[string]string {
	m := make(map[string]string, len(t.FullProductNames))
	for _, p := range t.FullProductNames {
		if p.ProductID != "" && p.Name != "" {
			m[p.ProductID] = p.Name
		}
	}
	for _, b := range t.Branches {
		collectBranchNames(b, 0, m)
	}
	return m
}

func collectBranchNames(b csafBranch, depth int, m map[string]string) {
	if depth >= maxBranchDepth {
		return
	}
	if b.Product != nil && b.Product.ProductID != "" {
		name := strings.TrimSpace(b.Product.Name)
		if name == "" {
			name = strings.TrimSpace(b.Name)
		}
		if name != "" {
			m[b.Product.ProductID] = name
		}
	}
	for _, child := range b.Branches {
		collectBranchNames(child, depth+1, m)
	}
}

// purlByProductID indexes product_id → PURL from BOTH product_tree shapes, mirroring cpeByProductID. RedHat
// carries a package version's PURL (pkg:rpm/redhat/<name>@<evr>) on a leaf product_version branch.
func (t csafTree) purlByProductID() map[string]string {
	m := make(map[string]string, len(t.FullProductNames))
	for _, p := range t.FullProductNames {
		if p.ProductID != "" && p.Helper.PURL != "" {
			m[p.ProductID] = p.Helper.PURL
		}
	}
	for _, b := range t.Branches {
		collectBranchPURLs(b, 0, m)
	}
	return m
}

// collectBranchPURLs walks a product_tree branch (depth-bounded) recording every leaf product's id → PURL.
func collectBranchPURLs(b csafBranch, depth int, m map[string]string) {
	if depth >= maxBranchDepth {
		return
	}
	if b.Product != nil && b.Product.ProductID != "" && b.Product.Helper.PURL != "" {
		m[b.Product.ProductID] = b.Product.Helper.PURL
	}
	for _, child := range b.Branches {
		collectBranchPURLs(child, depth+1, m)
	}
}

// csafRel is a resolved package↔platform binding: the composite product_id maps to the package product and
// the platform product it is a component of.
type csafRel struct {
	pkgRef      string // product_reference: the package product (carries the PURL)
	platformRef string // relates_to_product_reference: the platform product (carries the CPE)
}

// relationshipsByProductID indexes the composite product_id → (package ref, platform ref) for
// default_component_of relationships (the RedHat rpm binding). Other relationship categories are ignored.
func (t csafTree) relationshipsByProductID() map[string]csafRel {
	if len(t.Relationships) == 0 {
		return nil
	}
	m := make(map[string]csafRel, len(t.Relationships))
	for _, r := range t.Relationships {
		if r.Category != "default_component_of" {
			continue
		}
		id := r.FullProductName.ProductID
		if id == "" || r.ProductReference == "" || r.RelatesToProductReference == "" {
			continue
		}
		m[id] = csafRel{pkgRef: r.ProductReference, platformRef: r.RelatesToProductReference}
	}
	return m
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
		KnownAffected    []string `json:"known_affected"`
		KnownNotAffected []string `json:"known_not_affected"`
		Fixed            []string `json:"fixed"`
		FirstFixed       []string `json:"first_fixed"`
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
	ecosystem    string
	pkg          string
	versions     map[string]bool // explicit concrete affected versions (from each known_affected CPE)
	allVersions  bool            // a known_affected CPE with version "*" ⇒ every version is affected
	fixed        string          // fixed version: language ecosystem = the CPE fixed version; distro = MIN fixed EVR
	distro       bool            // an OS-package (rpm) binding: range-based distro semantics, not exact versions
	lastAffected string          // versioned no-fix case: MAX known_affected EVR ⇒ bound "[0, lastAffected]"
	openAffected bool            // unversioned binary VEX product: authoritative affected state without a fix
}

// affected resolves the vulnerability's product bindings into advisory.AffectedPackage entries, grouped by
// (ecosystem, package). Each product_id is resolved TWO ways: the CPE bridge (language ecosystems, exact
// versions) and the PURL+relationship bridge (RedHat rpm, distro range semantics).
//
// The RedHat rpm model is arch × module-stream × platform, richer than the (ecosystem, package) key. To stay
// sound under the no-false-positive bar, three narrowings apply to the distro path:
//   - MODULAR AppStream packages (release "...module+el...") are SKIPPED entirely (resolveProductPURL returns
//     ok=false). A module's streams (nodejs:16 vs nodejs:20) are parallel version lines, not one linear range,
//     so a "[0, fixed)" range built from one stream would falsely flag another. Matching them soundly needs
//     modularity labels on both the feed and the SBOM; until then a module rpm is a miss, never a false hit.
//   - A no-fix known_affected group is bounded by the MAX observed affected EVR (last_affected, inclusive),
//     not an open "[0, ∞)" range, so a later unaffected build is not swept in.
//   - A (major, package) that ALSO appears in known_not_affected is DROPPED: it means the CVE is arch- or
//     variant-specific for that package, which the arch-less key cannot represent, so emitting any range would
//     risk flagging the not-affected arch. Dropping is a miss on that (rare) package, never a false positive.
//
// Deterministic (sorted).
func (v csafVulnDoc) affected(cpeByProduct, purlByProduct, nameByProduct map[string]string, rels map[string]csafRel, allowUnboundedRPM bool) []advisory.AffectedPackage {
	groups := map[string]*affectedAccum{}
	key := func(eco, pkg string) string { return eco + "\x00" + pkg }
	getGroup := func(eco, pkg string, distro bool) *affectedAccum {
		g := groups[key(eco, pkg)]
		if g == nil {
			g = &affectedAccum{ecosystem: eco, pkg: pkg, versions: map[string]bool{}, distro: distro}
			groups[key(eco, pkg)] = g
		}
		return g
	}
	// Package-level matching cannot preserve architecture or repository variants. Any explicit negative for a
	// resolved binary package therefore removes that coarse package binding rather than risking a false positive.
	notAffected := map[string]bool{}
	for _, pid := range v.ProductStatus.KnownNotAffected {
		if binding, ok := resolveRPMProduct(purlByProduct, cpeByProduct, nameByProduct, rels, pid); ok {
			notAffected[key(binding.ecosystem, binding.pkg)] = true
		}
	}
	// A fixed state without a usable EVR still proves that an unbounded affected range is stale, but it cannot
	// supply a sound replacement boundary. Drop that package binding rather than preserving the open range.
	blockedFixed := map[string]bool{}

	for _, pid := range v.ProductStatus.KnownAffected {
		if eco, pkg, ver, ok := resolveProductCPE(cpeByProduct, pid); ok {
			g := getGroup(eco, pkg, false)
			switch ver {
			case "*":
				g.allVersions = true // CPE version ANY ⇒ all versions affected
			case "-", "":
				// NA / unspecified version: the package is named but no version signal – record the group so a
				// fixed version can still attach, but it contributes no match on its own.
			default:
				g.versions[ver] = true
			}
			continue
		}
		if binding, ok := resolveRPMProduct(purlByProduct, cpeByProduct, nameByProduct, rels, pid); ok {
			switch binding.kind {
			case rpmProductOpen:
				// Red Hat's binary-aware VEX deliberately omits the version for an affected binary product when no
				// fixed package version exists. Only a complete source snapshot can safely project that as open.
				if allowUnboundedRPM {
					getGroup(binding.ecosystem, binding.pkg, true).openAffected = true
				}
			case rpmProductBounded:
				// A concrete known-affected EVR is bounded inclusively so a later, unevaluated build is not swept in.
				g := getGroup(binding.ecosystem, binding.pkg, true)
				if g.lastAffected == "" || rpmLess(g.ecosystem, g.lastAffected, binding.evr) {
					g.lastAffected = binding.evr
				}
			case rpmProductUnsupportedVersion:
				// The relationship names a binary package, but its EVR cannot be reconciled with the platform. It
				// contributes no range.
			}
			continue
		}
		if eco, pkg, ver, ok := resolveLanguagePURL(purlByProduct, pid); ok {
			// A language-ecosystem product (npm/PyPI/Maven/Go/…) named by PURL contributes an explicit affected
			// version, exactly like a CPE-resolved one. GitHub and other CSAF exports key affected products by
			// PURL rather than CPE, so this is the path most of their advisories match on.
			getGroup(eco, pkg, false).versions[ver] = true
		}
	}
	for _, pid := range v.fixedProductIDs() {
		if eco, pkg, ver, ok := resolveProductCPE(cpeByProduct, pid); ok {
			if ver == "" || ver == "*" || ver == "-" {
				continue
			}
			if g := groups[key(eco, pkg)]; g != nil && g.fixed == "" {
				g.fixed = ver
			}
			continue
		}
		if binding, ok := resolveRPMProduct(purlByProduct, cpeByProduct, nameByProduct, rels, pid); ok {
			if binding.kind != rpmProductBounded {
				blockedFixed[key(binding.ecosystem, binding.pkg)] = true
				continue
			}
			g := getGroup(binding.ecosystem, binding.pkg, true) // a fixed-only product means "[0, fixed) affected"
			// Keep the MINIMUM fixed EVR. Distinct supported variants can carry different fixes; the minimum
			// yields the narrowest range, so a component at or above it is never falsely flagged.
			if g.fixed == "" || rpmLess(g.ecosystem, binding.evr, g.fixed) {
				g.fixed = binding.evr
			}
			continue
		}
		if eco, pkg, ver, ok := resolveLanguagePURL(purlByProduct, pid); ok {
			// The fixed version of a language-ecosystem product named by PURL (mirrors the CPE fixed path).
			if g := groups[key(eco, pkg)]; g != nil && g.fixed == "" {
				g.fixed = ver
			}
		}
	}

	out := make([]advisory.AffectedPackage, 0, len(groups))
	for _, g := range groups {
		groupKey := key(g.ecosystem, g.pkg)
		majorKey := key(rhelMajorEcosystem(g.ecosystem), g.pkg)
		if g.distro && (notAffected[groupKey] || notAffected[majorKey] || blockedFixed[groupKey] || blockedFixed[majorKey]) {
			continue
		}
		ap := advisory.AffectedPackage{Ecosystem: g.ecosystem, Package: g.pkg, FixedVersion: g.fixed}
		switch {
		case g.distro:
			// Distro semantics are range-based. A usable fix closes the range exclusively. Otherwise an
			// authoritative unversioned binary product is open; a concrete affected EVR remains bounded.
			switch {
			case g.fixed != "":
				ap.Ranges = []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: g.fixed}}}}
			case g.openAffected:
				ap.Ranges = []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}}}}
			case g.lastAffected != "":
				ap.Ranges = []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {LastAffected: g.lastAffected}}}}
			}
		case g.allVersions:
			// A language "all versions" CPE (version "*"): open range closed by the fixed version, if any.
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
		// Drop a binding that carries no match signal at all (no versions, no range) – it is inert.
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

// rpmLess reports whether EVR a orders strictly before b under the ecosystem's rpm comparator. A version the
// comparator cannot parse is treated as NOT-less (fail closed: the incumbent extreme is kept rather than
// replaced by an unorderable value).
func rpmLess(ecosystem, a, b string) bool {
	c, ok := advisory.CompareVersions(ecosystem, a, b)
	return ok && c < 0
}

// resolveProductCPE looks up a product_id's CPE and runs the conservative ecosystem bridge.
func resolveProductCPE(cpeByProduct map[string]string, productID string) (eco, pkg, version string, ok bool) {
	cpe, found := cpeByProduct[productID]
	if !found {
		return "", "", "", false
	}
	return cpeToEcosystem(cpe)
}

// resolveProductPURL resolves a COMPOSITE product_id (a RedHat default_component_of relationship) to the
// release-versioned RPM ecosystem key. It joins the package's PURL (name + EVR) with the platform's CPE
// (RHEL major): composite → (pkgRef, platformRef) → ("Red Hat:<major>", <name>, <evr>). It maps ONLY when
// the package is a pkg:rpm PURL AND the platform CPE is redhat:enterprise_linux; anything else returns
// ok=false → the binding is skipped (never mis-keyed). The "version" it returns is the full EVR, matched by
// the rpm comparator via advisory.schemeFor("Red Hat:<major>"). This is the ONLY sound way to reach the RH
// major, which lives on the platform product, not the package product.
type rpmProductKind uint8

const (
	rpmProductOpen rpmProductKind = iota + 1
	rpmProductBounded
	rpmProductUnsupportedVersion
)

type rpmProductBinding struct {
	ecosystem string
	pkg       string
	evr       string
	kind      rpmProductKind
}

func resolveRPMProduct(purlByProduct, cpeByProduct, nameByProduct map[string]string, rels map[string]csafRel, productID string) (rpmProductBinding, bool) {
	rel, found := rels[productID]
	if !found {
		return rpmProductBinding{}, false // only relationship-bound composites carry both package and platform
	}
	major, ok := rhelMajorFromCPE(cpeByProduct[rel.platformRef])
	if !ok {
		return rpmProductBinding{}, false
	}
	name, evr, kind, ok := redHatRPMPurl(rel.pkgRef, purlByProduct[rel.pkgRef])
	if !ok {
		return rpmProductBinding{}, false
	}
	ecosystem, soundOpenScope := rhelPlatformEcosystem(major, rel.platformRef, nameByProduct[rel.platformRef])
	if kind == rpmProductOpen && !soundOpenScope {
		// An unbounded range cannot be reduced to the RHEL major when the platform product is neither an exact
		// minor release nor an explicit major-wide product.
		kind = rpmProductUnsupportedVersion
	}
	if kind == rpmProductOpen && modularPlatformScope(cpeByProduct[rel.platformRef], rel.platformRef, nameByProduct[rel.platformRef]) {
		// Defence in depth for the open path. A bounded product is screened for modularity by its EVR
		// (isModularEVR below), but an unversioned product has no EVR, so the package id is otherwise the
		// only signal. If the platform side instead carries the module or AppStream marker, the range would
		// span parallel stream version lines, so refuse it rather than trust the id alone.
		kind = rpmProductUnsupportedVersion
	}
	if kind == rpmProductBounded && (isModularEVR(evr) || !rpmEVRMatchesRHELMajor(evr, major)) {
		// A module is a parallel version line. A tagless or mismatched EVR does not prove a bound for the
		// platform named by the relationship. Preserve the package identity so a fixed status can suppress a
		// competing open range, but never use this EVR as a boundary.
		kind = rpmProductUnsupportedVersion
	}
	return rpmProductBinding{ecosystem: ecosystem, pkg: name, evr: evr, kind: kind}, true
}

func redHatRPMPurl(productID, purl string) (name, evr string, kind rpmProductKind, ok bool) {
	const prefix = "pkg:rpm/redhat/"
	if !strings.HasPrefix(purl, prefix) {
		return "", "", 0, false
	}
	rest := purl[len(prefix):]
	path := rest
	if q := strings.IndexByte(path, '?'); q >= 0 {
		path = path[:q]
	}
	namePart := path
	versionPart := ""
	if at := strings.IndexByte(path, '@'); at >= 0 {
		namePart = path[:at]
		versionPart = path[at+1:]
		if versionPart == "" {
			return "", "", 0, false
		}
	}
	if strings.Contains(namePart, "/") {
		return "", "", 0, false
	}
	name = strings.TrimSpace(decodePURLSegment(namePart))
	arch := strings.TrimSpace(decodePURLSegment(purlQualifier(purl, "arch")))
	upstream := strings.TrimSpace(decodePURLSegment(purlQualifier(purl, "upstream")))
	if name == "" || strings.EqualFold(arch, "src") {
		// A source product is explicitly arch=src and never describes an installed binary.
		return "", "", 0, false
	}
	if arch == "" && upstream == "" && !redHatBinaryProductID(productID) {
		// Without an architecture or upstream qualifier the product_id is the only remaining proof that the
		// name is an installable binary rather than a source or modular identity.
		return "", "", 0, false
	}
	if versionPart == "" {
		return name, "", rpmProductOpen, true
	}
	versionPart = strings.TrimSpace(decodePURLSegment(versionPart))
	if versionPart == "" {
		return "", "", 0, false
	}
	return name, rpmCanonicalEVR(versionPart, decodePURLSegment(purlQualifier(purl, "epoch"))), rpmProductBounded, true
}

// modularPlatformScope reports whether a platform product describes a module stream or an AppStream-scoped
// variant rather than a plain RHEL release.
//
// This guards the unversioned (open-range) path only. A versioned product is screened by its EVR, which carries
// a ".module+el" marker, but an unversioned product has no EVR to inspect. Red Hat currently states modularity
// on the package id, so this is a second, independent signal rather than the primary one: if the module or
// stream identity is expressed on the platform side, an open range built from it would span parallel version
// lines and could report a flaw in one stream against an installed build of another.
//
// The CPE is checked beyond its major component, because a plain release CPE ("cpe:/o:redhat:enterprise_linux:9")
// carries nothing after the version, while an AppStream- or module-scoped one appends further components.
func modularPlatformScope(cpe, productID, productName string) bool {
	for _, label := range []string{productID, productName} {
		value := strings.ToLower(strings.TrimSpace(label))
		if strings.Contains(value, "module") || strings.Contains(value, "appstream") {
			return true
		}
	}
	value := strings.ToLower(strings.TrimSpace(cpe))
	for _, prefix := range []string{"cpe:/", "cpe:2.3:"} {
		value = strings.TrimPrefix(value, prefix)
	}
	parts := strings.Split(value, ":")
	if len(parts) < 4 {
		return false // not a resolvable platform CPE; rhelMajorFromCPE already rejected those
	}
	for _, component := range parts[4:] {
		if strings.TrimSpace(component) != "" {
			// Extra qualification beyond vendor:product:version, e.g. an appstream or module scope.
			return true
		}
	}
	return false
}

// redHatBinaryProductID reports whether a package product_id names an installable binary RPM, for the
// unversioned products Red Hat emits when a CVE has no fixed package version. Those products carry no arch or
// upstream qualifier, so the id is the only available discriminator, and Red Hat states the two identities it
// must exclude explicitly:
//   - a source product ends in ".src" (and also carries arch=src, rejected before this call);
//   - a modular product embeds its stream as "<name>::<module>:<stream>", a parallel version line that the
//     linear range matcher cannot represent soundly.
//
// Anything else is a plain binary name. This admits the not-yet-fixed evidence while keeping both excluded
// identities out, so a miss stays a miss and never becomes a cross-identity false positive.
func redHatBinaryProductID(productID string) bool {
	value := strings.TrimSpace(productID)
	if value == "" {
		return false
	}
	if strings.ContainsRune(value, ':') {
		// A colon cannot appear in an RPM package name: it delimits the epoch in NEVRA. So a colon is
		// positive evidence that the id carries extra structure rather than naming a binary, which is what
		// a modular stream ("<name>::<module>:<stream>") does. Refusing every colon rather than only the
		// "::" pair keeps a single-colon or otherwise-shaped stream marker out too, instead of relying on
		// Red Hat continuing to use exactly the doubled form.
		return false
	}
	if strings.HasSuffix(strings.ToLower(value), ".src") {
		return false // source identity
	}
	return true
}

func rhelPlatformEcosystem(major, productID, productName string) (string, bool) {
	majorEcosystem := "Red Hat:" + major
	idMinor, idFound, idAmbiguous := rhelMinorFromPlatformLabel(productID, major)
	nameMinor, nameFound, nameAmbiguous := rhelMinorFromPlatformLabel(productName, major)
	if idAmbiguous || nameAmbiguous || (idFound && nameFound && idMinor != nameMinor) {
		return majorEcosystem, false
	}
	minor := idMinor
	if !idFound {
		minor = nameMinor
	}
	if idFound || nameFound {
		return majorEcosystem + "." + minor, true
	}
	if rhelMajorWidePlatform(productID, major) || rhelMajorWidePlatform(productName, major) {
		return majorEcosystem, true
	}
	return majorEcosystem, false
}

func rhelMinorFromPlatformLabel(label, major string) (minor string, found, ambiguous bool) {
	value := strings.ToLower(strings.TrimSpace(label))
	needle := major + "."
	for offset := 0; offset < len(value); {
		rel := strings.Index(value[offset:], needle)
		if rel < 0 {
			break
		}
		start := offset + rel
		if start > 0 && value[start-1] >= '0' && value[start-1] <= '9' {
			offset = start + len(needle)
			continue
		}
		digitStart := start + len(needle)
		end := digitStart
		for end < len(value) && value[end] >= '0' && value[end] <= '9' {
			end++
		}
		if end == digitStart {
			offset = digitStart
			continue
		}
		candidate := value[digitStart:end]
		if found && candidate != minor {
			return "", false, true
		}
		minor, found = candidate, true
		offset = end
	}
	return minor, found, false
}

func rhelMajorEcosystem(ecosystem string) string {
	const prefix = "Red Hat:"
	if !strings.HasPrefix(ecosystem, prefix) {
		return ecosystem
	}
	release := strings.TrimPrefix(ecosystem, prefix)
	if major, _, ok := strings.Cut(release, "."); ok && major != "" {
		return prefix + major
	}
	return ecosystem
}

func rhelMajorWidePlatform(label, major string) bool {
	value := strings.ToLower(strings.TrimSpace(label))
	for _, candidate := range []string{
		"rhel" + major,
		"rhel-" + major,
		"rhel_" + major,
		"rhel " + major,
		"red_hat_enterprise_linux_" + major,
		"red hat enterprise linux " + major,
	} {
		if value == candidate {
			return true
		}
	}
	return false
}

func rpmEVRMatchesRHELMajor(evr, major string) bool {
	if !allASCIIDigits(major) {
		return false
	}
	value := strings.ToLower(strings.TrimSpace(evr))
	matches := 0
	for offset := 0; offset < len(value); {
		rel := strings.Index(value[offset:], ".el")
		if rel < 0 {
			break
		}
		start := offset + rel + len(".el")
		end := start
		for end < len(value) && value[end] >= '0' && value[end] <= '9' {
			end++
		}
		if end == start || (end < len(value) && !strings.ContainsRune("._+~-", rune(value[end]))) {
			return false
		}
		matches++
		if value[start:end] != major {
			return false
		}
		offset = end
	}
	return matches == 1
}

// isModularEVR reports whether an rpm EVR is an AppStream module build, whose release carries a
// "module+el" / "module_el" marker (the '+' arrives decoded from the PURL's %2B). Module streams coexist as
// independent version lines, so they are excluded from the linear-range distro matcher.
func isModularEVR(evr string) bool {
	return strings.Contains(evr, ".module+el") || strings.Contains(evr, ".module_el") ||
		strings.Contains(evr, ".module+") // defensive: any "module+" release marker
}

// rpmPurlNameEVR extracts the package name and a canonical EVR from a RedHat rpm PURL
// ("pkg:rpm/redhat/<name>@<version>?arch=...&epoch=N"). RedHat (and Syft) carry the epoch in an "epoch="
// qualifier, not in the version, so the EVR is rebuilt as "epoch:version-release" via rpmCanonicalEVR — the
// SAME normalization the scan side applies to a component PURL, so the two compare on identical strings. The
// name is the path segment after the "redhat" namespace.
//
// The version is PERCENT-DECODED (per the PURL spec): a modular-stream build encodes the '+' in
// "...module+el8.9.0+..." as "%2B" and the epoch colon as "%3A", so the decoded EVR ("...module+el8...")
// matches the DECODED version the SBOM/scan side carries. Skipping this decode would leave "%2B" literal on
// the feed side while the component carries "+", and the rpm comparator would order them differently — a
// patched module build could then compare BELOW the fix and be flagged (a false positive). Decoding both
// sides removes that hazard. A version url.PathUnescape cannot decode (malformed '%') is kept verbatim
// (fail-safe: never fabricate a version). Returns ok=false for a non-rpm or malformed PURL so the binding is
// skipped rather than mis-parsed.
func rpmPurlNameEVR(purl string) (name, evr string, ok bool) {
	const prefix = "pkg:rpm/"
	if !strings.HasPrefix(purl, prefix) {
		return "", "", false
	}
	rest := purl[len(prefix):]
	at := strings.IndexByte(rest, '@')
	if at < 0 {
		return "", "", false // no version component: cannot bound a range
	}
	namePath := rest[:at]
	verPart := rest[at+1:]
	if q := strings.IndexByte(verPart, '?'); q >= 0 {
		verPart = verPart[:q]
	}
	// The PURL name is the last '/'-separated segment (drops the "redhat" namespace, and any subpath).
	if slash := strings.LastIndexByte(namePath, '/'); slash >= 0 {
		name = namePath[slash+1:]
	} else {
		name = namePath
	}
	name = decodePURLSegment(name)
	verPart = decodePURLSegment(verPart)
	name = strings.TrimSpace(name)
	verPart = strings.TrimSpace(verPart)
	if name == "" || verPart == "" {
		return "", "", false
	}
	return name, rpmCanonicalEVR(verPart, decodePURLSegment(purlQualifier(purl, "epoch"))), true
}

// decodePURLSegment percent-decodes a PURL name/version/qualifier segment (per the PURL spec), so an encoded
// '+' (%2B) in a module-stream build or ':' (%3A) in an epoch matches the decoded form the scan side carries.
// A segment that is not valid percent-encoding is returned verbatim (fail-safe, never fabricated).
func decodePURLSegment(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	if decoded, err := url.PathUnescape(s); err == nil {
		return decoded
	}
	return s
}

// rhelMajorFromCPE extracts the RHEL major version from a RedHat platform CPE, accepting BOTH the CPE 2.2
// URI form RedHat CSAF uses ("cpe:/o:redhat:enterprise_linux:9::baseos") and the 2.3 formatted string
// ("cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*"). After stripping the prefix both share the
// layout part:vendor:product:version, so it requires vendor "redhat" and product "enterprise_linux" and
// returns the major (the version up to the first '.'). Any other RedHat product (openshift, ansible, …) or a
// missing version returns ok=false → the binding is skipped, so only RHEL, which the rpm feed is scoped to,
// is keyed.
func rhelMajorFromCPE(cpe string) (major string, ok bool) {
	s := strings.TrimSpace(cpe)
	switch {
	case strings.HasPrefix(s, "cpe:2.3:"):
		s = s[len("cpe:2.3:"):]
	case strings.HasPrefix(s, "cpe:/"):
		s = s[len("cpe:/"):]
	default:
		return "", false
	}
	parts := strings.Split(s, ":")
	if len(parts) < 4 {
		return "", false
	}
	vendor, product, version := parts[1], parts[2], parts[3]
	if vendor != "redhat" || product != "enterprise_linux" || version == "" {
		return "", false
	}
	if dot := strings.IndexByte(version, '.'); dot >= 0 {
		version = version[:dot]
	}
	if version == "" || !allASCIIDigits(version) {
		return "", false // a non-numeric major (e.g. "*") is not a concrete platform
	}
	return version, true
}

// allASCIIDigits reports whether s is non-empty and every byte is 0-9.
func allASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
