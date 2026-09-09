package ownadvisory

import (
	"encoding/json"
	"fmt"
	"net/url"
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
	purlByProduct := doc.ProductTree.purlByProductID()
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
			Affected: v.affected(cpeByProduct, purlByProduct, rels),
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
	ecosystem   string
	pkg         string
	versions     map[string]bool // explicit concrete affected versions (from each known_affected CPE)
	allVersions  bool            // a known_affected CPE with version "*" ⇒ every version is affected
	fixed        string          // fixed version: language ecosystem = the CPE fixed version; distro = MIN fixed EVR
	distro       bool            // an OS-package (rpm) binding: range-based distro semantics, not exact versions
	lastAffected string          // distro no-fix case: MAX known_affected EVR ⇒ bound "[0, lastAffected]" (not open)
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
func (v csafVulnDoc) affected(cpeByProduct, purlByProduct map[string]string, rels map[string]csafRel) []advisory.AffectedPackage {
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
	// (major, package) keys that RedHat marks known_not_affected via the rpm bridge: the distro group for such
	// a key is dropped at emit time (arch/variant ambiguity the arch-less key cannot resolve soundly).
	notAffected := map[string]bool{}
	for _, pid := range v.ProductStatus.KnownNotAffected {
		if eco, pkg, _, ok := resolveProductPURL(purlByProduct, cpeByProduct, rels, pid); ok {
			notAffected[key(eco, pkg)] = true
		}
	}

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
		if eco, pkg, evr, ok := resolveProductPURL(purlByProduct, cpeByProduct, rels, pid); ok {
			// A distro package RedHat lists as known_affected with no fix ⇒ affected up to this build. Bound the
			// range by the MAX observed affected EVR (last_affected, inclusive) rather than an open range, so a
			// higher, not-yet-evaluated build is not swept in.
			g := getGroup(eco, pkg, true)
			if g.lastAffected == "" || rpmLess(g.ecosystem, g.lastAffected, evr) {
				g.lastAffected = evr
			}
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
		if eco, pkg, evr, ok := resolveProductPURL(purlByProduct, cpeByProduct, rels, pid); ok {
			g := getGroup(eco, pkg, true) // a fixed-only distro product still means "[0, fixed) affected"
			// Keep the MINIMUM fixed EVR. Even with modules skipped, distinct variants of the same base package
			// can carry different fixes; the minimum yields the narrowest affected range, so a component at or
			// above it is never falsely flagged (the trade is a possible miss, the safe direction).
			if g.fixed == "" || rpmLess(g.ecosystem, evr, g.fixed) {
				g.fixed = evr
			}
		}
	}

	out := make([]advisory.AffectedPackage, 0, len(groups))
	for _, g := range groups {
		if g.distro && notAffected[key(g.ecosystem, g.pkg)] {
			continue // arch/variant-specific: cannot bound soundly with an arch-less key → drop (miss, not FP)
		}
		ap := advisory.AffectedPackage{Ecosystem: g.ecosystem, Package: g.pkg, FixedVersion: g.fixed}
		switch {
		case g.distro:
			// Distro semantics are range-based. A fix closes the range exclusively ("[0, fixed)"); with no fix
			// the range is bounded inclusively by the highest observed affected build ("[0, lastAffected]").
			// The ecosystem key is exact (RHEL major from the platform CPE), so the range can only match
			// versions of the RIGHT package in the RIGHT release.
			switch {
			case g.fixed != "":
				ap.Ranges = []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: g.fixed}}}}
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
func resolveProductPURL(purlByProduct, cpeByProduct map[string]string, rels map[string]csafRel, productID string) (eco, pkg, evr string, ok bool) {
	rel, found := rels[productID]
	if !found {
		return "", "", "", false // only relationship-bound composites carry both the package and the platform
	}
	name, version, okPurl := rpmPurlNameEVR(purlByProduct[rel.pkgRef])
	if !okPurl {
		return "", "", "", false
	}
	if isModularEVR(version) {
		// AppStream module build: its stream is a parallel version line, not a point on one linear range, so a
		// "[0, fixed)" range would falsely flag another stream. Skip until stream-aware matching exists (miss,
		// never a false positive).
		return "", "", "", false
	}
	major, okMajor := rhelMajorFromCPE(cpeByProduct[rel.platformRef])
	if !okMajor {
		return "", "", "", false
	}
	return "Red Hat:" + major, name, version, true
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
