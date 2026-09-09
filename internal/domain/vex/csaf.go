package vex

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// CSAF-VEX (OASIS CSAF 2.0, VEX profile) is the second machine-readable VEX format Synapse CONSUMES, next to
// OpenVEX. A supplier ships a CSAF document whose `vulnerabilities[].product_status` buckets each product id
// as affected / not_affected / fixed / under_investigation, resolves those ids through a `product_tree`, and
// (for not_affected) carries the reason in `flags[].label`. ParseCSAF maps that onto the SAME
// Document/Statement shape as OpenVEX Parse, so the downstream suppress + match core (Statement.Suppresses,
// Statement.MatchesFinding) is reused unchanged and the two formats can never drift.
//
// The five CSAF flag labels are identical strings to the five OpenVexJustification values, so a not_affected
// justification carries across formats with no translation table.
//
// The consumers (post-scan Apply and the in-scan .synapse.vex.json loader) suppress a finding on ANY
// matching suppressing statement and never un-suppress, so this parser is deliberately fail-safe:
//
//   - It rejects a document that could hide a real finding: a duplicate product-id definition, a product
//     with contradictory status (keyed by the MATCH TARGET a statement resolves to — the same identity
//     Statement.MatchesFinding uses — so two different ids resolving to one component are still caught), or
//     a reference to an undefined product.
//   - It never emits a SUPPRESSING statement for a product it cannot machine-identify: only a PURL-resolved
//     product suppresses; a free-text-name-only product, an environment-scoped (installed_on/installed_with)
//     relationship, and a malformed or self/cyclic relationship all stay unmatchable, so a statement about
//     one is skipped rather than hiding the bare component.
type csafWire struct {
	Document struct {
		Category    string `json:"category"`
		CSAFVersion string `json:"csaf_version"`
	} `json:"document"`
	ProductTree     csafProductTree `json:"product_tree"`
	Vulnerabilities []csafVuln      `json:"vulnerabilities"`
}

type csafProductTree struct {
	Branches         []csafBranch       `json:"branches"`
	FullProductNames []csafFullProduct  `json:"full_product_names"`
	Relationships    []csafRelationship `json:"relationships"`
	ProductGroups    []csafProductGroup `json:"product_groups"`
}

type csafProductGroup struct {
	GroupID    string   `json:"group_id"`
	ProductIDs []string `json:"product_ids"`
}

type csafBranch struct {
	Category string           `json:"category"`
	Name     string           `json:"name"`
	Branches []csafBranch     `json:"branches"`
	Product  *csafFullProduct `json:"product"`
}

type csafFullProduct struct {
	ProductID string `json:"product_id"`
	Name      string `json:"name"`
	Helper    struct {
		PURL string `json:"purl"`
	} `json:"product_identification_helper"`
}

type csafRelationship struct {
	Category                  string          `json:"category"`
	FullProductName           csafFullProduct `json:"full_product_name"`
	ProductReference          string          `json:"product_reference"`
	RelatesToProductReference string          `json:"relates_to_product_reference"`
}

type csafVuln struct {
	CVE string `json:"cve"`
	IDs []struct {
		SystemName string `json:"system_name"`
		Text       string `json:"text"`
	} `json:"ids"`
	// product_status carries the full CSAF bucket set. The affected variants (known/first/last_affected)
	// all mean "affected"; the fixed variants (fixed/first_fixed) all mean "fixed" — folding them into an
	// effective status is what makes the contradiction check see e.g. known_not_affected vs first_affected.
	ProductStatus struct {
		KnownAffected      []string `json:"known_affected"`
		FirstAffected      []string `json:"first_affected"`
		LastAffected       []string `json:"last_affected"`
		KnownNotAffected   []string `json:"known_not_affected"`
		Fixed              []string `json:"fixed"`
		FirstFixed         []string `json:"first_fixed"`
		UnderInvestigation []string `json:"under_investigation"`
	} `json:"product_status"`
	Flags []struct {
		Label      string   `json:"label"`
		ProductIDs []string `json:"product_ids"`
		GroupIDs   []string `json:"group_ids"`
	} `json:"flags"`
}

// csafProductIndex is the resolved product_tree. `resolved` holds the component string for every product id
// with a resolution; `viaPURL` marks the ones resolved from a PURL (the only ones allowed to carry a
// SUPPRESSING statement); `defined` is the superset of every declared product id (including ids left
// unresolved). The split lets ParseCSAF reject a dangling product_status reference (an undefined id) while
// fail-safe SKIPPING a defined-but-unmatchable one, never suppressing what it cannot machine-identify.
type csafProductIndex struct {
	resolved map[string]string
	viaPURL  map[string]bool
	defined  map[string]bool
	groups   map[string][]string
}

// csafBucket is one product_status group folded to its effective VEX status.
type csafBucket struct {
	ids    []string
	status string
}

// statusBuckets folds a vulnerability's product_status into effective-status groups. The affected variants
// collapse to "affected" and the fixed variants to "fixed", so a product listed under two variants of the
// SAME effective status is consistent, while a product listed as both not_affected and affected (via any
// variant) is caught as a contradiction. `recommended` is intentionally omitted: it names a remediation
// target, not an exploitability status, and never suppresses.
func (v csafVuln) statusBuckets() []csafBucket {
	return []csafBucket{
		{v.ProductStatus.KnownNotAffected, "not_affected"},
		{v.ProductStatus.Fixed, "fixed"},
		{v.ProductStatus.FirstFixed, "fixed"},
		{v.ProductStatus.KnownAffected, "affected"},
		{v.ProductStatus.FirstAffected, "affected"},
		{v.ProductStatus.LastAffected, "affected"},
		{v.ProductStatus.UnderInvestigation, "under_investigation"},
	}
}

func csafStatusSuppresses(status string) bool {
	return status == "not_affected" || status == "fixed"
}

// emitComponent decides whether a (product id, effective status) becomes a Statement and, if so, the
// component string it matches on. A product with no resolution is skipped; a SUPPRESSING status is emitted
// only for a PURL-resolved product, so a free-text-name-only product can never hide a finding. Pass 1
// (validation) and pass 2 (emission) both call this, so they consider exactly the same statement set.
func (idx csafProductIndex) emitComponent(pid, status string) (string, bool) {
	comp := idx.resolved[pid]
	if comp == "" {
		return "", false
	}
	if csafStatusSuppresses(status) && !idx.viaPURL[pid] {
		return "", false
	}
	return comp, true
}

// vulnProduct keys a (vulnerability, product id) pair; emitKey dedups an emitted statement.
type vulnProduct struct{ vuln, pid string }
type emitKey struct{ vuln, comp, status string }

// csafMatchEntry is the finding set one emitted statement covers: `set` is exactly the components
// Statement.MatchesFinding accepts for this product (its raw component AND that component's purlName, since
// componentMatches allows either), and `version` is its version bound ("" = every version). Modeling the
// FULL set — not a single collapsed name — is what makes the contradiction check agree with the matcher: a
// name-only product "@safe/lodash" matches the scoped finding by exact equality even though its purlName
// collapses to "lodash", so it must still be seen to collide with a scoped-PURL suppression.
type csafMatchEntry struct {
	set     map[string]bool
	version string
}

// ParseCSAF decodes a CSAF 2.x document into the shared VEX Document. It errors on invalid JSON, a non-CSAF
// document, a duplicate product-id definition, a contradictory status (within a vulnerability or across two
// entries for the same CVE, at the resolved match-target level), or a reference to an undefined product, so
// a caller never treats junk or a self-contradicting assertion as a suppression policy. Each emit-eligible
// product_status id becomes one Statement.
func ParseCSAF(data []byte) (Document, error) {
	var w csafWire
	if err := json.Unmarshal(data, &w); err != nil {
		return Document{}, fmt.Errorf("%w: invalid CSAF document: %v", shared.ErrValidation, err)
	}
	if !strings.HasPrefix(strings.TrimSpace(w.Document.CSAFVersion), "2.") {
		return Document{}, fmt.Errorf("%w: not a CSAF 2.x document (document.csaf_version=%q)", shared.ErrValidation, w.Document.CSAFVersion)
	}
	idx, err := indexCSAFProducts(w.ProductTree)
	if err != nil {
		return Document{}, err
	}

	// Pass 1: validate the whole document before emitting anything. (a) every product_status reference must
	// be defined; (b) one product id may hold only one effective status (CSAF mandatory test 6.1.2), keyed
	// per (vuln, id) so it holds regardless of resolvability; (c) at the MATCH-TARGET level, no suppressing
	// and non-suppressing statement of one vulnerability may match a common finding — checked with each
	// statement's FULL match set (component + its purlName), exactly what Statement.MatchesFinding accepts,
	// so a collision through either match path (two ids resolving to one component, a scoped PURL vs a
	// name-only "@scope/name", a wildcard version vs a concrete one) is caught. A bad document is rejected
	// whole, so a suppress-on-any-match consumer can never be handed a contradiction to resolve by accident.
	perID := make(map[vulnProduct]string)
	suppressEntries := make(map[string][]csafMatchEntry)
	openEntries := make(map[string][]csafMatchEntry)
	sawStatus := false
	for _, v := range w.Vulnerabilities {
		id := csafVulnID(v)
		if id == "" {
			continue
		}
		for _, b := range v.statusBuckets() {
			for _, pid := range b.ids {
				sawStatus = true
				if !idx.defined[pid] {
					return Document{}, fmt.Errorf("%w: CSAF references undefined product %q for %s", shared.ErrValidation, pid, id)
				}
				if prev, ok := perID[vulnProduct{id, pid}]; ok && prev != b.status {
					return Document{}, fmt.Errorf("%w: CSAF product %q has contradictory status %q and %q for %s", shared.ErrValidation, pid, prev, b.status, id)
				}
				perID[vulnProduct{id, pid}] = b.status
				comp, ok := idx.emitComponent(pid, b.status)
				if !ok {
					continue
				}
				e := matchEntryOf(comp)
				if csafStatusSuppresses(b.status) {
					suppressEntries[id] = append(suppressEntries[id], e)
				} else {
					openEntries[id] = append(openEntries[id], e)
				}
			}
		}
	}
	if !sawStatus {
		return Document{}, fmt.Errorf("%w: CSAF document carries no VEX product statements", shared.ErrValidation)
	}
	for id, sup := range suppressEntries {
		for _, se := range sup {
			for _, oe := range openEntries[id] {
				if setsIntersect(se.set, oe.set) && versionsOverlap(se.version, oe.version) {
					return Document{}, fmt.Errorf("%w: CSAF vulnerability %s asserts a product both suppressed and affected", shared.ErrValidation, id)
				}
			}
		}
	}

	// Pass 2: emit. Validation passed. Deduplicate by (vuln, component, status) so a product listed under
	// two variants of one effective status (known_affected + first_affected) yields a single statement.
	doc := Document{Context: strings.TrimSpace(w.Document.Category)}
	emitted := make(map[emitKey]bool)
	for _, v := range w.Vulnerabilities {
		id := csafVulnID(v)
		if id == "" {
			continue
		}
		just := csafJustifications(v, idx)
		for _, b := range v.statusBuckets() {
			for _, pid := range b.ids {
				comp, ok := idx.emitComponent(pid, b.status)
				if !ok {
					continue
				}
				k := emitKey{id, comp, b.status}
				if emitted[k] {
					continue
				}
				emitted[k] = true
				st := Statement{Vulnerability: id, Status: b.status, Products: []string{comp}}
				if b.status == "not_affected" {
					st.Justification = just[pid]
				}
				doc.Statements = append(doc.Statements, st)
			}
		}
	}
	return doc, nil
}

// matchEntryOf builds the match set a product covers, mirroring Statement.MatchesFinding: it splits the
// version off, then the finding-component set is {component, purlName(component)} (componentMatches accepts
// either). This is the identity the contradiction check compares, so it can never disagree with the matcher.
func matchEntryOf(comp string) csafMatchEntry {
	name, ver := splitProduct(comp)
	return csafMatchEntry{set: map[string]bool{name: true, purlName(name): true}, version: ver}
}

// setsIntersect reports whether two component match sets share a member (a finding both products can match).
func setsIntersect(a, b map[string]bool) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	for k := range a {
		if b[k] {
			return true
		}
	}
	return false
}

// versionsOverlap reports whether a suppressing and a non-suppressing statement could match the same
// finding's version: an empty version is a wildcard (MatchesFinding matches every version), so it overlaps
// anything; otherwise the two must name the same concrete version.
func versionsOverlap(suppress, open string) bool {
	return suppress == "" || open == "" || suppress == open
}

// csafVulnID is the vulnerability identifier: the CVE when present, else the first `ids[]` text (a
// non-CVE tracking id, e.g. a GHSA). An empty id means the entry names no vulnerability to apply.
func csafVulnID(v csafVuln) string {
	if cve := strings.TrimSpace(v.CVE); cve != "" {
		return cve
	}
	for _, i := range v.IDs {
		if t := strings.TrimSpace(i.Text); t != "" {
			return t
		}
	}
	return ""
}

// csafJustifications maps each not_affected product id to its OpenVEX justification from the CSAF flags. A
// flag is scoped by product_ids and/or group_ids (resolved through product_groups); CSAF defines no unscoped
// "default" flag, so a flag carrying neither is ignored rather than blanket-applied. A per-product flag wins
// over a group flag. Justification is audit METADATA only: it does not gate suppression (a not_affected
// assertion is itself the suppression signal, matching the OpenVEX Parse path), so an unknown or absent
// label is dropped, not fatal.
func csafJustifications(v csafVuln, idx csafProductIndex) map[string]string {
	out := make(map[string]string)
	for _, f := range v.Flags {
		j := OpenVexJustification(strings.TrimSpace(f.Label))
		if !j.Valid() {
			continue
		}
		for _, gid := range f.GroupIDs {
			for _, pid := range idx.groups[gid] {
				if _, ok := out[pid]; !ok {
					out[pid] = string(j) // group members fill in, without overriding a per-product flag
				}
			}
		}
		for _, pid := range f.ProductIDs {
			out[pid] = string(j) // an explicit per-product flag wins
		}
	}
	return out
}

// indexCSAFProducts builds the product index from the product_tree. Every declared product id (direct,
// branch-nested, or a relationship's full_product_name id) is DEFINED, and a duplicate definition is
// rejected (a silent overwrite could point a suppression at the wrong component). Products are RESOLVED to a
// component string, tracking whether the resolution came from a PURL. Relationships are resolved by a fixed
// point, order-independent; only the component-of family resolves to its underlying component, and only when
// the component and container are distinct defined products (no self/degenerate cycle). installed_on /
// installed_with and any malformed relationship stay DEFINED but unresolved, so a statement about one is
// skipped, never suppressed.
func indexCSAFProducts(tree csafProductTree) (csafProductIndex, error) {
	idx := csafProductIndex{
		resolved: make(map[string]string),
		viaPURL:  make(map[string]bool),
		defined:  make(map[string]bool),
		groups:   make(map[string][]string),
	}
	define := func(id string) error {
		if id == "" {
			return nil
		}
		if idx.defined[id] {
			return fmt.Errorf("%w: CSAF defines product %q more than once", shared.ErrValidation, id)
		}
		idx.defined[id] = true
		return nil
	}
	add := func(fp csafFullProduct) error {
		if err := define(fp.ProductID); err != nil {
			return err
		}
		if fp.ProductID == "" {
			return nil
		}
		// Only a well-formed PURL is trusted as a machine identity that may carry a SUPPRESSING statement;
		// a malformed helper value like "lodash" would otherwise set viaPURL and suppress as a wildcard. The
		// stored value is the CLEANED coordinate (qualifiers and subpath removed), so the shared matcher's
		// splitProduct/purlName parse exactly the string validPURL validated — a crafted "?x=/%40s/leaf"
		// qualifier can no longer smuggle a fake scope/name past validation into the match target.
		if c := canonicalPURL(strings.TrimSpace(fp.Helper.PURL)); c != "" {
			idx.resolved[fp.ProductID] = c
			idx.viaPURL[fp.ProductID] = true
		} else if n := strings.TrimSpace(fp.Name); n != "" {
			idx.resolved[fp.ProductID] = n // name-only (or malformed purl): resolvable, but never suppresses
		}
		return nil
	}
	for _, fp := range tree.FullProductNames {
		if err := add(fp); err != nil {
			return csafProductIndex{}, err
		}
	}
	var walk func([]csafBranch) error
	walk = func(branches []csafBranch) error {
		for _, b := range branches {
			if b.Product != nil {
				if err := add(*b.Product); err != nil {
					return err
				}
			}
			if err := walk(b.Branches); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(tree.Branches); err != nil {
		return csafProductIndex{}, err
	}
	for _, rel := range tree.Relationships {
		if err := define(rel.FullProductName.ProductID); err != nil {
			return csafProductIndex{}, err
		}
	}

	cyclic := containerCyclicRelationships(tree.Relationships)

	// Fixed point: each pass only ADDS a resolution and skips a resolved id, so it converges in at most
	// len(relationships) passes. A component-of relationship resolves only when its component
	// (product_reference) and container (relates_to_product_reference) are BOTH defined and are distinct
	// from each other and from the relationship's own id — so a self-referential or degenerate relationship
	// (PID-REL component_of PID-REL) never resolves — and only when it does not lie on a container cycle, so
	// a mutually-nested relationship pair cannot resolve into a bare-component suppression either.
	for changed := true; changed; {
		changed = false
		for _, rel := range tree.Relationships {
			id := rel.FullProductName.ProductID
			if id == "" || !isComponentOfCategory(rel.Category) || cyclic[id] {
				continue
			}
			if _, done := idx.resolved[id]; done {
				continue
			}
			ref, rel2 := rel.ProductReference, rel.RelatesToProductReference
			if ref == "" || rel2 == "" || ref == id || rel2 == id || ref == rel2 {
				continue
			}
			if !idx.defined[ref] || !idx.defined[rel2] {
				continue
			}
			if s := idx.resolved[ref]; s != "" {
				idx.resolved[id] = s
				idx.viaPURL[id] = idx.viaPURL[ref]
				changed = true
			}
		}
	}

	for _, g := range tree.ProductGroups {
		if g.GroupID != "" {
			idx.groups[g.GroupID] = g.ProductIDs
		}
	}
	return idx, nil
}

// canonicalPURL parses s and returns its coordinate "pkg:type/namespace/name[@version]" with ?qualifiers and
// #subpath removed, or "" if s is not a well-formed package URL. Crucially, the RETURNED string is what the
// index stores and the shared matcher (splitProduct/purlName) later parses, so validation and matching can
// never disagree — a crafted qualifier/subpath or a stray "@" cannot smuggle a different name/version past
// validation into the match target. Rules: a non-empty letter-led type; every namespace/name segment
// non-empty (no "//" or trailing "/"); an OPTIONAL single trailing "@version" (non-empty, no "/"), and no
// other "@" in the name portion (a scope must be percent-encoded as %40, never a literal "@").
func canonicalPURL(s string) string {
	if !strings.HasPrefix(strings.ToLower(s), "pkg:") {
		return ""
	}
	body := cleanPURL(s)[len("pkg:"):]
	slash := strings.IndexByte(body, '/')
	if slash <= 0 { // empty type, or no type/name separator
		return ""
	}
	typ := body[:slash]
	if !validPURLType(typ) {
		return ""
	}
	nameVer := body[slash+1:]
	name, version := nameVer, ""
	if at := strings.LastIndexByte(nameVer, '@'); at >= 0 {
		name, version = nameVer[:at], nameVer[at+1:]
		if version == "" || strings.IndexByte(version, '/') >= 0 {
			return "" // empty version, or an "@" that was actually inside the name (not a version separator)
		}
	}
	if name == "" || strings.IndexByte(name, '@') >= 0 {
		return ""
	}
	for _, seg := range strings.Split(name, "/") {
		if strings.TrimSpace(seg) == "" {
			return ""
		}
	}
	// npm has only "name" or "@scope/name"; an arbitrary namespace ("notascope/lodash") or an empty scope
	// ("%40/lodash") is malformed and would collapse (via purlName) onto a DIFFERENT unscoped package, so a
	// non-conforming npm coordinate is not a trustworthy suppressing identity.
	if strings.EqualFold(typ, "npm") && !validNpmName(name) {
		return ""
	}
	out := "pkg:" + typ + "/" + name
	if version != "" {
		out += "@" + version
	}
	return out
}

// validPURL reports whether s is a well-formed package URL (see canonicalPURL). It is a shape check, not a
// registry lookup — enough to reject a free-text value masquerading as a machine identity, which would
// otherwise be trusted to carry a suppressing, finding-hiding statement.
func validPURL(s string) bool { return canonicalPURL(s) != "" }

// cleanPURL strips a PURL's ?qualifiers and #subpath, leaving only "pkg:type/namespace/name@version". The
// shared matcher (splitProduct/purlName) parses by the last "@" and "/", which a qualifier or subpath
// containing those bytes would otherwise corrupt; removing them up front keeps the stored match target equal
// to the coordinate validPURL validated.
func cleanPURL(s string) string {
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		return s[:i]
	}
	return s
}

// validPURLType checks the purl type token: letter-led, then letters/digits/. + -. This rejects an empty or
// whitespace type (e.g. "pkg: /lodash"), which is not a machine identity.
func validPURLType(t string) bool {
	if t == "" {
		return false
	}
	if c := t[0]; !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '+', c == '-':
		default:
			return false
		}
	}
	return true
}

// containerCyclicRelationships returns the set of relationship ids that lie on (or lead into) a cycle formed
// by container edges — a relationship whose relates_to_product_reference is itself another relationship, of
// ANY category. A component-of relationship marked here is left unresolved rather than resolved into a
// bare-component suppression. Over-marking a lead-in is fail-safe (a skipped suppression, never a wrong one).
func containerCyclicRelationships(rels []csafRelationship) map[string]bool {
	// Follow container edges through EVERY relationship, not only the component-of ones: a component-of
	// relationship whose container is an installed_on relationship that points back to it is still a cycle.
	relOf := make(map[string]csafRelationship, len(rels))
	for _, rel := range rels {
		id := rel.FullProductName.ProductID
		if id == "" {
			continue
		}
		if _, exists := relOf[id]; !exists {
			relOf[id] = rel
		}
	}
	cyclic := make(map[string]bool)
	for start := range relOf {
		seen := map[string]bool{start: true}
		cur := start
		for {
			rel, isRel := relOf[cur]
			if !isRel {
				break // container chain reached a base product: no cycle
			}
			next := rel.RelatesToProductReference
			if next == "" {
				break
			}
			if seen[next] {
				cyclic[start] = true
				break
			}
			seen[next] = true
			cur = next
		}
	}
	return cyclic
}

// validNpmName reports whether an npm coordinate name portion is a real npm package name: a single
// unscoped segment, or exactly "@scope/name" with a non-empty scope. Anything else (a non-scope namespace,
// an empty scope, deeper nesting) is not a valid npm identity.
func validNpmName(name string) bool {
	segs := strings.Split(name, "/")
	switch len(segs) {
	case 1:
		return segs[0] != ""
	case 2:
		_, ok := npmScopeSegment(segs[0])
		return ok && segs[1] != ""
	default:
		return false
	}
}

// isComponentOfCategory reports whether a relationship category means "the product_reference IS the
// component of the referenced product" — the only case where resolving a composite id to its component is
// sound. installed_on / installed_with are environment relationships and are deliberately excluded.
func isComponentOfCategory(c string) bool {
	switch strings.TrimSpace(c) {
	case "default_component_of", "external_component_of", "optional_component_of":
		return true
	}
	return false
}

// ParseAny decodes either a CSAF 2.x document (detected by document.csaf_version) or an OpenVEX document
// (everything else, validated by Parse). It lets one consume path accept whichever format a supplier ships.
func ParseAny(data []byte) (Document, error) {
	var probe struct {
		Document struct {
			CSAFVersion string `json:"csaf_version"`
		} `json:"document"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return Document{}, fmt.Errorf("%w: invalid VEX document: %v", shared.ErrValidation, err)
	}
	if strings.TrimSpace(probe.Document.CSAFVersion) != "" {
		return ParseCSAF(data)
	}
	return Parse(data)
}
