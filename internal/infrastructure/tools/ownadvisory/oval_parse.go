package ownadvisory

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// This file parses vendor OVAL feeds into the owned normalized advisory shape. Each distro publishes
// per-release (or, for Oracle, per-year multi-release) OVAL carrying the distro's OWN fixed package version,
// the backport-accurate value a generic NVD range cannot express, so ingesting it natively gives Synapse
// offline, vendor-authoritative OS-package detection independent of any scanner DB. ParseOVAL detects the
// distro from the document and dispatches:
//
//   - deb-family (Canonical Ubuntu com.ubuntu.<codename>, Debian org.debian): dpkginfo tests bind a package
//     name to a "less than" fixed version (a <version> element for Ubuntu, <evr> for Debian). Keyed
//     "Ubuntu:<release>" (from the id codename) or "Debian:<major>" (from the affected <platform>), one file
//     is one release.
//   - rpm-family (Oracle Linux com.oracle.elsa, AlmaLinux org.almalinux.al, openSUSE/SLE
//     org.opensuse.security): rpminfo tests bind a package either to a "less than" fixed EVR or to a
//     not-yet-fixed fact (an existence-only test, or an explicit zero-floor lower bound such as SUSE's
//     "greater than 0:0-0"). A file can mix releases, so a
//     fixed binding keys by its own rpm dist tag (.elN / .olN); a not-yet-fixed binding has no usable EVR and
//     is emitted only when the definition covers exactly one release. The covered majors come from platform
//     metadata (Oracle/SUSE) or affected CPEs (AlmaLinux). One definition can name several CVEs and a CVE can
//     span definitions/releases, so bindings are merged per CVE. A real fixed boundary always dominates an
//     open-ended claim for the same (CVE, ecosystem, package), preventing a stale not-yet-fixed definition
//     from matching a version the vendor later fixed. Modular definitions remain skipped because sound
//     matching needs the enabled module stream the scan side does not carry.
//
// Fixed bindings map to [0, fixed); not-yet-fixed bindings map to [0, infinity). Both use the same owned rpm
// comparator and scan-side distro ecosystem key. Non-zero lower bounds and ambiguous multi-release
// not-yet-fixed facts fail closed rather than widening a vendor range.

// --- OVAL XML shapes (matched by LOCAL element name, so the linux-def namespace prefix is irrelevant) ---

type ovalDefinition struct {
	ID         string       `xml:"id,attr"`
	Class      string       `xml:"class,attr"`
	Title      string       `xml:"metadata>title"`
	Platforms  []string     `xml:"metadata>affected>platform"`
	CPEs       []string     `xml:"metadata>advisory>affected_cpe_list>cpe"` // AlmaLinux names the release only here
	References []ovalRef    `xml:"metadata>reference"`
	Severity   string       `xml:"metadata>advisory>severity"`
	Criteria   ovalCriteria `xml:"criteria"`
}

type ovalRef struct {
	Source string `xml:"source,attr"`
	RefID  string `xml:"ref_id,attr"`
}

// ovalCriteria is a (possibly nested) AND/OR tree; we flatten it, since any referenced fixed-package test
// is an affected+fixed fact regardless of the boolean shape.
type ovalCriteria struct {
	Comment   string          `xml:"comment,attr"`
	Negate    bool            `xml:"negate,attr"`
	Criteria  []ovalCriteria  `xml:"criteria"`
	Criterion []ovalCriterion `xml:"criterion"`
}

type ovalCriterion struct {
	TestRef string `xml:"test_ref,attr"`
	Comment string `xml:"comment,attr"`
	Negate  bool   `xml:"negate,attr"`
}

type ovalTest struct {
	ID             string `xml:"id,attr"`
	Comment        string `xml:"comment,attr"`
	Check          string `xml:"check,attr"`
	CheckExistence string `xml:"check_existence,attr"`
	Object         struct {
		Ref string `xml:"object_ref,attr"`
	} `xml:"object"`
	State struct {
		Ref string `xml:"state_ref,attr"`
	} `xml:"state"`
}

type ovalObject struct {
	ID   string   `xml:"id,attr"`
	Name ovalName `xml:"name"`
}

// Ubuntu's current OVAL feed puts the binary package names in a constant_variable and points at it from
// dpkginfo_object/name@var_ref. Older Ubuntu feeds and the other supported distros put the package name
// directly in the name element, so retain both shapes.
type ovalName struct {
	VarRef string `xml:"var_ref,attr"`
	Value  string `xml:",chardata"`
}

type ovalConstantVariable struct {
	ID     string   `xml:"id,attr"`
	Values []string `xml:"value"`
}

// ovalState carries the fixed-version boundary. Ubuntu OVAL states it in a <version> element, Debian OVAL in
// an <evr> element (both datatype="debian_evr_string"); we read whichever is present.
type ovalState struct {
	ID      string  `xml:"id,attr"`
	Version ovalEVR `xml:"version"`
	Evr     ovalEVR `xml:"evr"`
}

type ovalEVR struct {
	Operation string `xml:"operation,attr"`
	Value     string `xml:",chardata"`
}

// fixed returns the operation and value of whichever of <evr>/<version> the state carries, and ok=false when
// no bound is present or the state AMBIGUOUSLY carries BOTH with different values (schema-valid but not a safe
// "pick one" union). An ambiguous state is skipped rather than guessed, so a match never rests on a boundary
// the feed did not unambiguously state.
func (s ovalState) fixed() (operation, value string, ok bool) {
	v := strings.TrimSpace(s.Version.Value)
	e := strings.TrimSpace(s.Evr.Value)
	switch {
	case v != "" && e != "":
		if v == e && strings.EqualFold(strings.TrimSpace(s.Version.Operation), strings.TrimSpace(s.Evr.Operation)) {
			return s.Evr.Operation, e, true // both present and identical: unambiguous
		}
		return "", "", false // both present and divergent: refuse to guess the boundary
	case e != "":
		return s.Evr.Operation, e, true
	case v != "":
		return s.Version.Operation, v, true
	default:
		return "", "", false
	}
}

// ovalScan holds the raw deb-family OVAL facts collected by one streaming pass, before a distro-specific
// ecosystem key is resolved.
type ovalScan struct {
	defs    []ovalDefinition
	tests   map[string]ovalTest // test id -> object/state refs
	objects map[string][]string // object id -> one or more binary package names
	states  map[string]ovalState
}

// scanOVAL streams one OVAL document (optionally bzip2-compressed) into the raw facts. It returns an error
// only for an input it cannot soundly handle (bad XML, over-cap decompressed stream). Elements are matched by
// LOCAL name, so the Ubuntu (linux-def) and Debian (linux) namespace prefixes both resolve.
func scanOVAL(content []byte) (*ovalScan, error) {
	// Self-guard direct callers that bypass the feed's per-file cap (parity with ParseCSAF): the raw input
	// is bounded here, and the bzip2 branch below additionally bounds the DECOMPRESSED stream.
	if int64(len(content)) > maxOVALFileBytes {
		return nil, fmt.Errorf("%w: OVAL document exceeds %d bytes", shared.ErrValidation, maxOVALFileBytes)
	}
	var r io.Reader = bytes.NewReader(content)
	var lr *io.LimitedReader
	// Read one PAST the cap so an over-cap feed is detected and fails CLOSED after the loop, rather than
	// truncating silently mid-stream into a partial (whole-release-dropped) advisory set. Ubuntu/Debian/Oracle
	// ship bzip2; SUSE ships gzip.
	switch {
	case bytes.HasPrefix(content, []byte("BZh")): // bzip2 magic
		lr = &io.LimitedReader{R: bzip2.NewReader(r), N: maxOVALDecompressed + 1}
		r = lr
	case bytes.HasPrefix(content, []byte{0x1f, 0x8b}): // gzip magic
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("parse oval: gzip: %w", err)
		}
		lr = &io.LimitedReader{R: gz, N: maxOVALDecompressed + 1}
		r = lr
	}

	scan := &ovalScan{
		defs:    make([]ovalDefinition, 0, 1024),
		tests:   map[string]ovalTest{},
		objects: map[string][]string{},
		states:  map[string]ovalState{},
	}
	objects := map[string]ovalObject{}
	variables := map[string][]string{}
	dec := xml.NewDecoder(r)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse oval: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "definition":
			var d ovalDefinition
			if err := dec.DecodeElement(&d, &se); err != nil {
				return nil, fmt.Errorf("decode definition: %w", err)
			}
			scan.defs = append(scan.defs, d)
		// dpkginfo (deb-family: Ubuntu, Debian) and rpminfo (rpm-family: Oracle Linux) share the same internal
		// shape (id, object ref, state ref, package name, evr), so both feed the same maps; the distinct id
		// namespaces prevent any collision.
		case "dpkginfo_test", "rpminfo_test":
			var t ovalTest
			if err := dec.DecodeElement(&t, &se); err == nil && t.ID != "" {
				scan.tests[t.ID] = t
			}
		case "dpkginfo_object", "rpminfo_object":
			var o ovalObject
			if err := dec.DecodeElement(&o, &se); err == nil && o.ID != "" {
				objects[o.ID] = o
			}
		case "dpkginfo_state", "rpminfo_state":
			var s ovalState
			if err := dec.DecodeElement(&s, &se); err == nil && s.ID != "" {
				scan.states[s.ID] = s
			}
		case "constant_variable":
			var v ovalConstantVariable
			if err := dec.DecodeElement(&v, &se); err == nil && v.ID != "" {
				variables[v.ID] = cleanPackageNames(v.Values)
			}
		}
	}

	// Fail closed if the decompressed stream hit the cap: a silently partial parse would drop most of a
	// release's CVEs while reporting success.
	if lr != nil && lr.N <= 0 {
		return nil, fmt.Errorf("%w: OVAL decompressed stream exceeds %d bytes; raise the cap or split the feed", shared.ErrValidation, maxOVALDecompressed)
	}
	for id, object := range objects {
		names := cleanPackageNames([]string{object.Name.Value})
		if ref := strings.TrimSpace(object.Name.VarRef); ref != "" {
			names = append(names, variables[ref]...)
			names = cleanPackageNames(names)
		}
		scan.objects[id] = names
	}
	return scan, nil
}

func cleanPackageNames(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		name := strings.TrimSpace(value)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// ParseOVAL parses one deb-family OVAL document (Canonical Ubuntu or Debian, optionally bzip2-compressed)
// into advisories keyed to the release-versioned ecosystem the owned dpkg comparator and the scan-side
// osDistroEcosystem agree on ("Ubuntu:22.04", "Debian:12"). It returns an error only for an input it cannot
// soundly handle (bad XML, unrecognized distro/release); the caller's hardened walk turns that into a
// per-file skip rather than a mis-keyed advisory.
func ParseOVAL(content []byte) ([]advisory.Advisory, error) {
	scan, err := scanOVAL(content)
	if err != nil {
		return nil, err
	}
	// The rpm-family feeds (Oracle Linux, AlmaLinux) are rpm OVAL: one file can mix releases, a definition
	// fixes several CVEs, and packages are modular; they take a separate per-definition build path. The
	// deb-family (Ubuntu/Debian) flow below is unchanged.
	if distro := scan.rpmDistro(); distro != nil {
		return scan.rpmOvalAdvisories(*distro), nil
	}
	ecosystem, err := scan.ecosystem()
	if err != nil {
		return nil, err
	}
	out := make([]advisory.Advisory, 0, len(scan.defs))
	for i := range scan.defs {
		if adv, ok := buildOVALAdvisory(&scan.defs[i], ecosystem, scan.tests, scan.objects, scan.states); ok {
			out = append(out, adv)
		}
	}
	return out, nil
}

// rpmOvalDistro configures an rpm-family OVAL feed: how its definitions are recognized, the ecosystem-key
// prefix its packages are stamped with, and how the release majors a definition covers are found.
type rpmOvalDistro struct {
	idPrefix  string                                // anchored definition-id prefix, e.g. "oval:com.oracle.elsa"
	ecosystem string                                // ecosystem-key prefix, e.g. "Oracle Linux:"
	majorsOf  func(*ovalDefinition) map[string]bool // the release majors a definition covers
}

// rpmOvalDistros is the registry of supported rpm-family OVAL feeds. Oracle names the release in the affected
// <platform>; AlmaLinux names it only in the advisory's affected_cpe_list.
var rpmOvalDistros = []rpmOvalDistro{
	{idPrefix: "oval:com.oracle.elsa", ecosystem: "Oracle Linux:", majorsOf: oraclePlatformMajors},
	{idPrefix: "oval:org.almalinux.al", ecosystem: "AlmaLinux:", majorsOf: almaCPEMajors},
	{idPrefix: "oval:org.opensuse.security", ecosystem: "openSUSE:", majorsOf: susePlatformMajors},
	// SUSE Linux Enterprise shares openSUSE's definition-id prefix but uses "SUSE Linux Enterprise ... 15 SP6"
	// platform strings (vs openSUSE's "openSUSE Leap 15.6"). rpmDistro disambiguates the shared prefix by which
	// entry's majorsOf actually recognizes the document's platforms, so a Leap file keys openSUSE: and an SLE
	// file keys SUSE:. Keyed per service pack (SUSE:15.6), matching the sles-<major.minor> inventory key.
	{idPrefix: "oval:org.opensuse.security", ecosystem: "SUSE:", majorsOf: sleServerPlatformMajors},
}

// rpmDistro reports which rpm-family OVAL feed this document is. Detection is by the anchored definition-id
// prefix, but two feeds (openSUSE Leap and SUSE Linux Enterprise) share the prefix "oval:org.opensuse.security"
// and differ only in their platform strings, so a shared-prefix tie is broken by which entry's majorsOf
// actually recognizes a definition in this document. The first entry whose majorsOf matches wins; if the
// prefix matches but no entry recognizes any platform (an unrecognized release), the first prefix match is
// returned so the caller still keys nothing (majorsOf stays empty downstream). nil for a deb-family document.
func (s *ovalScan) rpmDistro() *rpmOvalDistro {
	var prefixMatch *rpmOvalDistro
	for di := range rpmOvalDistros {
		dist := &rpmOvalDistros[di]
		for i := range s.defs {
			if !strings.HasPrefix(s.defs[i].ID, dist.idPrefix) {
				continue
			}
			if prefixMatch == nil {
				prefixMatch = dist
			}
			if len(dist.majorsOf(&s.defs[i])) > 0 {
				return dist // this entry recognizes the document's platforms → it is the right feed
			}
		}
	}
	return prefixMatch
}

type rpmOvalAcc struct {
	summary  string
	score    float64
	bindings map[string]*rpmOvalBindingAcc // "ecosystem\x00package" -> merged authority
	order    []string                      // first-seen binding order
}

type rpmOvalBindingAcc struct {
	openEnded bool
	fixedEVRs map[string]struct{}
}

// rpmOvalAdvisories builds advisories from an rpm-family OVAL document. One file can mix releases, so the
// release majors a definition covers come from distro.majorsOf. One definition can name several CVEs and the
// same CVE can appear in several definitions, so bindings are merged by (CVE, ecosystem, package) before
// emission. This merge is authority-preserving: any concrete fixed EVR wins over an open-ended
// not-yet-fixed claim. When several fixed EVRs exist, the same rpm-lineage resolver used by updateinfo/Rocky
// selects a superseding max within one lineage and fails closed across lineages. Thus definition order can
// never turn a known-fixed package back into [0, infinity). Modular definitions are skipped.
func (s *ovalScan) rpmOvalAdvisories(distro rpmOvalDistro) []advisory.Advisory {
	byCVE := map[string]*rpmOvalAcc{}
	order := make([]string, 0)
	for i := range s.defs {
		d := &s.defs[i]
		if !strings.HasPrefix(d.ID, distro.idPrefix) {
			continue // only this distro's own definitions (a mixed document keys each under its own config)
		}
		if d.Class != "" && d.Class != "vulnerability" && d.Class != "patch" {
			continue
		}
		if criteriaHasNegation(&d.Criteria) {
			continue // flattening cannot preserve boolean negation; skip rather than invert affected authority
		}
		if criteriaHasModule(&d.Criteria) {
			continue // matching a modular package soundly requires the enabled stream, which inventory lacks
		}
		majors := distro.majorsOf(d)
		if len(majors) == 0 {
			continue // unrecognized release
		}
		cves := rpmOvalCVEs(d)
		if len(cves) == 0 {
			continue
		}
		affected := rpmOvalAffected(d, distro.ecosystem, majors, s.tests, s.objects, s.states)
		if len(affected) == 0 {
			continue
		}
		score := ovalSeverityScore(d.Severity)
		summary := strings.TrimSpace(d.Title)
		for _, cve := range cves {
			a := byCVE[cve]
			if a == nil {
				a = &rpmOvalAcc{
					summary:  summary,
					score:    score,
					bindings: map[string]*rpmOvalBindingAcc{},
				}
				byCVE[cve] = a
				order = append(order, cve)
			}
			if score > a.score {
				a.score = score
			}
			for _, ap := range affected {
				key := ap.Ecosystem + "\x00" + ap.Package
				binding := a.bindings[key]
				if binding == nil {
					binding = &rpmOvalBindingAcc{fixedEVRs: map[string]struct{}{}}
					a.bindings[key] = binding
					a.order = append(a.order, key)
				}
				if fixed := strings.TrimSpace(ap.FixedVersion); fixed != "" {
					binding.fixedEVRs[fixed] = struct{}{}
				} else {
					binding.openEnded = true
				}
			}
		}
	}
	out := make([]advisory.Advisory, 0, len(order))
	for _, cve := range order {
		a := byCVE[cve]
		affected := make([]advisory.AffectedPackage, 0, len(a.order))
		for _, key := range a.order {
			ecosystem, pkg, ok := strings.Cut(key, "\x00")
			if !ok {
				continue
			}
			binding := a.bindings[key]
			switch {
			case len(binding.fixedEVRs) > 0:
				fixed := resolveRpmFixedInLineage(ecosystem, binding.fixedEVRs)
				if fixed == "" {
					continue // ambiguous/unorderable fixed authority: skip instead of falling back open-ended
				}
				affected = append(affected, advisory.AffectedPackage{
					Ecosystem:    ecosystem,
					Package:      pkg,
					Ranges:       []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}},
					FixedVersion: fixed,
				})
			case binding.openEnded:
				affected = append(affected, advisory.AffectedPackage{
					Ecosystem: ecosystem,
					Package:   pkg,
					Ranges:    []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}}}},
				})
			}
		}
		if len(affected) == 0 {
			continue
		}
		out = append(out, advisory.Advisory{ID: cve, Summary: a.summary, CVSSScore: a.score, Affected: affected})
	}
	return out
}

// rpmOvalAffected resolves a definition's rpm package bindings. A concrete "less than" fixed EVR is keyed
// by the release encoded in its own dist tag (.elN/.olN), falling back to the definition's release only when
// that release is unique. A not-yet-fixed fact has no release-bearing EVR, so it is emitted ONLY for a
// single-release definition and only in two conservative OVAL shapes:
//   - existence-only rpminfo test whose check_existence is/defaults to at_least_one_exists;
//   - a zero-floor state: SUSE affected feeds use "greater than 0:0-0"; some feeds use
//     "greater than or equal" with an equivalent zero EVR.
//
// Any real non-zero lower bound marks the package bounded and suppresses [0,...] emission. The caller merges
// duplicate bindings across definitions and lets concrete fixed authority dominate open-ended authority.
func rpmOvalAffected(d *ovalDefinition, ecosystemPrefix string, majors map[string]bool, tests map[string]ovalTest, objects map[string][]string, states map[string]ovalState) []advisory.AffectedPackage {
	singleMajor := ""
	if len(majors) == 1 {
		for m := range majors {
			singleMajor = m
		}
	}
	bounded := boundedPackages(d, tests, objects, states)
	var out []advisory.AffectedPackage
	for _, criterion := range flattenCriterionEntries(&d.Criteria) {
		ref := criterion.TestRef
		t, ok := tests[ref]
		if !ok {
			continue
		}
		packages := objects[t.Object.Ref]
		if len(packages) == 0 {
			continue
		}

		// OVAL defaults an omitted check_existence to at_least_one_exists. With no state, the test is a
		// package-existence fact. Restrict it to one concrete package name and one release so evaluating a
		// component never depends on another variable-expanded object or an ambiguous distro key.
		if strings.TrimSpace(t.State.Ref) == "" {
			if singleMajor == "" || len(packages) != 1 || !rpmPositiveExistence(t.CheckExistence) || !rpmPositiveCheck(t.Check) {
				continue
			}
			pkg := strings.TrimSpace(packages[0])
			// A state-less test is not enough by itself: OVAL definitions also contain package-existence
			// gates for the platform ("... is installed"). Require the vendor's explicit affected wording
			// and bind it to this exact package name before minting vulnerability authority.
			if pkg == "" || !rpmExplicitAffectedAuthority(criterion.Comment, t.Comment, pkg) || bounded[pkg] {
				continue
			}
			out = append(out, advisory.AffectedPackage{
				Ecosystem: ecosystemPrefix + singleMajor,
				Package:   pkg,
				Ranges:    []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}}}},
			})
			continue
		}

		st, ok := states[t.State.Ref]
		if !ok {
			continue
		}
		operation, value, ok := st.fixed()
		if !ok {
			continue
		}
		op := strings.ToLower(strings.TrimSpace(operation))
		value = strings.TrimSpace(value)

		switch op {
		case "less than":
			fixed := value
			if fixed == "" || isDebianZeroBound(fixed) || strings.Contains(fixed, ".module") {
				continue
			}
			major := oracleReleaseFromEVR(fixed)
			if major == "" {
				major = singleMajor // no dist tag: only safe to key when the definition covers one release
			}
			if major == "" || !majors[major] {
				continue
			}
			ecosystem := ecosystemPrefix + major
			for _, rawPkg := range packages {
				pkg := strings.TrimSpace(rawPkg)
				if pkg == "" || bounded[pkg] {
					continue // a real [X,Y) range must never be widened to [0,Y)
				}
				out = append(out, advisory.AffectedPackage{
					Ecosystem:    ecosystem,
					Package:      pkg,
					Ranges:       []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}},
					FixedVersion: fixed,
				})
			}

		case "greater than", "greater than or equal":
			// SUSE's affected-only OVAL feed represents "installed package is affected, no fix published" as
			// EVR > 0:0-0. Some rpm OVAL producers use >= with an equivalent zero floor. These are the ONLY
			// lower-bound-only states we widen to [0, infinity); every non-zero lower bound remains fail-closed.
			// Require a single concrete package and an affirmative check so a variable-expanded/negated test
			// cannot become per-package authority.
			if singleMajor == "" || len(packages) != 1 || !rpmAllVersionsFloor(op, value) || !rpmPositiveCheck(t.Check) {
				continue
			}
			ecosystem := ecosystemPrefix + singleMajor
			for _, rawPkg := range packages {
				pkg := strings.TrimSpace(rawPkg)
				if pkg == "" || !rpmExplicitAffectedAuthority(criterion.Comment, t.Comment, pkg) || bounded[pkg] {
					continue
				}
				out = append(out, advisory.AffectedPackage{
					Ecosystem: ecosystem,
					Package:   pkg,
					Ranges:    []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}}}},
				})
			}
		}
	}
	return out
}

// rpmPositiveExistence reports whether a state-less OVAL test is an affirmative package-existence fact.
// OVAL defaults an omitted check_existence to at_least_one_exists. "any_exist" also proves at least one
// matching object may exist only weakly (zero is permitted), so it is deliberately NOT accepted. Likewise
// all_exist/only_one_exists depend on set cardinality that the per-component matcher cannot reproduce.
func rpmPositiveExistence(check string) bool {
	check = strings.ToLower(strings.TrimSpace(check))
	return check == "" || check == "at_least_one_exists"
}

// rpmPositiveCheck accepts only affirmative item-state aggregation. OVAL requires this attribute, so an
// absent/unknown value is malformed and fails closed. "none satisfy" in particular is a negation and must
// never mint affected authority. "only one" depends on runtime item cardinality the per-component matcher
// does not carry, so it is also declined.
func rpmPositiveCheck(check string) bool {
	switch strings.ToLower(strings.TrimSpace(check)) {
	case "at least one", "all":
		return true
	default:
		return false
	}
}

// rpmExplicitAffectedAuthority distinguishes a vulnerable-package test from the platform/package-presence
// gates in the same OVAL definition. SUSE puts "<package> is affected" on the criterion while the referenced
// rpminfo_test says only "<package> is >0"; some producers may place the explicit wording on the test itself.
// Accept either layer, but only as an exact package-bound assertion. "... is installed" never grants CVE
// authority.
func rpmExplicitAffectedAuthority(criterionComment, testComment, pkg string) bool {
	pkg = strings.TrimSpace(pkg)
	if pkg == "" {
		return false
	}
	want := pkg + " is affected"
	return strings.EqualFold(strings.TrimSpace(criterionComment), want) ||
		strings.EqualFold(strings.TrimSpace(testComment), want)
}

// rpmZeroFloor recognizes only canonical zero EVRs used as the lower edge of an "all installed versions"
// vendor assertion. 0:0-0 is SUSE's affected-feed form; 0 and 0:0 occur in other OVAL producers.
func rpmZeroFloor(value string) bool {
	switch strings.TrimSpace(value) {
	case "0", "0:0", "0:0-0":
		return true
	default:
		return false
	}
}

// rpmAllVersionsFloor identifies the two source encodings accepted as not-yet-fixed authority. The
// operation is part of the contract: any non-zero greater-than bound describes a genuinely bounded affected
// interval and must not be widened to all versions.
func rpmAllVersionsFloor(operation, value string) bool {
	switch strings.ToLower(strings.TrimSpace(operation)) {
	case "greater than", "greater than or equal":
		return rpmZeroFloor(value)
	default:
		return false
	}
}

// boundedPackages returns packages constrained by a REAL lower bound ("greater than", or
// "greater than or equal" to a non-zero EVR). Those shapes describe [X,Y) when paired with a less-than state,
// so emitting the upper bound alone as [0,Y) would create false positives. A >=0 state is not a lower-bound
// restriction: an accepted zero-floor state is the explicit all-versions affected form and therefore does not mark the package bounded.
func boundedPackages(d *ovalDefinition, tests map[string]ovalTest, objects map[string][]string, states map[string]ovalState) map[string]bool {
	bounded := map[string]bool{}
	for _, ref := range flattenCriteria(&d.Criteria) {
		t, ok := tests[ref]
		if !ok {
			continue
		}
		packages := objects[t.Object.Ref]
		st, ok := states[t.State.Ref]
		if len(packages) == 0 || !ok {
			continue
		}
		op, value, ok := st.fixed()
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(op)) {
		case "greater than", "greater than or equal":
			if rpmAllVersionsFloor(op, value) {
				continue
			}
			for _, pkg := range packages {
				bounded[strings.TrimSpace(pkg)] = true
			}
		}
	}
	return bounded
}

// oraclePlatformMajors is the set of release majors a definition's platforms name ("Oracle Linux 8" -> "8").
func oraclePlatformMajors(d *ovalDefinition) map[string]bool {
	majors := map[string]bool{}
	for _, p := range d.Platforms {
		if m := oraclePlatformRelease(p); m != "" {
			majors[m] = true
		}
	}
	return majors
}

// almaCPEMajors is the set of release majors an AlmaLinux definition names in its affected CPEs
// ("cpe:/a:almalinux:almalinux:9" -> "9"). AlmaLinux leaves the affected <platform> empty.
func almaCPEMajors(d *ovalDefinition) map[string]bool {
	majors := map[string]bool{}
	for _, cpe := range d.CPEs {
		if m := almaCPERelease(cpe); m != "" {
			majors[m] = true
		}
	}
	return majors
}

// almaCPERelease extracts the release major from an AlmaLinux CPE ("cpe:/a:almalinux:almalinux:9::appstream"
// -> "9"); a non-AlmaLinux CPE or one with no numeric release returns "".
func almaCPERelease(cpe string) string {
	const marker = "almalinux:almalinux:"
	i := strings.Index(strings.ToLower(cpe), marker)
	if i < 0 {
		return ""
	}
	rest := cpe[i+len(marker):]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	if j == 0 {
		return ""
	}
	return rest[:j]
}

// rpmOvalCVEs returns the definition's distinct CVE references in order, from the CVE <reference> entries
// (Oracle, AlmaLinux) and from the <title> (SUSE names the CVE only in the title, e.g. "CVE-2001-0405").
func rpmOvalCVEs(d *ovalDefinition) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if strings.HasPrefix(id, "CVE-") && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, r := range d.References {
		if r.Source == "CVE" {
			add(r.RefID)
		}
	}
	for _, id := range cvePattern.FindAllString(d.Title, -1) {
		add(id)
	}
	return out
}

var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// susePlatformMajors is the set of release versions a SUSE definition's platforms name ("openSUSE Leap 15.6"
// -> "15.6"). openSUSE OVAL is per-release, so this is normally a single entry.
func susePlatformMajors(d *ovalDefinition) map[string]bool {
	majors := map[string]bool{}
	for _, p := range d.Platforms {
		if rel := susePlatformRelease(p); rel != "" {
			majors[rel] = true
		}
	}
	return majors
}

// susePlatformRelease extracts the release from a SUSE OVAL platform ("openSUSE Leap 15.6" -> "15.6"); a
// non-openSUSE-Leap platform returns "". SUSE rpm versions carry no distro dist tag, so the release comes
// from the platform and every package in a (single-release) file keys to it.
func susePlatformRelease(platform string) string {
	const marker = "opensuse leap "
	trimmed := strings.TrimSpace(platform)
	i := strings.Index(strings.ToLower(trimmed), marker)
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(trimmed[i+len(marker):])
	j := 0
	for j < len(rest) && (rest[j] >= '0' && rest[j] <= '9' || rest[j] == '.') {
		j++
	}
	rel := strings.TrimRight(rest[:j], ".")
	if rel == "" || !strings.ContainsAny(rel, "0123456789") {
		return ""
	}
	return rel
}

// sleServerPlatformMajors returns the SUSE Linux Enterprise release(s) a definition covers, read from its
// affected <platform> strings (e.g. "SUSE Linux Enterprise Server 15 SP6", "SUSE Linux Enterprise Module for
// Basesystem 15 SP6"). Any openSUSE Leap platform is not SLE and contributes nothing, so an openSUSE Leap
// document yields no SLE majors and rpmDistro keeps it on the openSUSE entry.
func sleServerPlatformMajors(d *ovalDefinition) map[string]bool {
	majors := map[string]bool{}
	for _, p := range d.Platforms {
		if rel := slePlatformRelease(p); rel != "" {
			majors[rel] = true
		}
	}
	return majors
}

// slePlatformRelease extracts the release key from a "SUSE Linux Enterprise ..." platform string: a trailing
// "<major> SP<sp>" yields "<major>.<sp>" (SP6 → 15.6), a bare trailing "<major>" yields "<major>", and an
// already-dotted "<major>.<minor>" (SLE 16.0) is returned as-is. This matches the sles-<major.minor> inventory
// key (per service pack), so a fixed NEVR is never applied across service packs. A non-SLE platform returns "".
func slePlatformRelease(platform string) string {
	s := strings.ToLower(strings.TrimSpace(platform))
	if !strings.HasPrefix(s, "suse linux enterprise") {
		return ""
	}
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return ""
	}
	last := fields[len(fields)-1]
	if sp, ok := strings.CutPrefix(last, "sp"); ok && sleAllDigits(sp) {
		if major := fields[len(fields)-2]; sleAllDigits(major) {
			return major + "." + sp
		}
		return ""
	}
	if sleNumericVersion(last) { // bare major "15" or already major.minor "16.0"
		return last
	}
	return ""
}

// sleAllDigits reports whether s is non-empty and all ASCII digits.
func sleAllDigits(s string) bool {
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

// sleNumericVersion reports whether s is a version of digits with at most one interior dot ("15" or "16.0").
func sleNumericVersion(s string) bool {
	if s == "" || s[0] == '.' || s[len(s)-1] == '.' {
		return false
	}
	dot := false
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '.' {
			if dot {
				return false
			}
			dot = true
		} else if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// oracleReleaseFromEVR extracts the OS major from an rpm release dist tag: ".el8_10" / ".el8uek" / ".ol9_..."
// all yield the leading major ("8"/"8"/"9"). Returns "" when the version carries no el/ol dist tag.
func oracleReleaseFromEVR(evr string) string {
	m := oracleDistTag.FindStringSubmatch(evr)
	if m == nil {
		return ""
	}
	return m[1]
}

var oracleDistTag = regexp.MustCompile(`\.(?:el|ol)(\d+)`)

// oraclePlatformRelease extracts the numeric release from "Oracle Linux 8" -> "8"; a non-Oracle platform or
// one with no leading numeric release returns "".
func oraclePlatformRelease(platform string) string {
	const marker = "oracle linux "
	trimmed := strings.TrimSpace(platform)
	i := strings.Index(strings.ToLower(trimmed), marker)
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(trimmed[i+len(marker):])
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	if j == 0 {
		return ""
	}
	return rest[:j]
}

// ParseUbuntuOVAL is retained for callers and tests that name the Ubuntu feed explicitly; it dispatches
// through the distro-parametric ParseOVAL, which detects the family from the document itself.
func ParseUbuntuOVAL(content []byte) ([]advisory.Advisory, error) { return ParseOVAL(content) }

// ecosystem resolves the release-versioned ecosystem key from the scanned document, detecting the distro
// family. Ubuntu tags each definition id with the release codename (oval:com.ubuntu.<codename>:def); Debian
// tags the id with org.debian and states the release in the affected <platform>. An unrecognized release for
// a recognized family is an error (per-file skip), never a guessed key.
func (s *ovalScan) ecosystem() (string, error) {
	ubuntuCodes := map[string]bool{}
	debian := false
	for i := range s.defs {
		// Detect the family from an ANCHORED definition-id prefix, not a loose substring: a real Ubuntu id is
		// "oval:com.ubuntu.<codename>:def:N", a real Debian id "oval:org.debian:def:N". This keeps a crafted id
		// that merely contains "com.ubuntu" as a substring (e.g. "oval:org.debian.com.ubuntu...") classified by
		// its true "oval:org.debian" prefix instead of being miscounted as Ubuntu.
		id := s.defs[i].ID
		switch {
		case strings.HasPrefix(id, "oval:com.ubuntu."):
			if codename := ubuntuCodename(id); codename != "" {
				ubuntuCodes[codename] = true
			}
		case strings.HasPrefix(id, "oval:org.debian"):
			debian = true
		}
	}
	// Fail closed on a document that is not exactly one recognized family: a mixed or crafted file could
	// otherwise key one distro's package facts under another distro's ecosystem (a false match).
	if len(ubuntuCodes) > 0 && debian {
		return "", fmt.Errorf("parse oval: ambiguous OVAL document mixes ubuntu and debian definitions")
	}
	if len(ubuntuCodes) > 0 {
		if len(ubuntuCodes) > 1 {
			return "", fmt.Errorf("parse oval: ambiguous ubuntu OVAL document mixes releases")
		}
		var codename string
		for c := range ubuntuCodes {
			codename = c
		}
		release := ubuntuRelease(codename)
		if release == "" {
			return "", fmt.Errorf("parse oval: unrecognized ubuntu release (codename %q)", codename)
		}
		return "Ubuntu:" + release, nil
	}
	if debian {
		release := debianRelease(s.defs)
		if release == "" {
			return "", fmt.Errorf("parse oval: unrecognized or mixed debian release")
		}
		return "Debian:" + release, nil
	}
	return "", fmt.Errorf("parse oval: unrecognized OVAL distro family")
}

// isDebianZeroBound reports whether a fixed version is the "0"/"0:0" sentinel that carries no actionable
// boundary (all epoch/upstream/revision components are zero or empty). A real fix is never at version zero,
// so treating these as no-boundary cannot drop a legitimate fixed version.
func isDebianZeroBound(v string) bool {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[i+1:] // drop the epoch
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return true
	}
	for _, r := range v {
		if r != '0' && r != '.' && r != '-' && r != ':' {
			return false
		}
	}
	return true // only zeros and separators
}

// buildOVALAdvisory resolves a definition's criteria into an advisory. ok=false when the definition carries
// no CVE id or no fixed package (nothing matchable).
func buildOVALAdvisory(d *ovalDefinition, ecosystem string, tests map[string]ovalTest, objects map[string][]string, states map[string]ovalState) (advisory.Advisory, bool) {
	if d.Class != "" && d.Class != "vulnerability" {
		return advisory.Advisory{}, false
	}
	if criteriaHasNegation(&d.Criteria) {
		return advisory.Advisory{}, false // flattened package facts cannot soundly represent an inverted branch
	}
	cve := ""
	for _, r := range d.References {
		if r.Source == "CVE" && strings.HasPrefix(r.RefID, "CVE-") {
			cve = r.RefID
			break
		}
	}
	if cve == "" {
		return advisory.Advisory{}, false
	}

	affected := affectedFromCriteria(d, ecosystem, tests, objects, states, false)
	if len(affected) == 0 {
		return advisory.Advisory{}, false
	}
	return advisory.Advisory{
		ID:        cve,
		Summary:   strings.TrimSpace(d.Title),
		CVSSScore: ovalSeverityScore(d.Severity), // vendor qualitative severity is authoritative for an OS package
		Affected:  affected,
	}, true
}

// affectedFromCriteria resolves a definition's criteria into its fixed (ecosystem, package, [0, fixed))
// bindings. Only an exact "less than <fixed>" dpkginfo/rpminfo state is an actionable boundary; a not-fixed,
// zero-sentinel, or ambiguous state is skipped. When skipModular is set (the rpm families), a fixed version
// carrying a ".module" build tag is skipped: matching a modular package soundly needs the enabled module
// STREAM, which the scan side does not carry, so a cross-stream comparison could false-match.
func affectedFromCriteria(d *ovalDefinition, ecosystem string, tests map[string]ovalTest, objects map[string][]string, states map[string]ovalState, skipModular bool) []advisory.AffectedPackage {
	seen := map[string]bool{} // dedup package within this definition
	var affected []advisory.AffectedPackage
	for _, ref := range flattenCriteria(&d.Criteria) {
		t, ok := tests[ref]
		if !ok {
			continue
		}
		packages := objects[t.Object.Ref]
		st, ok := states[t.State.Ref]
		if len(packages) == 0 || !ok {
			continue
		}
		operation, value, ok := st.fixed()
		if !ok {
			continue // no bound, or an ambiguous both-elements state
		}
		fixed := strings.TrimSpace(value)
		if strings.ToLower(strings.TrimSpace(operation)) != "less than" || fixed == "" {
			continue
		}
		if isDebianZeroBound(fixed) {
			continue // "0"/"0:0" missing-data sentinel: a [0, 0) range is a degenerate non-boundary
		}
		if skipModular && strings.Contains(fixed, ".module") {
			continue // modular rpm without stream context: skip rather than risk a cross-stream false match
		}
		for _, pkg := range packages {
			if seen[pkg] {
				continue
			}
			seen[pkg] = true
			affected = append(affected, advisory.AffectedPackage{
				Ecosystem:    ecosystem,
				Package:      pkg,
				Ranges:       []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}},
				FixedVersion: fixed,
			})
		}
	}
	return affected
}

// maxCriteriaDepth bounds the criteria-tree recursion (real Ubuntu OVAL nests 2-3 deep; this is defense-
// in-depth against a corrupt/crafted feed, mirroring the misconfig locator cap).
const maxCriteriaDepth = 1000

// criteriaHasNegation reports whether any criteria node or criterion in the tree inverts its result. Package
// extraction deliberately flattens the boolean tree into independent affected facts, so preserving a negated
// branch would require evaluating the complete OVAL expression against a host. Fail closed for the whole
// definition instead: ignoring negate can turn "package is NOT affected" into open-ended affected authority.
func criteriaHasNegation(c *ovalCriteria) bool { return criteriaHasNegationDepth(c, 0) }

func criteriaHasNegationDepth(c *ovalCriteria, depth int) bool {
	if depth > maxCriteriaDepth {
		return true // malformed/hostile depth: do not extract facts from a partially inspected tree
	}
	if c.Negate {
		return true
	}
	for _, cr := range c.Criterion {
		if cr.Negate {
			return true
		}
	}
	for i := range c.Criteria {
		if criteriaHasNegationDepth(&c.Criteria[i], depth+1) {
			return true
		}
	}
	return false
}

// criteriaHasModule reports whether the (possibly nested) criteria tree gates on an enabled module stream,
// detected by a "Module <name>:<stream> is enabled" comment on any criterion or sub-criteria. Such a
// definition fixes a modular package.
func criteriaHasModule(c *ovalCriteria) bool { return criteriaHasModuleDepth(c, 0) }

func criteriaHasModuleDepth(c *ovalCriteria, depth int) bool {
	if depth > maxCriteriaDepth {
		return false
	}
	if isModuleComment(c.Comment) {
		return true
	}
	for _, cr := range c.Criterion {
		if isModuleComment(cr.Comment) {
			return true
		}
	}
	for i := range c.Criteria {
		if criteriaHasModuleDepth(&c.Criteria[i], depth+1) {
			return true
		}
	}
	return false
}

func isModuleComment(comment string) bool {
	c := strings.ToLower(comment)
	return strings.Contains(c, "module ") && strings.Contains(c, "is enabled")
}

// flattenCriterionEntries preserves the criterion-level comment alongside each test_ref. This matters for
// rpm affected-only feeds: SUSE's vulnerability authority ("<package> is affected") lives on the criterion,
// while the referenced rpminfo_test comment only describes the mechanical state ("<package> is >0").
func flattenCriterionEntries(c *ovalCriteria) []ovalCriterion {
	return flattenCriterionEntriesDepth(c, 0)
}

func flattenCriterionEntriesDepth(c *ovalCriteria, depth int) []ovalCriterion {
	if depth > maxCriteriaDepth {
		return nil
	}
	var out []ovalCriterion
	for _, cr := range c.Criterion {
		if cr.TestRef != "" {
			out = append(out, cr)
		}
	}
	for i := range c.Criteria {
		out = append(out, flattenCriterionEntriesDepth(&c.Criteria[i], depth+1)...)
	}
	return out
}

// flattenCriteria collects every criterion test_ref in the (possibly nested) criteria tree.
func flattenCriteria(c *ovalCriteria) []string { return flattenCriteriaDepth(c, 0) }

func flattenCriteriaDepth(c *ovalCriteria, depth int) []string {
	if depth > maxCriteriaDepth {
		return nil
	}
	var refs []string
	for _, cr := range c.Criterion {
		if cr.TestRef != "" {
			refs = append(refs, cr.TestRef)
		}
	}
	for i := range c.Criteria {
		refs = append(refs, flattenCriteriaDepth(&c.Criteria[i], depth+1)...)
	}
	return refs
}

// debianRelease returns the Debian release major (e.g. "12") shared by the document's definitions, taken from
// each definition's affected <platform> ("Debian GNU/Linux 12"). It requires a UNIQUE release across the file
// (Debian publishes one OVAL file per release); a file that mixes releases, or names none, returns "" so the
// caller skips it rather than key an advisory to the wrong release (which would be a false match).
func debianRelease(defs []ovalDefinition) string {
	release := ""
	for i := range defs {
		for _, p := range defs[i].Platforms {
			r := debianPlatformRelease(p)
			if r == "" {
				continue
			}
			switch {
			case release == "":
				release = r
			case release != r:
				return "" // mixed releases in one file: refuse to key any of them
			}
		}
	}
	return release
}

// debianPlatformRelease extracts the numeric release from a Debian OVAL platform string
// ("Debian GNU/Linux 12" -> "12"). A string that is not a Debian platform, or carries no leading numeric
// release, returns "". This matches the "Debian:<major>" key osDistroEcosystem derives for a deb PURL.
func debianPlatformRelease(platform string) string {
	const marker = "debian gnu/linux "
	trimmed := strings.TrimSpace(platform)
	i := strings.Index(strings.ToLower(trimmed), marker) // ASCII marker: byte index valid in the original too
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(trimmed[i+len(marker):])
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	if j == 0 {
		return ""
	}
	return rest[:j]
}

// ubuntuCodename extracts the release codename from an Ubuntu OVAL id like
// "oval:com.ubuntu.jammy:def:20231234000" → "jammy".
func ubuntuCodename(id string) string {
	const marker = "com.ubuntu."
	i := strings.Index(id, marker)
	if i < 0 {
		return ""
	}
	rest := id[i+len(marker):]
	if j := strings.IndexByte(rest, ':'); j >= 0 {
		return rest[:j]
	}
	return rest
}

// ubuntuRelease maps a codename to its VERSION_ID ("22.04"), which is what Syft emits in the deb PURL's
// distro qualifier (distro=ubuntu-22.04) – so the feed and the matcher agree on "Ubuntu:22.04". Unknown
// codename → "" (skip the file, honestly counted, rather than key it wrong).
func ubuntuRelease(codename string) string {
	switch strings.ToLower(codename) {
	case "trusty":
		return "14.04"
	case "xenial":
		return "16.04"
	case "bionic":
		return "18.04"
	case "focal":
		return "20.04"
	case "jammy":
		return "22.04"
	case "noble":
		return "24.04"
	case "kinetic":
		return "22.10"
	case "lunar":
		return "23.04"
	case "mantic":
		return "23.10"
	case "oracular":
		return "24.10"
	case "plucky":
		return "25.04"
	}
	return ""
}

// ovalSeverityScore maps a distro qualitative CVE priority to a representative CVSS base score so the
// finding carries the vendor's rating. For an OS package the distro's severity is the authoritative one
// (it reflects the backport/exposure context), which is why we set it here rather than leaving it for an
// NVD backfill. The CVSS vector is intentionally left empty to signal this is a mapped band, not a scored
// vector. Unknown/untriaged → 0 (kept as unknown; an NVD enricher may still fill it).
func ovalSeverityScore(sev string) float64 {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 9.5
	case "high", "important": // Ubuntu uses "high", the rpm families use "important"
		return 8.0
	case "medium", "moderate": // Ubuntu "medium", rpm "moderate"
		return 5.5
	case "low":
		return 3.0
	case "negligible":
		return 1.0
	}
	return 0
}
