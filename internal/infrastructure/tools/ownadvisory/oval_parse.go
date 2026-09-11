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
//   - rpm-family (Oracle Linux com.oracle.elsa, AlmaLinux org.almalinux.al, openSUSE org.opensuse.security):
//     rpminfo tests bind a package name to a "less than" <evr>. A file can mix releases, so each package is
//     keyed to the release its own rpm dist tag names (.elN / .olN), or, for a version with no dist tag (SUSE),
//     the definition's single covered release; the covered majors come from the platform (Oracle, SUSE) or the
//     affected CPE (AlmaLinux). One patch fixes several CVEs and a CVE spans releases, so packages are unioned
//     per CVE into one advisory. Modular definitions are skipped (they need the enabled module stream the scan
//     side does not carry). See rpmOvalDistros for the per-feed configuration. SUSE ships gzip, the rest bzip2.
//
// Each binding maps to a [0, fixed) ECOSYSTEM range that the owned dpkg/rpm comparator orders and the
// scan-side osDistroEcosystem keys identically. A package with no "less than" fixed version (not-yet-fixed /
// not-affected) is skipped conservatively, so a match always carries an actionable fix.

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
	Criteria  []ovalCriteria  `xml:"criteria"`
	Criterion []ovalCriterion `xml:"criterion"`
}

type ovalCriterion struct {
	TestRef string `xml:"test_ref,attr"`
	Comment string `xml:"comment,attr"`
}

type ovalTest struct {
	ID     string `xml:"id,attr"`
	Object struct {
		Ref string `xml:"object_ref,attr"`
	} `xml:"object"`
	State struct {
		Ref string `xml:"state_ref,attr"`
	} `xml:"state"`
}

type ovalObject struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name"`
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
	objects map[string]string   // object id -> binary package name
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
		objects: map[string]string{},
		states:  map[string]ovalState{},
	}
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
				scan.objects[o.ID] = strings.TrimSpace(o.Name)
			}
		case "dpkginfo_state", "rpminfo_state":
			var s ovalState
			if err := dec.DecodeElement(&s, &se); err == nil && s.ID != "" {
				scan.states[s.ID] = s
			}
		}
	}

	// Fail closed if the decompressed stream hit the cap: a silently partial parse would drop most of a
	// release's CVEs while reporting success.
	if lr != nil && lr.N <= 0 {
		return nil, fmt.Errorf("%w: OVAL decompressed stream exceeds %d bytes; raise the cap or split the feed", shared.ErrValidation, maxOVALDecompressed)
	}
	return scan, nil
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
}

// rpmDistro reports which rpm-family OVAL feed this document is, detected by the anchored definition-id
// prefix, or nil for a deb-family (or unrecognized) document.
func (s *ovalScan) rpmDistro() *rpmOvalDistro {
	for di := range rpmOvalDistros {
		for i := range s.defs {
			if strings.HasPrefix(s.defs[i].ID, rpmOvalDistros[di].idPrefix) {
				return &rpmOvalDistros[di]
			}
		}
	}
	return nil
}

type rpmOvalAcc struct {
	summary  string
	score    float64
	affected []advisory.AffectedPackage
	seen     map[string]bool // "ecosystem\x00package" dedup
}

// rpmOvalAdvisories builds advisories from an rpm-family OVAL document. One file can mix releases, so the
// release majors a definition covers come from distro.majorsOf; one patch definition fixes several CVEs and
// the same CVE is fixed across several releases, so affected packages are UNIONED per CVE across definitions
// into one advisory (the store upserts by id, overwriting affected, so per-(CVE, definition) advisories would
// keep only the last release). Modular definitions are skipped.
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
		// A definition gated on an enabled module stream fixes a MODULAR package; matching it soundly needs the
		// stream the scan side does not carry, so skip the whole definition. rpmOvalAffected also skips any
		// per-package binding whose fixed version carries a ".module" build tag (the second signal).
		if criteriaHasModule(&d.Criteria) {
			continue
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
				a = &rpmOvalAcc{summary: summary, score: score, seen: map[string]bool{}}
				byCVE[cve] = a
				order = append(order, cve)
			}
			if score > a.score {
				a.score = score
			}
			for _, ap := range affected {
				key := ap.Ecosystem + "\x00" + ap.Package
				if a.seen[key] {
					continue
				}
				a.seen[key] = true
				a.affected = append(a.affected, ap)
			}
		}
	}
	out := make([]advisory.Advisory, 0, len(order))
	for _, cve := range order {
		a := byCVE[cve]
		out = append(out, advisory.Advisory{ID: cve, Summary: a.summary, CVSSScore: a.score, Affected: a.affected})
	}
	return out
}

// rpmOvalAffected resolves a definition's non-modular fixed bindings, keying EACH package by the release its
// OWN version's rpm dist tag names (.elN / .olN), constrained to the definition's covered majors. Because one
// definition can cover several releases (a shared UEK build, or per-release package tests), keying by the
// version's own dist tag is what stops a package being emitted under a release it does not belong to (a false
// match). A version with no recognizable dist tag is keyed only when the definition covers one release.
func rpmOvalAffected(d *ovalDefinition, ecosystemPrefix string, majors map[string]bool, tests map[string]ovalTest, objects map[string]string, states map[string]ovalState) []advisory.AffectedPackage {
	singleMajor := ""
	if len(majors) == 1 {
		for m := range majors {
			singleMajor = m
		}
	}
	// A package that also carries an upper-exclusion ("greater than [or equal]") state in this definition is a
	// BOUNDED [X, Y) affected range, not a fixed-at boundary; emitting its "less than Y" as [0, Y) would widen
	// past X and match versions below X that are not affected. Current feeds never pair the two for one package
	// (verified against the SUSE feed), so this is a fail-closed guard against a future feed that does.
	bounded := boundedPackages(d, tests, objects, states)
	seen := map[string]bool{}
	var out []advisory.AffectedPackage
	for _, ref := range flattenCriteria(&d.Criteria) {
		t, ok := tests[ref]
		if !ok {
			continue
		}
		pkg := objects[t.Object.Ref]
		st, ok := states[t.State.Ref]
		if pkg == "" || !ok {
			continue
		}
		if bounded[pkg] {
			continue // a [X, Y) range: skip rather than emit an overshooting [0, Y)
		}
		operation, value, ok := st.fixed()
		if !ok {
			continue
		}
		fixed := strings.TrimSpace(value)
		if strings.ToLower(strings.TrimSpace(operation)) != "less than" || fixed == "" {
			continue
		}
		if isDebianZeroBound(fixed) || strings.Contains(fixed, ".module") {
			continue
		}
		major := oracleReleaseFromEVR(fixed)
		if major == "" {
			major = singleMajor // no dist tag: only safe to key when the definition covers one release
		}
		if major == "" || !majors[major] {
			continue // the version's release is unknown or not one this definition covers: skip
		}
		ecosystem := ecosystemPrefix + major
		key := ecosystem + "\x00" + pkg
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, advisory.AffectedPackage{
			Ecosystem:    ecosystem,
			Package:      pkg,
			Ranges:       []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}},
			FixedVersion: fixed,
		})
	}
	return out
}

// boundedPackages returns the set of packages a definition constrains with an upper-exclusion state
// ("greater than" / "greater than or equal"), i.e. the lower bound of a [X, Y) affected range. Such a package
// must not be emitted from its "less than Y" state alone (that would be [0, Y), overshooting past X).
func boundedPackages(d *ovalDefinition, tests map[string]ovalTest, objects map[string]string, states map[string]ovalState) map[string]bool {
	bounded := map[string]bool{}
	for _, ref := range flattenCriteria(&d.Criteria) {
		t, ok := tests[ref]
		if !ok {
			continue
		}
		pkg := objects[t.Object.Ref]
		st, ok := states[t.State.Ref]
		if pkg == "" || !ok {
			continue
		}
		op, _, ok := st.fixed()
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(op)) {
		case "greater than", "greater than or equal":
			bounded[pkg] = true
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
func buildOVALAdvisory(d *ovalDefinition, ecosystem string, tests map[string]ovalTest, objects map[string]string, states map[string]ovalState) (advisory.Advisory, bool) {
	if d.Class != "" && d.Class != "vulnerability" {
		return advisory.Advisory{}, false
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
func affectedFromCriteria(d *ovalDefinition, ecosystem string, tests map[string]ovalTest, objects map[string]string, states map[string]ovalState, skipModular bool) []advisory.AffectedPackage {
	seen := map[string]bool{} // dedup package within this definition
	var affected []advisory.AffectedPackage
	for _, ref := range flattenCriteria(&d.Criteria) {
		t, ok := tests[ref]
		if !ok {
			continue
		}
		pkg := objects[t.Object.Ref]
		st, ok := states[t.State.Ref]
		if pkg == "" || !ok {
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
	return affected
}

// maxCriteriaDepth bounds the criteria-tree recursion (real Ubuntu OVAL nests 2-3 deep; this is defense-
// in-depth against a corrupt/crafted feed, mirroring the misconfig locator cap).
const maxCriteriaDepth = 1000

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
