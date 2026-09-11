package ownadvisory

import (
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// This file parses a deb-family OVAL feed into the owned normalized advisory shape: Canonical Ubuntu
// (com.ubuntu.<codename>.cve.oval.xml[.bz2]) and Debian (oval-definitions-<release>.xml[.bz2]). Both publish
// per-release OVAL that carries the distro's OWN fixed package version, the backport-accurate value a generic
// NVD range cannot express, so ingesting it natively gives Synapse offline, vendor-authoritative OS-package
// detection independent of any scanner DB.
//
// It handles only the dpkginfo (deb-family) OVAL: a definition's criteria reference dpkginfo_tests, each
// binding a dpkginfo_object (binary package name) to a dpkginfo_state (a "less than" fixed version, in a
// <version> element for Ubuntu or an <evr> element for Debian). We map each such binding to a [0, fixed)
// ECOSYSTEM range keyed "Ubuntu:<release>" or "Debian:<major>", which the owned dpkg comparator already
// orders and the scan-side osDistroEcosystem derives identically. The release is taken from the Ubuntu
// definition-id codename or the Debian affected <platform>. A package with no "less than" fixed version
// (not-yet-fixed / not-affected) is skipped conservatively, so a match always carries an actionable fix.

// --- OVAL XML shapes (matched by LOCAL element name, so the linux-def namespace prefix is irrelevant) ---

type ovalDefinition struct {
	ID         string       `xml:"id,attr"`
	Class      string       `xml:"class,attr"`
	Title      string       `xml:"metadata>title"`
	Platforms  []string     `xml:"metadata>affected>platform"`
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
	Criteria  []ovalCriteria  `xml:"criteria"`
	Criterion []ovalCriterion `xml:"criterion"`
}

type ovalCriterion struct {
	TestRef string `xml:"test_ref,attr"`
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
	if bytes.HasPrefix(content, []byte("BZh")) { // bzip2 magic
		// Read one PAST the cap so an over-cap feed is detected and fails CLOSED after the loop, rather than
		// truncating silently mid-stream into a partial (whole-release-dropped) advisory set.
		lr = &io.LimitedReader{R: bzip2.NewReader(r), N: maxOVALDecompressed + 1}
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
		case "dpkginfo_test":
			var t ovalTest
			if err := dec.DecodeElement(&t, &se); err == nil && t.ID != "" {
				scan.tests[t.ID] = t
			}
		case "dpkginfo_object":
			var o ovalObject
			if err := dec.DecodeElement(&o, &se); err == nil && o.ID != "" {
				scan.objects[o.ID] = strings.TrimSpace(o.Name)
			}
		case "dpkginfo_state":
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

	score := ubuntuSeverityScore(d.Severity)
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
		// Only the exact "less than <fixed>" state is an actionable fixed-at boundary → [0, fixed). Anything
		// else (not-fixed "pattern match", "greater than", or "less than or equal", which would be a
		// DIFFERENT, off-by-one interval) is skipped so a match always yields a real remediation version.
		if strings.ToLower(strings.TrimSpace(operation)) != "less than" || fixed == "" {
			continue
		}
		// Debian OVAL has historically emitted "less than 0:0" (or "0") for missing/inaccurate version data.
		// A [0, 0) range is a degenerate non-boundary, so skip it rather than store a row that can never carry
		// an actionable fix.
		if isDebianZeroBound(fixed) {
			continue
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
	if len(affected) == 0 {
		return advisory.Advisory{}, false
	}
	return advisory.Advisory{
		ID:        cve,
		Summary:   strings.TrimSpace(d.Title),
		CVSSScore: score, // Ubuntu ships a qualitative severity, not CVSS; vendor severity is authoritative
		Affected:  affected,
	}, true
}

// maxCriteriaDepth bounds the criteria-tree recursion (real Ubuntu OVAL nests 2-3 deep; this is defense-
// in-depth against a corrupt/crafted feed, mirroring the misconfig locator cap).
const maxCriteriaDepth = 1000

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

// ubuntuSeverityScore maps Ubuntu's qualitative CVE priority to a representative CVSS base score so the
// finding carries the vendor's rating. For an OS package the distro's severity is the authoritative one
// (it reflects the backport/exposure context), which is why we set it here rather than leaving it for an
// NVD backfill. The CVSS vector is intentionally left empty to signal this is a mapped band, not a scored
// vector. Unknown/untriaged → 0 (kept as unknown; an NVD enricher may still fill it).
func ubuntuSeverityScore(sev string) float64 {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 9.5
	case "high":
		return 8.0
	case "medium":
		return 5.5
	case "low":
		return 3.0
	case "negligible":
		return 1.0
	}
	return 0
}
