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

// This file parses a Canonical Ubuntu OVAL feed (com.ubuntu.<codename>.cve.oval.xml[.bz2]) into the owned
// normalized advisory shape. Ubuntu (and Debian) publish per-release OVAL that carries the distro's OWN
// fixed package version – the backport-accurate value a generic NVD range cannot express – so ingesting it
// natively gives Synapse offline, vendor-authoritative OS-package detection independent of any scanner DB.
//
// It handles only the dpkginfo (deb-family) OVAL: a definition's criteria reference dpkginfo_tests, each
// binding a dpkginfo_object (binary package name) to a dpkginfo_state (a "less than" fixed version). We map
// each such binding to a [0, fixed) ECOSYSTEM range keyed "Ubuntu:<release>", which the owned dpkg
// comparator already orders. A package with no "less than" fixed version (not-yet-fixed / not-affected) is
// skipped conservatively, so a match always carries an actionable fix.

// --- OVAL XML shapes (matched by LOCAL element name, so the linux-def namespace prefix is irrelevant) ---

type ovalDefinition struct {
	Class      string       `xml:"class,attr"`
	Title      string       `xml:"metadata>title"`
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

type ovalState struct {
	ID      string `xml:"id,attr"`
	Version struct {
		Operation string `xml:"operation,attr"`
		Value     string `xml:",chardata"`
	} `xml:"version"`
}

// ParseUbuntuOVAL parses one Ubuntu OVAL document (optionally bzip2-compressed) into advisories. It returns
// an error only for an input it cannot soundly handle (bad XML, unknown release); the caller's hardened
// walk turns that into a per-file skip.
func ParseUbuntuOVAL(content []byte) ([]advisory.Advisory, error) {
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

	defs := make([]ovalDefinition, 0, 1024)
	objects := map[string]string{}   // object id -> binary package name
	states := map[string]ovalState{} // state id -> version state
	tests := map[string]ovalTest{}   // test id -> object/state refs
	codename := ""

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
			// Grab the release codename from the first definition id: "oval:com.ubuntu.jammy:def:NNN".
			if codename == "" {
				codename = ubuntuCodename(attr(se, "id"))
			}
			var d ovalDefinition
			if err := dec.DecodeElement(&d, &se); err != nil {
				return nil, fmt.Errorf("decode definition: %w", err)
			}
			defs = append(defs, d)
		case "dpkginfo_test":
			var t ovalTest
			if err := dec.DecodeElement(&t, &se); err == nil && t.ID != "" {
				tests[t.ID] = t
			}
		case "dpkginfo_object":
			var o ovalObject
			if err := dec.DecodeElement(&o, &se); err == nil && o.ID != "" {
				objects[o.ID] = strings.TrimSpace(o.Name)
			}
		case "dpkginfo_state":
			var s ovalState
			if err := dec.DecodeElement(&s, &se); err == nil && s.ID != "" {
				states[s.ID] = s
			}
		}
	}

	// Fail closed if the decompressed stream hit the cap: a silently partial parse would drop most of a
	// release's CVEs while reporting success.
	if lr != nil && lr.N <= 0 {
		return nil, fmt.Errorf("%w: OVAL decompressed stream exceeds %d bytes; raise the cap or split the feed", shared.ErrValidation, maxOVALDecompressed)
	}
	release := ubuntuRelease(codename)
	if release == "" {
		return nil, fmt.Errorf("parse oval: unrecognized ubuntu release (codename %q)", codename)
	}
	ecosystem := "Ubuntu:" + release

	out := make([]advisory.Advisory, 0, len(defs))
	for i := range defs {
		if adv, ok := buildOVALAdvisory(&defs[i], ecosystem, tests, objects, states); ok {
			out = append(out, adv)
		}
	}
	return out, nil
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
		fixed := strings.TrimSpace(st.Version.Value)
		// Only the exact "less than <fixed>" state is an actionable fixed-at boundary → [0, fixed). Anything
		// else (not-fixed "pattern match", "greater than", or "less than or equal", which would be a
		// DIFFERENT, off-by-one interval) is skipped so a match always yields a real remediation version.
		if strings.ToLower(strings.TrimSpace(st.Version.Operation)) != "less than" || fixed == "" {
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

// attr returns a start-element attribute by local name.
func attr(se xml.StartElement, local string) string {
	for _, a := range se.Attr {
		if a.Name.Local == local {
			return a.Value
		}
	}
	return ""
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
