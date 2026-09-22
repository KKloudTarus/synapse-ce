package ownadvisory

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"sort"
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
// Fixed bindings map to [0, fixed) ECOSYSTEM ranges that the owned dpkg/rpm comparator orders and the
// scan-side osDistroEcosystem keys identically. SUSE's affected feed also has a narrowly admitted ordinary-SLES
// lifecycle template: its vendor "is affected" >0 sentinel maps to an open introduced:0 range, while the paired
// "is not affected" ==0 template emits an empty current replacement. Other no-fix shapes remain skipped.

// --- OVAL XML shapes (prefix spelling is irrelevant; admitted RPM elements must use the Linux OVAL namespace) ---

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

// ovalCriteria preserves the nested Boolean tree. RPM ingestion admits only criteria topology whose release
// and package meaning can be represented without dropping a branch or predicate.
type ovalCriteria struct {
	Operator  string          `xml:"operator,attr"`
	Negate    string          `xml:"negate,attr"`
	Comment   string          `xml:"comment,attr"`
	Criteria  []ovalCriteria  `xml:"criteria"`
	Criterion []ovalCriterion `xml:"criterion"`
	Other     []ovalElement   `xml:",any"`
}

type ovalCriterion struct {
	TestRef            string `xml:"test_ref,attr"`
	Comment            string `xml:"comment,attr"`
	Negate             string `xml:"negate,attr"`
	ApplicabilityCheck string `xml:"applicability_check,attr"`
}

type ovalTest struct {
	XMLName        xml.Name
	ID             string           `xml:"id,attr"`
	Comment        string           `xml:"comment,attr"`
	Check          string           `xml:"check,attr"`
	CheckExistence string           `xml:"check_existence,attr"`
	StateOperator  string           `xml:"state_operator,attr"`
	Objects        []ovalRefElement `xml:"object"`
	States         []ovalRefElement `xml:"state"`
	Other          []ovalElement    `xml:",any"`
}

type ovalRefElement struct {
	XMLName   xml.Name
	ObjectRef string `xml:"object_ref,attr"`
	StateRef  string `xml:"state_ref,attr"`
}

func (t ovalTest) refs() (objectRef, stateRef string, ok bool) {
	if len(t.Objects) != 1 || len(t.States) != 1 {
		return "", "", false
	}
	objectRef = strings.TrimSpace(t.Objects[0].ObjectRef)
	stateRef = strings.TrimSpace(t.States[0].StateRef)
	return objectRef, stateRef, objectRef != "" && stateRef != ""
}

type ovalElement struct {
	XMLName xml.Name
}

type ovalObject struct {
	XMLName xml.Name
	ID      string        `xml:"id,attr"`
	Names   []ovalName    `xml:"name"`
	Other   []ovalElement `xml:",any"`
}

// Ubuntu's current OVAL feed puts the binary package names in a constant_variable and points at it from
// dpkginfo_object/name@var_ref. Older Ubuntu feeds and the other supported distros put the package name
// directly in the name element, so retain both shapes.
type ovalName struct {
	XMLName   xml.Name
	VarRef    string `xml:"var_ref,attr"`
	Operation string `xml:"operation,attr"`
	Datatype  string `xml:"datatype,attr"`
	Value     string `xml:",chardata"`
}

type ovalConstantVariable struct {
	ID     string   `xml:"id,attr"`
	Values []string `xml:"value"`
}

// ovalState carries the fixed-version boundary. Ubuntu OVAL states it in a <version> element, Debian OVAL in
// an <evr> element (both datatype="debian_evr_string"); we read whichever is present.
type ovalState struct {
	XMLName       xml.Name
	ID            string        `xml:"id,attr"`
	Versions      []ovalEVR     `xml:"version"`
	EVRs          []ovalEVR     `xml:"evr"`
	Architectures []ovalEVR     `xml:"arch"`
	Signatures    []ovalEVR     `xml:"signature_keyid"`
	Other         []ovalElement `xml:",any"`
}

type ovalEVR struct {
	XMLName   xml.Name
	Operation string `xml:"operation,attr"`
	Datatype  string `xml:"datatype,attr"`
	Value     string `xml:",chardata"`
}

// fixed returns the operation and value of whichever of <evr>/<version> the state carries, and ok=false when
// no bound is present or the state AMBIGUOUSLY carries BOTH with different values (schema-valid but not a safe
// "pick one" union). An ambiguous state is skipped rather than guessed, so a match never rests on a boundary
// the feed did not unambiguously state.
func (s ovalState) fixed() (operation, value string, ok bool) {
	if len(s.Versions) > 1 || len(s.EVRs) > 1 {
		return "", "", false
	}
	var version, evr ovalEVR
	if len(s.Versions) == 1 {
		version = s.Versions[0]
	}
	if len(s.EVRs) == 1 {
		evr = s.EVRs[0]
	}
	v := strings.TrimSpace(version.Value)
	e := strings.TrimSpace(evr.Value)
	switch {
	case v != "" && e != "":
		if v == e && strings.EqualFold(strings.TrimSpace(version.Operation), strings.TrimSpace(evr.Operation)) {
			return evr.Operation, e, true // both present and identical: unambiguous
		}
		return "", "", false // both present and divergent: refuse to guess the boundary
	case e != "":
		return evr.Operation, e, true
	case v != "":
		return version.Operation, v, true
	default:
		return "", "", false
	}
}

// ovalScan holds the raw deb-family OVAL facts collected by one streaming pass, before a distro-specific
// ecosystem key is resolved.
type ovalScan struct {
	defs       []ovalDefinition
	tests      map[string]ovalTest   // test id -> object/state refs
	objects    map[string][]string   // object id -> one or more binary package names
	objectDefs map[string]ovalObject // object id -> retained predicates for strict lifecycle recognition
	states     map[string]ovalState
}

// scanOVAL streams one OVAL document (optionally compressed) into raw facts and returns the decompressed
// bytes actually read from that stream. Elements are matched by LOCAL name, so the Ubuntu (linux-def) and
// Debian (linux) namespace prefixes both resolve.
func scanOVAL(content []byte, documentLimit, snapshotLimit, remainingSnapshotLimit int64) (*ovalScan, int64, error) {
	var r io.Reader = bytes.NewReader(content)
	// Read one PAST the tighter cap so an over-cap feed is detected and fails CLOSED rather than silently
	// truncating into a partial advisory set. Ubuntu/Debian/Oracle ship bzip2; SUSE ships gzip.
	switch {
	case bytes.HasPrefix(content, []byte("BZh")): // bzip2 magic
		r = bzip2.NewReader(r)
	case bytes.HasPrefix(content, []byte{0x1f, 0x8b}): // gzip magic
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, 0, fmt.Errorf("parse oval: gzip: %w", err)
		}
		r = gz
	}
	streamLimit := documentLimit
	if remainingSnapshotLimit < streamLimit {
		streamLimit = remainingSnapshotLimit
	}
	// One reader both accounts for and supplies XML bytes. For plain XML that counts its raw XML bytes; for
	// gzip/bzip2 it counts only bytes the decompressor actually produced, without a second decompression pass.
	counted := &byteCountingReader{Reader: r}
	limited := &io.LimitedReader{R: counted, N: streamLimit + 1}

	scan := &ovalScan{
		defs:       make([]ovalDefinition, 0, 1024),
		tests:      map[string]ovalTest{},
		objects:    map[string][]string{},
		objectDefs: map[string]ovalObject{},
		states:     map[string]ovalState{},
	}
	objects := map[string]ovalObject{}
	variables := map[string][]string{}
	seenIDs := map[string]string{}
	claimID := func(kind, id string) error {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil
		}
		if previous, exists := seenIDs[id]; exists {
			return fmt.Errorf("%w: duplicate OVAL id %q (%s and %s)", shared.ErrValidation, id, previous, kind)
		}
		seenIDs[id] = kind
		return nil
	}
	dec := xml.NewDecoder(limited)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			if limited.N <= 0 {
				return nil, counted.bytes, ovalDecompressedLimitError(documentLimit, snapshotLimit, remainingSnapshotLimit)
			}
			return nil, counted.bytes, fmt.Errorf("parse oval: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "definition":
			var d ovalDefinition
			if err := dec.DecodeElement(&d, &se); err != nil {
				if limited.N <= 0 {
					return nil, counted.bytes, ovalDecompressedLimitError(documentLimit, snapshotLimit, remainingSnapshotLimit)
				}
				return nil, counted.bytes, fmt.Errorf("decode definition: %w", err)
			}
			if err := claimID("definition", d.ID); err != nil {
				return nil, counted.bytes, err
			}
			scan.defs = append(scan.defs, d)
		// dpkginfo (deb-family) and rpminfo (rpm-family) retain their concrete element name and namespace.
		// Distro-specific admission must verify both before interpreting a test as package evidence.
		case "dpkginfo_test", "rpminfo_test":
			var t ovalTest
			if err := dec.DecodeElement(&t, &se); err != nil {
				if limited.N <= 0 {
					return nil, counted.bytes, ovalDecompressedLimitError(documentLimit, snapshotLimit, remainingSnapshotLimit)
				}
				return nil, counted.bytes, fmt.Errorf("decode %s: %w", se.Name.Local, err)
			}
			if err := claimID(se.Name.Local, t.ID); err != nil {
				return nil, counted.bytes, err
			}
			if t.ID != "" {
				scan.tests[t.ID] = t
			}
		case "dpkginfo_object", "rpminfo_object":
			var o ovalObject
			if err := dec.DecodeElement(&o, &se); err != nil {
				if limited.N <= 0 {
					return nil, counted.bytes, ovalDecompressedLimitError(documentLimit, snapshotLimit, remainingSnapshotLimit)
				}
				return nil, counted.bytes, fmt.Errorf("decode %s: %w", se.Name.Local, err)
			}
			if err := claimID(se.Name.Local, o.ID); err != nil {
				return nil, counted.bytes, err
			}
			if o.ID != "" {
				objects[o.ID] = o
			}
		case "dpkginfo_state", "rpminfo_state":
			var s ovalState
			if err := dec.DecodeElement(&s, &se); err != nil {
				if limited.N <= 0 {
					return nil, counted.bytes, ovalDecompressedLimitError(documentLimit, snapshotLimit, remainingSnapshotLimit)
				}
				return nil, counted.bytes, fmt.Errorf("decode %s: %w", se.Name.Local, err)
			}
			if err := claimID(se.Name.Local, s.ID); err != nil {
				return nil, counted.bytes, err
			}
			if s.ID != "" {
				scan.states[s.ID] = s
			}
		case "constant_variable":
			var v ovalConstantVariable
			if err := dec.DecodeElement(&v, &se); err != nil {
				if limited.N <= 0 {
					return nil, counted.bytes, ovalDecompressedLimitError(documentLimit, snapshotLimit, remainingSnapshotLimit)
				}
				return nil, counted.bytes, fmt.Errorf("decode constant_variable: %w", err)
			}
			if err := claimID("constant_variable", v.ID); err != nil {
				return nil, counted.bytes, err
			}
			if v.ID != "" {
				variables[v.ID] = cleanPackageNames(v.Values)
			}
		}
	}

	// Fail closed if the decompressed stream hit either cap: a silently partial parse would drop most of a
	// release's CVEs while reporting success.
	if limited.N <= 0 {
		return nil, counted.bytes, ovalDecompressedLimitError(documentLimit, snapshotLimit, remainingSnapshotLimit)
	}
	for id, object := range objects {
		var names []string
		for _, name := range object.Names {
			names = append(names, name.Value)
			if ref := strings.TrimSpace(name.VarRef); ref != "" {
				names = append(names, variables[ref]...)
			}
		}
		scan.objects[id] = cleanPackageNames(names)
		scan.objectDefs[id] = object
	}
	return scan, counted.bytes, nil
}

type byteCountingReader struct {
	io.Reader
	bytes int64
}

func (r *byteCountingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.bytes += int64(n)
	return n, err
}

func ovalDecompressedLimitError(documentLimit, snapshotLimit, remainingSnapshotLimit int64) error {
	if remainingSnapshotLimit < documentLimit {
		return fmt.Errorf("%w: OVAL snapshot decompressed stream exceeds %d bytes", shared.ErrValidation, snapshotLimit)
	}
	return fmt.Errorf("%w: OVAL decompressed stream exceeds %d bytes; raise the cap or split the feed", shared.ErrValidation, documentLimit)
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

// ParseOVAL parses one vendor OVAL document. RPM lifecycle precedence is resolved through the same snapshot
// reducer used by multi-document providers so a one-file import and a complete source snapshot have identical
// semantics.
func ParseOVAL(content []byte) ([]advisory.Advisory, error) {
	return ParseOVALSnapshot([][]byte{content})
}

// ParseOVALSnapshot parses and reduces one complete, non-empty OVAL source snapshot. Facts are merged by
// (CVE, ecosystem, package) across document boundaries: a fixed boundary replaces an open affected fact,
// explicit not-affected removes only that package binding, and conflicting fixed boundaries reject the snapshot.
func ParseOVALSnapshot(documents [][]byte) ([]advisory.Advisory, error) {
	return parseOVALSnapshotWithLimits(documents, defaultOVALSnapshotLimits())
}

func parseOVALSnapshotWithLimits(documents [][]byte, limits ovalSnapshotLimits) ([]advisory.Advisory, error) {
	if len(documents) == 0 {
		return nil, fmt.Errorf("%w: OVAL snapshot is empty", shared.ErrValidation)
	}
	facts := map[string]*rpmOvalAcc{}
	rawBytes := int64(0)
	decompressedBytes := int64(0)
	for index, content := range documents {
		contentBytes := int64(len(content))
		if contentBytes > limits.fileBytes {
			return nil, fmt.Errorf("%w: OVAL snapshot document %d exceeds %d raw bytes", shared.ErrValidation, index+1, limits.fileBytes)
		}
		if contentBytes > limits.snapshotBytes-rawBytes {
			return nil, fmt.Errorf("%w: OVAL snapshot exceeds %d raw bytes", shared.ErrValidation, limits.snapshotBytes)
		}
		rawBytes += contentBytes
		remainingDecompressedBytes := limits.snapshotDecompressedBytes - decompressedBytes
		scan, scannedBytes, err := scanOVAL(content, limits.documentDecompressedBytes, limits.snapshotDecompressedBytes, remainingDecompressedBytes)
		if err != nil {
			return nil, fmt.Errorf("parse OVAL snapshot document %d: %w", index+1, err)
		}
		if scannedBytes > remainingDecompressedBytes {
			return nil, fmt.Errorf("%w: OVAL snapshot decompressed stream exceeds %d bytes", shared.ErrValidation, limits.snapshotDecompressedBytes)
		}
		decompressedBytes += scannedBytes
		distro, err := scan.rpmDistro()
		if err != nil {
			return nil, fmt.Errorf("parse OVAL snapshot document %d: %w", index+1, err)
		}
		if distro != nil {
			documentFacts, err := scan.rpmOvalFacts(*distro)
			if err != nil {
				return nil, fmt.Errorf("parse OVAL snapshot document %d: %w", index+1, err)
			}
			mergeRPMOvalFacts(facts, documentFacts)
			continue
		}
		ecosystem, err := scan.ecosystem()
		if err != nil {
			return nil, fmt.Errorf("parse OVAL snapshot document %d: %w", index+1, err)
		}
		for i := range scan.defs {
			adv, represented, err := buildOVALAdvisory(&scan.defs[i], ecosystem, scan.tests, scan.objects, scan.objectDefs, scan.states)
			if err != nil {
				return nil, fmt.Errorf("parse OVAL snapshot document %d: %w", index+1, err)
			}
			if !represented {
				continue
			}
			entry := facts[adv.ID]
			if entry == nil {
				entry = newRPMOvalAcc()
				facts[adv.ID] = entry
			}
			if adv.Summary != "" && (entry.summary == "" || adv.Summary < entry.summary) {
				entry.summary = adv.Summary
			}
			if adv.CVSSScore > entry.score {
				entry.score = adv.CVSSScore
			}
			if len(adv.Affected) == 0 {
				entry.lifecycleSeen = true
			}
			for _, binding := range adv.Affected {
				entry.merge(binding)
			}
		}
	}
	if err := validateRPMOvalFacts(facts); err != nil {
		return nil, err
	}
	return rpmOvalAdvisories(facts), nil
}

func validateRPMOvalFacts(facts map[string]*rpmOvalAcc) error {
	cves := make([]string, 0, len(facts))
	for cve := range facts {
		cves = append(cves, cve)
	}
	sort.Strings(cves)
	for _, cve := range cves {
		keys := make([]string, 0, len(facts[cve].conflicts))
		for key := range facts[cve].conflicts {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if len(keys) > 0 {
			return fmt.Errorf("%w: conflicting OVAL fixed boundaries for %s %q", shared.ErrValidation, cve, keys[0])
		}
	}
	return nil
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
func (s *ovalScan) rpmDistro() (*rpmOvalDistro, error) {
	var prefixMatch *rpmOvalDistro
	matched := map[string]*rpmOvalDistro{}
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
				matched[dist.ecosystem] = dist
			}
		}
	}
	if len(matched) > 1 {
		families := make([]string, 0, len(matched))
		for family := range matched {
			families = append(families, family)
		}
		sort.Strings(families)
		return nil, fmt.Errorf("%w: mixed RPM OVAL families %s", shared.ErrValidation, strings.Join(families, ", "))
	}
	for _, dist := range matched {
		return dist, nil
	}
	return prefixMatch, nil
}

type rpmOvalAcc struct {
	summary         string
	score           float64
	bindings        map[string]advisory.AffectedPackage
	blocked         map[string]bool
	suppressed      map[string]bool
	fixedBoundaries map[string]string
	conflicts       map[string]bool
	lifecycleSeen   bool
}

func newRPMOvalAcc() *rpmOvalAcc {
	return &rpmOvalAcc{
		bindings:        map[string]advisory.AffectedPackage{},
		blocked:         map[string]bool{},
		suppressed:      map[string]bool{},
		fixedBoundaries: map[string]string{},
		conflicts:       map[string]bool{},
	}
}

func higherFixedBoundary(ecosystem, current, candidate string) (string, bool) {
	if current == candidate {
		return current, true
	}
	comparison, ok := advisory.CompareVersions(ecosystem, candidate, current)
	if !ok {
		return "", false
	}
	if comparison > 0 {
		return candidate, true
	}
	return current, true
}

func (a *rpmOvalAcc) observeFixed(key, boundary string) {
	boundary = strings.TrimSpace(boundary)
	if boundary == "" {
		return
	}
	current, exists := a.fixedBoundaries[key]
	if !exists {
		a.fixedBoundaries[key] = boundary
		return
	}
	ecosystem, _, ok := strings.Cut(key, "\x00")
	preferred, comparable := higherFixedBoundary(ecosystem, current, boundary)
	if !ok || !comparable {
		a.conflicts[key] = true
		return
	}
	a.fixedBoundaries[key] = preferred
}

func (a *rpmOvalAcc) merge(ap advisory.AffectedPackage) {
	// Two keys with deliberately different scopes.
	//
	// packageKey (ecosystem + package) scopes retirement and supersession. Suppression, known-not-affected,
	// and conflict remain package-wide so that unreadable or contradictory evidence about ANY architecture
	// variant withdraws the whole package binding. That is the fail-closed direction and it must not become
	// per-architecture, or an unreadable variant would leave sibling variants matching.
	//
	// bindingKey additionally carries the architecture set, because one CVE legitimately publishes several
	// architecture-scoped facts for the same package (SLES ships libacl1 for both
	// "(aarch64|ppc64le|s390x|x86_64)" and "(ppc64le|x86_64)" under CVE-2026-54369, from different product
	// clauses). Keying bindings by package alone would let one overwrite the other and silently drop real
	// applicability.
	packageKey := ap.Ecosystem + "\x00" + ap.Package
	bindingKey := packageKey + "\x00" + strings.Join(ap.Architectures, ",")
	candidateFixed := strings.TrimSpace(ap.FixedVersion)
	a.observeFixed(packageKey, candidateFixed)
	if a.conflicts[packageKey] || a.blocked[packageKey] || a.suppressed[packageKey] {
		a.deleteBindings(packageKey)
		return
	}
	current, ok := a.bindings[bindingKey]
	if !ok {
		a.bindings[bindingKey] = ap
		return
	}
	currentFixed := strings.TrimSpace(current.FixedVersion)
	switch {
	case currentFixed != "" && candidateFixed != "":
		if a.fixedBoundaries[packageKey] == candidateFixed {
			a.bindings[bindingKey] = ap
		}
	case currentFixed == "" && candidateFixed != "":
		a.bindings[bindingKey] = ap
	}
}

// deleteBindings withdraws every architecture-scoped binding belonging to one package key. Retirement is
// package-wide, but bindings are stored per architecture set, so a single map delete is no longer enough.
func (a *rpmOvalAcc) deleteBindings(packageKey string) {
	delete(a.bindings, packageKey)
	prefix := packageKey + "\x00"
	for key := range a.bindings {
		if strings.HasPrefix(key, prefix) {
			delete(a.bindings, key)
		}
	}
}

// rpmOvalFacts collects scoped facts from one rpm-family OVAL document. One document can mix releases, so the
// release majors a definition covers come from distro.majorsOf; one patch definition can fix several CVEs and
// the same CVE can span releases. ParseOVALSnapshot performs the final cross-document reduction. Modular
// definitions are skipped because the scan identity does not carry the enabled module stream.
func (s *ovalScan) rpmOvalFacts(distro rpmOvalDistro) (map[string]*rpmOvalAcc, error) {
	byCVE := map[string]*rpmOvalAcc{}
	for i := range s.defs {
		d := &s.defs[i]
		if !strings.HasPrefix(d.ID, distro.idPrefix) {
			continue
		}
		if d.Class != "" && d.Class != "vulnerability" && d.Class != "patch" {
			continue
		}
		cves := rpmOvalCVEs(d)
		if len(cves) == 0 {
			continue
		}
		if !rpmDefinitionTargetsDistro(d, distro) {
			continue
		}
		if criteriaHasModule(&d.Criteria) {
			return nil, fmt.Errorf("%w: RPM OVAL definition %q for %s depends on an unrepresentable module stream", shared.ErrValidation, d.ID, strings.Join(cves, ", "))
		}
		majors := distro.majorsOf(d)
		if len(majors) == 0 {
			return nil, fmt.Errorf("%w: RPM OVAL definition %q for %s has no supported release applicability", shared.ErrValidation, d.ID, strings.Join(cves, ", "))
		}

		var facts suseLifecycleResult
		if distro.ecosystem == "SUSE:" {
			var represented bool
			var err error
			facts, represented, err = suseLifecycleAffected(d, majors, s.tests, s.objectDefs, s.states)
			if err != nil {
				return nil, fmt.Errorf("%w: RPM OVAL definition %q for %s is unrepresentable: %v", shared.ErrValidation, d.ID, strings.Join(cves, ", "), err)
			}
			if !represented {
				continue
			}
		} else {
			var err error
			facts.affected, err = rpmOvalAffected(d, distro.ecosystem, majors, s.tests, s.objectDefs, s.states)
			if err != nil {
				return nil, fmt.Errorf("%w: RPM OVAL definition %q for %s is unrepresentable: %v", shared.ErrValidation, d.ID, strings.Join(cves, ", "), err)
			}
			facts.seen = true
		}
		score := ovalSeverityScore(d.Severity)
		summary := strings.TrimSpace(d.Title)
		for _, cve := range cves {
			a := byCVE[cve]
			if a == nil {
				a = newRPMOvalAcc()
				byCVE[cve] = a
			}
			if summary != "" && (a.summary == "" || summary < a.summary) {
				a.summary = summary
			}
			if score > a.score {
				a.score = score
			}
			a.lifecycleSeen = a.lifecycleSeen || facts.seen
			for key, boundary := range facts.fixedBoundaries {
				a.observeFixed(key, boundary)
			}
			for _, key := range facts.notAffected {
				a.blocked[key] = true
				a.deleteBindings(key)
			}
			for _, key := range facts.suppressed {
				a.suppressed[key] = true
				a.deleteBindings(key)
			}
			for _, ap := range facts.affected {
				a.merge(ap)
			}
		}
	}
	return byCVE, nil
}

func rpmDefinitionTargetsDistro(d *ovalDefinition, distro rpmOvalDistro) bool {
	for _, platform := range d.Platforms {
		platform = strings.ToLower(strings.TrimSpace(platform))
		switch distro.ecosystem {
		case "Oracle Linux:":
			if strings.Contains(platform, "oracle linux") {
				return true
			}
		case "openSUSE:":
			if strings.Contains(platform, "opensuse leap") {
				return true
			}
		case "SUSE:":
			if strings.HasPrefix(platform, "suse linux enterprise ") {
				return true
			}
		}
	}
	if distro.ecosystem == "AlmaLinux:" {
		for _, cpe := range d.CPEs {
			if strings.Contains(strings.ToLower(cpe), "almalinux:almalinux:") {
				return true
			}
		}
	}
	return false
}

func mergeRPMOvalFacts(target map[string]*rpmOvalAcc, source map[string]*rpmOvalAcc) {
	for cve, incoming := range source {
		current := target[cve]
		if current == nil {
			current = newRPMOvalAcc()
			target[cve] = current
		}
		if incoming.summary != "" && (current.summary == "" || incoming.summary < current.summary) {
			current.summary = incoming.summary
		}
		if incoming.score > current.score {
			current.score = incoming.score
		}
		current.lifecycleSeen = current.lifecycleSeen || incoming.lifecycleSeen
		for key, boundary := range incoming.fixedBoundaries {
			current.observeFixed(key, boundary)
		}
		for key := range incoming.blocked {
			current.blocked[key] = true
			current.deleteBindings(key)
		}
		for key := range incoming.suppressed {
			current.suppressed[key] = true
			current.deleteBindings(key)
		}
		for key := range incoming.conflicts {
			current.conflicts[key] = true
			current.deleteBindings(key)
		}
		for _, binding := range incoming.bindings {
			current.merge(binding)
		}
	}
}

func rpmOvalAdvisories(byCVE map[string]*rpmOvalAcc) []advisory.Advisory {
	cves := make([]string, 0, len(byCVE))
	for cve := range byCVE {
		cves = append(cves, cve)
	}
	sort.Strings(cves)
	out := make([]advisory.Advisory, 0, len(cves))
	for _, cve := range cves {
		a := byCVE[cve]
		keys := make([]string, 0, len(a.bindings))
		for key := range a.bindings {
			if !a.blocked[key] && !a.suppressed[key] {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		affected := make([]advisory.AffectedPackage, 0, len(keys))
		for _, key := range keys {
			affected = append(affected, a.bindings[key])
		}
		if len(affected) == 0 && !a.lifecycleSeen {
			continue
		}
		out = append(out, advisory.Advisory{ID: cve, Summary: a.summary, CVSSScore: a.score, Affected: affected})
	}
	return out
}

// rpmOvalAffected resolves a definition's non-modular fixed bindings, keying EACH package by the release its
// OWN version's rpm dist tag names (.elN / .olN), constrained to the definition's covered majors. Because one
// definition can cover several releases (a shared UEK build, or per-release package tests), keying by the
// version's own dist tag is what stops a package being emitted under a release it does not belong to (a false
// match). A version with no recognizable dist tag is keyed only when the definition covers one release.
func rpmOvalAffected(d *ovalDefinition, ecosystemPrefix string, majors map[string]bool, tests map[string]ovalTest, objects map[string]ovalObject, states map[string]ovalState) ([]advisory.AffectedPackage, error) {
	facts, ok := rpmCriteriaFacts(&d.Criteria, ecosystemPrefix, majors, tests, objects, states, 0)
	if !ok || len(facts) == 0 {
		return nil, fmt.Errorf("unsupported or incomplete RPM criteria")
	}
	keys := make([]string, 0, len(facts))
	for key := range facts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]advisory.AffectedPackage, 0, len(keys))
	for _, key := range keys {
		out = append(out, facts[key])
	}
	return out, nil
}

func rpmCriteriaFacts(criteria *ovalCriteria, ecosystemPrefix string, majors map[string]bool, tests map[string]ovalTest, objects map[string]ovalObject, states map[string]ovalState, depth int) (map[string]advisory.AffectedPackage, bool) {
	if criteria == nil || depth > maxCriteriaDepth || !ovalFalseOrEmpty(criteria.Negate) || len(criteria.Other) != 0 {
		return nil, false
	}
	operator := strings.ToUpper(strings.TrimSpace(criteria.Operator))
	if operator == "" {
		operator = "AND"
	}
	if operator != "AND" && operator != "OR" {
		return nil, false
	}
	type branch struct {
		facts   map[string]advisory.AffectedPackage
		release bool
	}
	branches := make([]branch, 0, len(criteria.Criterion)+len(criteria.Criteria))
	for _, criterion := range criteria.Criterion {
		facts, release, ok := rpmCriterionFacts(criterion, ecosystemPrefix, majors, tests, objects, states)
		if !ok {
			return nil, false
		}
		branches = append(branches, branch{facts: facts, release: release})
	}
	for i := range criteria.Criteria {
		facts, ok := rpmCriteriaFacts(&criteria.Criteria[i], ecosystemPrefix, majors, tests, objects, states, depth+1)
		if !ok {
			return nil, false
		}
		branches = append(branches, branch{facts: facts, release: len(facts) == 0})
	}
	if len(branches) == 0 {
		return nil, false
	}
	out := map[string]advisory.AffectedPackage{}
	if operator == "OR" {
		allRelease := true
		allPackage := true
		for _, current := range branches {
			allRelease = allRelease && current.release && len(current.facts) == 0
			allPackage = allPackage && !current.release && len(current.facts) > 0
		}
		if !allRelease && !allPackage {
			return nil, false
		}
	}
	for _, current := range branches {
		for key, candidate := range current.facts {
			if existing, found := out[key]; found && existing.FixedVersion != candidate.FixedVersion {
				return nil, false
			}
			out[key] = candidate
		}
	}
	return out, true
}

func rpmCriterionFacts(criterion ovalCriterion, ecosystemPrefix string, majors map[string]bool, tests map[string]ovalTest, objects map[string]ovalObject, states map[string]ovalState) (map[string]advisory.AffectedPackage, bool, bool) {
	if !suseCriterionShape(criterion) {
		return nil, false, false
	}
	test, ok := tests[strings.TrimSpace(criterion.TestRef)]
	if !ok || !rpmTestShape(test) {
		return nil, false, false
	}
	objectRef, stateRef, _ := test.refs()
	object, objectOK := objects[objectRef]
	state, stateOK := states[stateRef]
	if !objectOK || !stateOK || !rpmElement(object.XMLName, "rpminfo_object") || !rpmElement(state.XMLName, "rpminfo_state") {
		return nil, false, false
	}
	packageName, literal := rpmLiteralObject(object)
	if !literal {
		return nil, false, false
	}
	if rpmReleasePredicate(packageName, state, majors) {
		return map[string]advisory.AffectedPackage{}, true, true
	}
	if len(state.Architectures) != 0 || len(state.Signatures) != 0 || len(state.Other) != 0 || len(state.Versions) != 0 || len(state.EVRs) != 1 {
		return nil, false, false
	}
	evr := state.EVRs[0]
	if !rpmElement(evr.XMLName, "evr") || !strings.EqualFold(strings.TrimSpace(evr.Datatype), "evr_string") || !strings.EqualFold(strings.TrimSpace(evr.Operation), "less than") {
		return nil, false, false
	}
	fixed := strings.TrimSpace(evr.Value)
	if fixed == "" || isDebianZeroBound(fixed) || strings.Contains(fixed, ".module") {
		return nil, false, false
	}
	major := oracleReleaseFromEVR(fixed)
	if major == "" && len(majors) == 1 {
		for candidate := range majors {
			major = candidate
		}
	}
	if major == "" || !majors[major] {
		return nil, false, false
	}
	ecosystem := ecosystemPrefix + major
	binding := advisory.AffectedPackage{
		Ecosystem:    ecosystem,
		Package:      packageName,
		Ranges:       []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}},
		FixedVersion: fixed,
	}
	return map[string]advisory.AffectedPackage{ecosystem + "\x00" + packageName: binding}, false, true
}

const ovalLinuxNamespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"

func rpmElement(name xml.Name, local string) bool {
	return name.Space == ovalLinuxNamespace && name.Local == local
}

func rpmTestShape(test ovalTest) bool {
	if !rpmElement(test.XMLName, "rpminfo_test") || len(test.Other) != 0 || len(test.Objects) != 1 || len(test.States) != 1 {
		return false
	}
	if !rpmElement(test.Objects[0].XMLName, "object") || !rpmElement(test.States[0].XMLName, "state") {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(test.Check), "at least one") {
		return false
	}
	checkExistence := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(test.CheckExistence), "_", " "))
	if checkExistence != "" && checkExistence != "at least one exists" {
		return false
	}
	stateOperator := strings.ToUpper(strings.TrimSpace(test.StateOperator))
	if stateOperator != "" && stateOperator != "AND" {
		return false
	}
	_, _, ok := test.refs()
	return ok
}

func rpmLiteralObject(object ovalObject) (string, bool) {
	if !rpmElement(object.XMLName, "rpminfo_object") || len(object.Names) != 1 || len(object.Other) != 0 {
		return "", false
	}
	name := object.Names[0]
	if !rpmElement(name.XMLName, "name") || strings.TrimSpace(name.VarRef) != "" || strings.TrimSpace(name.Operation) != "" || strings.TrimSpace(name.Datatype) != "" {
		return "", false
	}
	value := strings.TrimSpace(name.Value)
	return value, value != ""
}

func rpmReleasePredicate(packageName string, state ovalState, majors map[string]bool) bool {
	if !strings.Contains(strings.ToLower(packageName), "release") || len(state.Architectures) != 0 || len(state.Signatures) != 0 || len(state.Other) != 0 || len(state.EVRs) != 0 || len(state.Versions) != 1 {
		return false
	}
	version := state.Versions[0]
	if !rpmElement(version.XMLName, "version") || !strings.EqualFold(strings.TrimSpace(version.Datatype), "version") {
		return false
	}
	value := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(version.Value), "^"))
	value = strings.TrimSuffix(value, ".*")
	operation := strings.ToLower(strings.TrimSpace(version.Operation))
	if operation != "equals" && operation != "pattern match" {
		return false
	}
	for major := range majors {
		if value == major || value == regexp.QuoteMeta(major) {
			return true
		}
	}
	return false
}

type suseLifecycleResult struct {
	seen            bool
	affected        []advisory.AffectedPackage
	notAffected     []string
	suppressed      []string
	fixedBoundaries map[string]string
}

type susePackageDisposition uint8

const (
	susePackageOpen susePackageDisposition = iota + 1
	susePackageFixed
	susePackageNotAffected
	susePackageSuppressed
)

type susePackageStatus struct {
	packageName  string
	disposition  susePackageDisposition
	fixedVersion string
	// architectures is the exact architecture set the vendor scoped this package fact to, or nil when the
	// criterion carried no architecture predicate (meaning every architecture).
	architectures []string
}

type suseCriteriaItem struct {
	criterion *ovalCriterion
	criteria  *ovalCriteria
}

// suseLifecycleAffected recognizes only SUSE's documented affected-feed lifecycle templates. The
// greater-than-zero EVR is not interpreted as generic RPM arithmetic: the package/test comments,
// ordinary SLES product predicate, boolean topology, and otherwise-empty state must all agree.
func suseLifecycleAffected(d *ovalDefinition, majors map[string]bool, tests map[string]ovalTest, objects map[string]ovalObject, states map[string]ovalState) (suseLifecycleResult, bool, error) {
	if !suseOrdinaryServerPlatform(d) {
		return suseLifecycleResult{}, false, nil
	}
	if len(majors) != 1 {
		return suseLifecycleResult{}, false, fmt.Errorf("ordinary SLES evidence must name exactly one release")
	}
	if ovalCriteriaAbsent(&d.Criteria) {
		return suseLifecycleResult{seen: true}, true, nil
	}
	if !suseLifecycleSignal(&d.Criteria, tests) {
		return suseLifecycleResult{}, false, fmt.Errorf("SLES lifecycle predicates are incomplete")
	}
	major := ""
	for candidate := range majors {
		major = candidate
	}
	declaredProducts := suseDeclaredProductComments(d, major)
	if len(declaredProducts) == 0 {
		return suseLifecycleResult{}, false, fmt.Errorf("ordinary SLES product metadata is missing")
	}
	clauses, ok := suseLifecycleClauses(&d.Criteria)
	if !ok {
		return suseLifecycleResult{}, false, fmt.Errorf("unsupported SLES criteria topology")
	}

	ecosystem := "SUSE:" + major
	byPackage := map[string]susePackageStatus{}
	suppressed := map[string]bool{}
	fixedBoundaries := map[string]string{}
	applicable := false
	for i := range clauses {
		applies, statuses, valid := suseLifecycleClause(&clauses[i], major, declaredProducts, tests, objects, states)
		if !valid {
			return suseLifecycleResult{}, false, fmt.Errorf("unsupported SLES product or package predicate in clause %d", i+1)
		}
		if !applies {
			continue
		}
		applicable = true
		for _, status := range statuses {
			if status.fixedVersion != "" {
				current, exists := fixedBoundaries[status.packageName]
				if !exists {
					fixedBoundaries[status.packageName] = status.fixedVersion
				} else {
					preferred, comparable := higherFixedBoundary(ecosystem, current, status.fixedVersion)
					if !comparable {
						return suseLifecycleResult{}, false, fmt.Errorf("contradictory SLES fixed boundaries for %q", status.packageName)
					}
					fixedBoundaries[status.packageName] = preferred
				}
			}
			if status.disposition == susePackageSuppressed {
				suppressed[status.packageName] = true
				continue
			}
			// Lifecycle statuses are deduplicated per package AND architecture set, because one CVE
			// legitimately publishes several architecture-scoped facts for the same package from different
			// product clauses. Collapsing them by package alone would drop a real architecture set. Note that
			// suppression above and fixedBoundaries below stay package-wide on purpose: those are the
			// fail-closed directions and must withdraw or bound every variant of the package.
			statusKey := status.packageName + "\x00" + strings.Join(status.architectures, ",")
			current, exists := byPackage[statusKey]
			if !exists {
				byPackage[statusKey] = status
				continue
			}
			switch {
			case current.disposition == susePackageNotAffected:
				continue
			case status.disposition == susePackageNotAffected:
				byPackage[statusKey] = status
			case current.disposition == susePackageFixed && status.disposition == susePackageFixed:
				if fixedBoundaries[status.packageName] == status.fixedVersion {
					byPackage[statusKey] = status
				}
			case current.disposition == susePackageFixed:
				continue
			case status.disposition == susePackageFixed:
				byPackage[statusKey] = status
			case current.disposition == status.disposition:
				continue
			default:
				return suseLifecycleResult{}, false, fmt.Errorf("contradictory SLES package lifecycle states for %q", status.packageName)
			}
		}
	}
	if !applicable {
		return suseLifecycleResult{}, false, nil
	}
	if len(byPackage)+len(suppressed) == 0 {
		return suseLifecycleResult{}, false, fmt.Errorf("ordinary SLES applicability has no classifiable package lifecycle")
	}

	// byPackage is keyed by package + architecture set, so iterate its keys for affected/not-affected
	// emission, and add suppression-only packages (which carry no architecture-scoped status) separately.
	statusKeys := make([]string, 0, len(byPackage))
	for statusKey := range byPackage {
		statusKeys = append(statusKeys, statusKey)
	}
	sort.Strings(statusKeys)
	suppressedOnly := make([]string, 0, len(suppressed))
	for pkg := range suppressed {
		suppressedOnly = append(suppressedOnly, pkg)
	}
	sort.Strings(suppressedOnly)

	result := suseLifecycleResult{seen: true, fixedBoundaries: map[string]string{}}
	// Suppression and fixed boundaries are package-scoped, so record them once per package before emitting
	// the architecture-scoped bindings.
	for _, pkg := range suppressedOnly {
		key := ecosystem + "\x00" + pkg
		if fixed := fixedBoundaries[pkg]; fixed != "" {
			result.fixedBoundaries[key] = fixed
		}
		result.suppressed = append(result.suppressed, key)
	}
	for _, statusKey := range statusKeys {
		status := byPackage[statusKey]
		pkg := status.packageName
		key := ecosystem + "\x00" + pkg
		if suppressed[pkg] {
			// A suppressed package was already withdrawn above; no architecture variant of it may bind.
			continue
		}
		if fixed := fixedBoundaries[pkg]; fixed != "" {
			result.fixedBoundaries[key] = fixed
		}
		switch status.disposition {
		case susePackageOpen:
			result.affected = append(result.affected, advisory.AffectedPackage{
				Ecosystem:     ecosystem,
				Package:       pkg,
				Ranges:        []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}}}},
				Architectures: status.architectures,
			})
		case susePackageFixed:
			result.affected = append(result.affected, advisory.AffectedPackage{
				Ecosystem:     ecosystem,
				Package:       pkg,
				Ranges:        []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: status.fixedVersion}}}},
				FixedVersion:  status.fixedVersion,
				Architectures: status.architectures,
			})
		case susePackageNotAffected:
			result.notAffected = append(result.notAffected, key)
		}
	}
	return result, true, nil
}

func suseOrdinaryServerPlatform(d *ovalDefinition) bool {
	for _, platform := range d.Platforms {
		platform = strings.ToLower(strings.TrimSpace(platform))
		if strings.HasPrefix(platform, "suse linux enterprise server ") &&
			!strings.Contains(platform, "sap applications") &&
			!strings.HasSuffix(platform, "-ltss") {
			return true
		}
	}
	return false
}

func suseLifecycleClauses(root *ovalCriteria) ([]ovalCriteria, bool) {
	if root == nil || !ovalFalseOrEmpty(root.Negate) || len(root.Other) != 0 {
		return nil, false
	}
	switch strings.ToUpper(strings.TrimSpace(root.Operator)) {
	case "AND":
		return []ovalCriteria{*root}, true
	case "OR":
		if len(root.Criterion) != 0 || len(root.Criteria) == 0 {
			return nil, false
		}
		clauses := make([]ovalCriteria, len(root.Criteria))
		copy(clauses, root.Criteria)
		for i := range clauses {
			if strings.ToUpper(strings.TrimSpace(clauses[i].Operator)) != "AND" {
				return nil, false
			}
		}
		return clauses, true
	default:
		return nil, false
	}
}

func suseLifecycleClause(clause *ovalCriteria, major string, declaredProducts map[string]struct{}, tests map[string]ovalTest, objects map[string]ovalObject, states map[string]ovalState) (bool, []susePackageStatus, bool) {
	if clause == nil || strings.ToUpper(strings.TrimSpace(clause.Operator)) != "AND" || !ovalFalseOrEmpty(clause.Negate) || len(clause.Other) != 0 {
		return false, nil, false
	}
	items := make([]suseCriteriaItem, 0, len(clause.Criteria)+len(clause.Criterion))
	for i := range clause.Criteria {
		items = append(items, suseCriteriaItem{criteria: &clause.Criteria[i]})
	}
	for i := range clause.Criterion {
		items = append(items, suseCriteriaItem{criterion: &clause.Criterion[i]})
	}
	if len(items) != 2 {
		return false, nil, false
	}

	productIndex := -1
	ordinary := false
	for i, item := range items {
		valid, itemOrdinary := suseProductItem(item, major, declaredProducts, tests, objects, states)
		if !valid {
			continue
		}
		if productIndex != -1 {
			return false, nil, false
		}
		productIndex = i
		ordinary = itemOrdinary
	}
	if productIndex == -1 {
		return false, nil, false
	}
	if !ordinary {
		return false, nil, true // a fully identified LTSS/SAP clause is not ordinary SLES applicability
	}
	packageIndex := 1 - productIndex
	statuses, ok := susePackageItem(items[packageIndex], tests, objects, states)
	if !ok || len(statuses) == 0 {
		return false, nil, false
	}
	return true, statuses, true
}

func suseProductItem(item suseCriteriaItem, major string, declaredProducts map[string]struct{}, tests map[string]ovalTest, objects map[string]ovalObject, states map[string]ovalState) (bool, bool) {
	if item.criterion != nil {
		return suseProductCriterion(*item.criterion, major, declaredProducts, tests, objects, states)
	}
	group := item.criteria
	if group == nil || strings.ToUpper(strings.TrimSpace(group.Operator)) != "OR" || !ovalFalseOrEmpty(group.Negate) || len(group.Criteria) != 0 || len(group.Other) != 0 || len(group.Criterion) == 0 {
		return false, false
	}
	ordinary := false
	for _, criterion := range group.Criterion {
		valid, itemOrdinary := suseProductCriterion(criterion, major, declaredProducts, tests, objects, states)
		if !valid {
			return false, false
		}
		ordinary = ordinary || itemOrdinary
	}
	return true, ordinary
}

func suseProductCriterion(criterion ovalCriterion, major string, declaredProducts map[string]struct{}, tests map[string]ovalTest, objects map[string]ovalObject, states map[string]ovalState) (bool, bool) {
	if !suseCriterionShape(criterion) {
		return false, false
	}
	comment := strings.TrimSpace(criterion.Comment)
	if _, ok := declaredProducts[comment]; !ok {
		return false, false
	}
	if !suseOrdinaryServerComment(comment, major) {
		return true, false
	}
	test, ok := tests[strings.TrimSpace(criterion.TestRef)]
	if !ok || !suseTestShape(test) {
		return false, false
	}
	objectRef, stateRef, _ := test.refs()
	name, ok := suseLiteralObject(objects[objectRef])
	if !ok || !suseReleaseObject(name) || strings.TrimSpace(test.Comment) != name+" is =="+major {
		return false, false
	}
	state, ok := states[stateRef]
	if !ok || !rpmElement(state.XMLName, "rpminfo_state") || len(state.Versions) != 1 || len(state.EVRs) != 0 || len(state.Architectures) != 0 || len(state.Signatures) != 0 || len(state.Other) != 0 {
		return false, false
	}
	if !suseVersionEquals(state.Versions[0], major) || name != "sles-release" {
		return false, false
	}
	return true, true
}

func suseOrdinaryServerComment(comment, major string) bool {
	platform, ok := strings.CutSuffix(strings.TrimSpace(comment), " is installed")
	if !ok || slePlatformRelease(platform) != major {
		return false
	}
	platform = strings.ToLower(platform)
	return strings.HasPrefix(platform, "suse linux enterprise server ") &&
		!strings.Contains(platform, "sap applications") &&
		!strings.HasSuffix(platform, "-ltss")
}

func suseDeclaredProductComments(d *ovalDefinition, major string) map[string]struct{} {
	comments := map[string]struct{}{}
	for _, platform := range d.Platforms {
		platform = strings.TrimSpace(platform)
		if platform != "" && suseDeclaredProductRelease(platform) == major {
			comments[platform+" is installed"] = struct{}{}
		}
	}
	return comments
}

func suseDeclaredProductRelease(platform string) string {
	s := strings.ToLower(strings.TrimSpace(platform))
	if !strings.HasPrefix(s, "suse ") {
		return ""
	}
	return sleReleaseSuffix(s)
}

func suseReleaseObject(name string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(name)), "-release")
}

func suseVersionEquals(version ovalEVR, want string) bool {
	datatype := strings.ToLower(strings.TrimSpace(version.Datatype))
	return rpmElement(version.XMLName, "version") &&
		(datatype == "" || datatype == "version") &&
		strings.EqualFold(strings.TrimSpace(version.Operation), "equals") &&
		strings.TrimSpace(version.Value) == want
}

func susePackageItem(item suseCriteriaItem, tests map[string]ovalTest, objects map[string]ovalObject, states map[string]ovalState) ([]susePackageStatus, bool) {
	if item.criterion != nil {
		status, ok := susePackageCriterion(*item.criterion, tests, objects, states)
		if !ok {
			return nil, false
		}
		return []susePackageStatus{status}, true
	}
	return susePackageCriteria(item.criteria, tests, objects, states, 0)
}

func susePackageCriteria(group *ovalCriteria, tests map[string]ovalTest, objects map[string]ovalObject, states map[string]ovalState, depth int) ([]susePackageStatus, bool) {
	if group == nil || depth > maxCriteriaDepth || !ovalFalseOrEmpty(group.Negate) || len(group.Other) != 0 {
		return nil, false
	}
	operator := strings.ToUpper(strings.TrimSpace(group.Operator))
	if operator != "AND" && operator != "OR" {
		return nil, false
	}
	itemCount := len(group.Criterion) + len(group.Criteria)
	if itemCount == 0 {
		return nil, false
	}
	statuses := make([]susePackageStatus, 0, itemCount)
	for _, criterion := range group.Criterion {
		status, ok := susePackageCriterion(criterion, tests, objects, states)
		if !ok {
			return nil, false
		}
		statuses = append(statuses, status)
	}
	for i := range group.Criteria {
		nested, ok := susePackageCriteria(&group.Criteria[i], tests, objects, states, depth+1)
		if !ok {
			return nil, false
		}
		statuses = append(statuses, nested...)
	}
	if operator == "AND" && itemCount > 1 {
		for i := range statuses {
			statuses[i].disposition = susePackageSuppressed
		}
	}
	return statuses, true
}

func susePackageCriterion(criterion ovalCriterion, tests map[string]ovalTest, objects map[string]ovalObject, states map[string]ovalState) (susePackageStatus, bool) {
	if !suseCriterionShape(criterion) {
		return susePackageStatus{}, false
	}
	test, ok := tests[strings.TrimSpace(criterion.TestRef)]
	if !ok || !suseScopedPackageTest(test) {
		return susePackageStatus{}, false
	}
	objectRef, stateRef, _ := test.refs()
	pkg, ok := suseLiteralObject(objects[objectRef])
	if !ok || suseReleaseObject(pkg) {
		return susePackageStatus{}, false
	}
	state, ok := states[stateRef]
	if !ok || !suseScopedPackageState(state) {
		return susePackageStatus{}, false
	}
	criterionComment := strings.TrimSpace(criterion.Comment)
	testComment := strings.TrimSpace(test.Comment)
	if !susePackageCommentsBound(pkg, criterionComment, testComment) {
		return susePackageStatus{}, false
	}

	fixed := ""
	if len(state.EVRs) == 1 && len(state.Versions) == 0 {
		evr := state.EVRs[0]
		candidate := strings.TrimSpace(evr.Value)
		if rpmElement(evr.XMLName, "evr") && strings.EqualFold(strings.TrimSpace(evr.Datatype), "evr_string") && strings.EqualFold(strings.TrimSpace(evr.Operation), "less than") && candidate != "" && !isDebianZeroBound(candidate) {
			fixed = candidate
		}
	}
	// An architecture predicate is authoritative applicability evidence, not a reason to discard the package
	// fact. It is read into an exact architecture set that is carried on the affected block and enforced at
	// match time, so "libacl1-32bit for (x86_64)" binds to x86_64 only and can never match aarch64. A
	// predicate we cannot read exactly still suppresses, preserving fail-closed behavior for unsupported or
	// ambiguous architecture syntax.
	architectures := []string(nil)
	if len(state.Architectures) != 0 {
		parsed, ok := suseArchitectures(state.Architectures)
		if !ok {
			return susePackageStatus{packageName: pkg, disposition: susePackageSuppressed, fixedVersion: fixed}, true
		}
		architectures = parsed
	}
	if !strings.EqualFold(strings.TrimSpace(test.Check), "at least one") {
		return susePackageStatus{packageName: pkg, disposition: susePackageSuppressed, fixedVersion: fixed}, true
	}
	if len(state.EVRs) == 1 && len(state.Versions) == 0 {
		evr := state.EVRs[0]
		if rpmElement(evr.XMLName, "evr") && strings.EqualFold(strings.TrimSpace(evr.Datatype), "evr_string") && strings.EqualFold(strings.TrimSpace(evr.Operation), "greater than") && strings.TrimSpace(evr.Value) == "0:0-0" && strings.EqualFold(criterionComment, pkg+" is affected") && strings.EqualFold(testComment, pkg+" is >0") {
			return susePackageStatus{packageName: pkg, disposition: susePackageOpen, architectures: architectures}, true
		}
		if fixed != "" && suseFixedComments(pkg, fixed, criterionComment, testComment, architectures) {
			return susePackageStatus{packageName: pkg, disposition: susePackageFixed, fixedVersion: fixed, architectures: architectures}, true
		}
	}
	if len(state.Versions) == 1 && len(state.EVRs) == 0 {
		if suseVersionEquals(state.Versions[0], "0") && strings.EqualFold(criterionComment, pkg+" is not affected") && strings.EqualFold(testComment, pkg+" is ==0") {
			return susePackageStatus{packageName: pkg, disposition: susePackageNotAffected, architectures: architectures}, true
		}
	}
	return susePackageStatus{packageName: pkg, disposition: susePackageSuppressed, fixedVersion: fixed}, true
}

func suseScopedPackageTest(test ovalTest) bool {
	if !rpmElement(test.XMLName, "rpminfo_test") || len(test.Other) != 0 || len(test.Objects) != 1 || len(test.States) != 1 {
		return false
	}
	if !rpmElement(test.Objects[0].XMLName, "object") || !rpmElement(test.States[0].XMLName, "state") {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(test.Check)) {
	case "at least one", "all", "none satisfy":
	default:
		return false
	}
	checkExistence := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(test.CheckExistence), "_", " "))
	if checkExistence != "" && checkExistence != "at least one exists" {
		return false
	}
	stateOperator := strings.ToUpper(strings.TrimSpace(test.StateOperator))
	if stateOperator != "" && stateOperator != "AND" {
		return false
	}
	_, _, ok := test.refs()
	return ok
}

// suseArchLiteral matches the ONLY architecture predicate shape the SUSE feed publishes: a parenthesised
// alternation of literal architecture tokens, optionally a single bare token. Verified against the frozen
// SLES 15 SP6 feed: all 9463 arch predicates are operation="pattern match" datatype="string" and every one
// matches this shape, across 23 distinct values such as "(aarch64|ppc64le|s390x|x86_64)", "(noarch)" and
// "(x86_64)". Anything else is an unsupported regular expression and must fail closed rather than be
// approximated, because a misread architecture set would either over-match a foreign architecture or
// silently drop real applicability.
var suseArchLiteral = regexp.MustCompile(`^\(?[a-z0-9_]+(\|[a-z0-9_]+)*\)?$`)

// suseArchitectures converts an OVAL architecture predicate into an exact, authoritative architecture set.
//
// It returns ok=false for any predicate it cannot read exactly: a non-"pattern match" operation, a
// non-"string" datatype, an empty value, or a value carrying regular-expression syntax beyond a literal
// alternation (anchors, character classes, quantifiers, wildcards, nested groups). The caller must suppress
// such evidence instead of guessing, which preserves the parser's fail-closed contract for unsupported,
// malformed, or ambiguous input.
func suseArchitectures(states []ovalEVR) ([]string, bool) {
	architectures := make([]string, 0, len(states))
	for _, state := range states {
		if !rpmElement(state.XMLName, "arch") {
			return nil, false
		}
		if !strings.EqualFold(strings.TrimSpace(state.Datatype), "string") {
			return nil, false
		}
		if !strings.EqualFold(strings.TrimSpace(state.Operation), "pattern match") {
			return nil, false
		}
		value := strings.ToLower(strings.TrimSpace(state.Value))
		if value == "" || !suseArchLiteral.MatchString(value) {
			return nil, false
		}
		// A parenthesis may appear only as a balanced wrapper around the whole alternation.
		open := strings.Count(value, "(")
		closed := strings.Count(value, ")")
		if open != closed || open > 1 {
			return nil, false
		}
		if open == 1 && !(strings.HasPrefix(value, "(") && strings.HasSuffix(value, ")")) {
			return nil, false
		}
		for _, token := range strings.Split(strings.Trim(value, "()"), "|") {
			if token == "" {
				return nil, false
			}
			architectures = append(architectures, token)
		}
	}
	if len(architectures) == 0 {
		return nil, false
	}
	sort.Strings(architectures)
	return architectures, true
}

func suseScopedPackageState(state ovalState) bool {
	if !rpmElement(state.XMLName, "rpminfo_state") || len(state.Signatures) != 0 || len(state.Other) != 0 || len(state.EVRs)+len(state.Versions) == 0 {
		return false
	}
	for _, evr := range state.EVRs {
		if !rpmElement(evr.XMLName, "evr") || !strings.EqualFold(strings.TrimSpace(evr.Datatype), "evr_string") || strings.TrimSpace(evr.Operation) == "" || strings.TrimSpace(evr.Value) == "" {
			return false
		}
	}
	for _, version := range state.Versions {
		if !rpmElement(version.XMLName, "version") || strings.TrimSpace(version.Operation) == "" || strings.TrimSpace(version.Value) == "" {
			return false
		}
		datatype := strings.ToLower(strings.TrimSpace(version.Datatype))
		if datatype != "" && datatype != "version" {
			return false
		}
	}
	for _, arch := range state.Architectures {
		if !rpmElement(arch.XMLName, "arch") || !strings.EqualFold(strings.TrimSpace(arch.Datatype), "string") || !strings.EqualFold(strings.TrimSpace(arch.Operation), "pattern match") || strings.TrimSpace(arch.Value) == "" {
			return false
		}
	}
	return true
}

func susePackageCommentsBound(pkg, criterionComment, testComment string) bool {
	pkg = strings.ToLower(strings.TrimSpace(pkg))
	criterionComment = strings.ToLower(strings.TrimSpace(criterionComment))
	testComment = strings.ToLower(strings.TrimSpace(testComment))
	criterionBound := strings.HasPrefix(criterionComment, pkg+" is ") ||
		strings.HasPrefix(criterionComment, "no "+pkg+" is ") ||
		((strings.HasPrefix(criterionComment, pkg+"-") || strings.HasPrefix(criterionComment, pkg+" ")) &&
			strings.HasSuffix(criterionComment, " is installed"))
	return criterionBound && strings.HasPrefix(testComment, pkg+" is ")
}

// suseFixedComments verifies that a bounded SLES package criterion's human-readable comments agree with the
// machine-readable boundary, so a mismatched or reused comment cannot bind a package to the wrong fix.
//
// An architecture-scoped criterion states its architectures in the test comment, e.g.
// "libacl1 is <0:2.4.0-150000.4.6.1 for aarch64,ppc64le,s390x,x86_64". architectures carries the set already
// parsed from the state's arch predicate, and the suffix must name exactly that set: this cross-checks the
// prose against the predicate instead of discarding it, so a comment that disagrees with the predicate fails
// closed rather than binding. A nil/empty set requires the plain, suffix-free comment.
func suseFixedComments(pkg, fixed, criterionComment, testComment string, architectures []string) bool {
	withoutEpoch := fixed
	if _, rest, ok := strings.Cut(fixed, ":"); ok {
		withoutEpoch = rest
	}
	criterionOK := strings.EqualFold(criterionComment, pkg+"-"+fixed+" is installed") || strings.EqualFold(criterionComment, pkg+"-"+withoutEpoch+" is installed")
	if !criterionOK {
		return false
	}
	suffixes := []string{""}
	if len(architectures) != 0 {
		// The feed lists the architectures comma-separated in ascending order, which is the order
		// suseArchitectures already produced.
		suffixes = append(suffixes, " for "+strings.Join(architectures, ","))
	}
	for _, suffix := range suffixes {
		if strings.EqualFold(testComment, pkg+" is <"+fixed+suffix) || strings.EqualFold(testComment, pkg+" is <"+withoutEpoch+suffix) {
			return true
		}
	}
	return false
}

func suseCriterionShape(criterion ovalCriterion) bool {
	return strings.TrimSpace(criterion.TestRef) != "" && ovalFalseOrEmpty(criterion.Negate) && strings.TrimSpace(criterion.ApplicabilityCheck) == ""
}

func suseTestShape(test ovalTest) bool {
	return rpmTestShape(test) && strings.EqualFold(strings.TrimSpace(test.Check), "at least one")
}

func suseLiteralObject(object ovalObject) (string, bool) {
	if !rpmElement(object.XMLName, "rpminfo_object") || len(object.Names) != 1 || len(object.Other) != 0 {
		return "", false
	}
	name := object.Names[0]
	if !rpmElement(name.XMLName, "name") || strings.TrimSpace(name.VarRef) != "" || strings.TrimSpace(name.Operation) != "" || strings.TrimSpace(name.Datatype) != "" {
		return "", false
	}
	value := strings.TrimSpace(name.Value)
	return value, value != ""
}

func ovalFalseOrEmpty(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "" || value == "false"
}

func ovalCriteriaAbsent(criteria *ovalCriteria) bool {
	return criteria != nil && strings.TrimSpace(criteria.Operator) == "" && strings.TrimSpace(criteria.Negate) == "" && strings.TrimSpace(criteria.Comment) == "" && len(criteria.Criteria) == 0 && len(criteria.Criterion) == 0 && len(criteria.Other) == 0
}

func suseLifecycleSignal(criteria *ovalCriteria, tests map[string]ovalTest) bool {
	found := false
	walkCriteria(criteria, 0, func(criterion ovalCriterion) {
		comment := strings.ToLower(strings.TrimSpace(criterion.Comment))
		if strings.HasSuffix(comment, " is affected") || strings.HasSuffix(comment, " is not affected") {
			found = true
			return
		}
		if test, ok := tests[strings.TrimSpace(criterion.TestRef)]; ok {
			testComment := strings.ToLower(strings.TrimSpace(test.Comment))
			if strings.HasSuffix(testComment, " is >0") || strings.HasSuffix(testComment, " is ==0") || strings.Contains(testComment, " is <") {
				found = true
			}
		}
	})
	return found
}

func walkCriteria(criteria *ovalCriteria, depth int, visit func(ovalCriterion)) {
	if criteria == nil || depth > maxCriteriaDepth || visit == nil {
		return
	}
	for _, criterion := range criteria.Criterion {
		visit(criterion)
	}
	for i := range criteria.Criteria {
		walkCriteria(&criteria.Criteria[i], depth+1, visit)
	}
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
// "<major> SP<sp>" or "<major> SP<sp>-LTSS" yields "<major>.<sp>" (SP6 → 15.6), a bare trailing "<major>"
// yields "<major>", and an already-dotted "<major>.<minor>" (SLE 16.0) is returned as-is. This matches the sles-<major.minor> inventory
// key (per service pack), so a fixed NEVR is never applied across service packs. A non-SLE platform returns "".
func slePlatformRelease(platform string) string {
	s := strings.ToLower(strings.TrimSpace(platform))
	if !strings.HasPrefix(s, "suse linux enterprise") {
		return ""
	}
	return sleReleaseSuffix(s)
}

func sleReleaseSuffix(platform string) string {
	fields := strings.Fields(platform)
	if len(fields) < 2 {
		return ""
	}
	last := strings.TrimSuffix(fields[len(fields)-1], "-ltss")
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

// buildOVALAdvisory resolves one deb-family definition. represented=false with no error is reserved for
// definitions positively outside the CVE projection; a supported CVE definition that cannot be represented
// exactly rejects the complete authoritative snapshot.
func buildOVALAdvisory(d *ovalDefinition, ecosystem string, tests map[string]ovalTest, objects map[string][]string, objectDefs map[string]ovalObject, states map[string]ovalState) (advisory.Advisory, bool, error) {
	if d.Class != "" && d.Class != "vulnerability" {
		return advisory.Advisory{}, false, nil
	}
	cves := make([]string, 0, len(d.References))
	for _, r := range d.References {
		if r.Source == "CVE" && strings.HasPrefix(r.RefID, "CVE-") {
			cves = append(cves, r.RefID)
		}
	}
	if len(cves) == 0 {
		return advisory.Advisory{}, false, nil
	}
	if len(cves) != 1 {
		return advisory.Advisory{}, false, fmt.Errorf("%w: deb OVAL definition %q names multiple CVEs", shared.ErrValidation, d.ID)
	}
	if err := validateDebDefinitionScope(d, ecosystem); err != nil {
		return advisory.Advisory{}, false, fmt.Errorf("%w: deb OVAL definition %q for %s: %v", shared.ErrValidation, d.ID, cves[0], err)
	}
	affected, suppressed, err := debCriteriaAffected(&d.Criteria, ecosystem, tests, objects, objectDefs, states, 0)
	if err != nil {
		return advisory.Advisory{}, false, fmt.Errorf("%w: deb OVAL definition %q for %s is unrepresentable: %v", shared.ErrValidation, d.ID, cves[0], err)
	}
	if len(affected) == 0 && !suppressed {
		return advisory.Advisory{}, false, fmt.Errorf("%w: deb OVAL definition %q for %s has no representable package applicability", shared.ErrValidation, d.ID, cves[0])
	}
	return advisory.Advisory{
		ID:        cves[0],
		Summary:   strings.TrimSpace(d.Title),
		CVSSScore: ovalSeverityScore(d.Severity),
		Affected:  affected,
	}, true, nil
}

func validateDebDefinitionScope(d *ovalDefinition, ecosystem string) error {
	if strings.HasPrefix(ecosystem, "Ubuntu:") {
		if !strings.HasPrefix(d.ID, "oval:com.ubuntu.") {
			return fmt.Errorf("definition id is outside the Ubuntu family")
		}
		return nil
	}
	if strings.HasPrefix(ecosystem, "Debian:") {
		if !strings.HasPrefix(d.ID, "oval:org.debian") {
			return fmt.Errorf("definition id is outside the Debian family")
		}
		release := strings.TrimPrefix(ecosystem, "Debian:")
		for _, platform := range d.Platforms {
			if debianPlatformRelease(platform) == release {
				return nil
			}
		}
		return fmt.Errorf("definition does not declare Debian %s applicability", release)
	}
	return fmt.Errorf("unsupported deb ecosystem %q", ecosystem)
}

func debCriteriaAffected(criteria *ovalCriteria, ecosystem string, tests map[string]ovalTest, objects map[string][]string, objectDefs map[string]ovalObject, states map[string]ovalState, depth int) ([]advisory.AffectedPackage, bool, error) {
	facts, _, suppressed, err := debCriteriaFacts(criteria, ecosystem, tests, objects, objectDefs, states, depth)
	if err != nil {
		return nil, false, err
	}
	keys := make([]string, 0, len(facts))
	for key := range facts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	affected := make([]advisory.AffectedPackage, 0, len(keys))
	for _, key := range keys {
		affected = append(affected, facts[key])
	}
	return affected, suppressed, nil
}

func debCriteriaFacts(criteria *ovalCriteria, ecosystem string, tests map[string]ovalTest, objects map[string][]string, objectDefs map[string]ovalObject, states map[string]ovalState, depth int) (map[string]advisory.AffectedPackage, bool, bool, error) {
	if criteria == nil || depth > maxCriteriaDepth || !ovalFalseOrEmpty(criteria.Negate) || len(criteria.Other) != 0 {
		return nil, false, false, fmt.Errorf("unsupported criteria shape")
	}
	operator := strings.ToUpper(strings.TrimSpace(criteria.Operator))
	if operator == "" {
		operator = "AND"
	}
	if operator != "AND" && operator != "OR" {
		return nil, false, false, fmt.Errorf("unsupported criteria operator %q", criteria.Operator)
	}
	type branch struct {
		facts         map[string]advisory.AffectedPackage
		applicability bool
		suppressed    bool
	}
	branches := make([]branch, 0, len(criteria.Criterion)+len(criteria.Criteria))
	for _, criterion := range criteria.Criterion {
		facts, applicability, suppressed, err := debCriterionFacts(criterion, ecosystem, tests, objects, objectDefs, states)
		if err != nil {
			return nil, false, false, err
		}
		branches = append(branches, branch{facts: facts, applicability: applicability, suppressed: suppressed})
	}
	for i := range criteria.Criteria {
		facts, applicability, suppressed, err := debCriteriaFacts(&criteria.Criteria[i], ecosystem, tests, objects, objectDefs, states, depth+1)
		if err != nil {
			return nil, false, false, err
		}
		branches = append(branches, branch{facts: facts, applicability: applicability, suppressed: suppressed})
	}
	if len(branches) == 0 {
		return nil, false, false, fmt.Errorf("criteria group is empty")
	}
	if operator == "AND" {
		for _, current := range branches {
			if current.suppressed {
				return map[string]advisory.AffectedPackage{}, false, true, nil
			}
		}
	} else {
		active := branches[:0]
		for _, current := range branches {
			if !current.suppressed {
				active = append(active, current)
			}
		}
		if len(active) == 0 {
			return map[string]advisory.AffectedPackage{}, false, true, nil
		}
		branches = active
		allApplicability := true
		allPackages := true
		for _, current := range branches {
			allApplicability = allApplicability && current.applicability && len(current.facts) == 0
			allPackages = allPackages && !current.applicability && len(current.facts) > 0
		}
		if !allApplicability && !allPackages {
			return nil, false, false, fmt.Errorf("OR group mixes applicability and package predicates")
		}
	}
	out := map[string]advisory.AffectedPackage{}
	for _, current := range branches {
		for key, candidate := range current.facts {
			if existing, found := out[key]; found && existing.FixedVersion != candidate.FixedVersion {
				return nil, false, false, fmt.Errorf("conflicting fixed boundaries for %q", candidate.Package)
			}
			out[key] = candidate
		}
	}
	return out, len(out) == 0, false, nil
}

func debCriterionFacts(criterion ovalCriterion, ecosystem string, tests map[string]ovalTest, objects map[string][]string, objectDefs map[string]ovalObject, states map[string]ovalState) (map[string]advisory.AffectedPackage, bool, bool, error) {
	if !suseCriterionShape(criterion) {
		return nil, false, false, fmt.Errorf("unsupported criterion shape")
	}
	ref := strings.TrimSpace(criterion.TestRef)
	test, ok := tests[ref]
	if !ok {
		if debApplicabilityCriterion(criterion, ecosystem) {
			return map[string]advisory.AffectedPackage{}, true, false, nil
		}
		return nil, false, false, fmt.Errorf("unresolved test %q", ref)
	}
	if !debTestShape(test) {
		return nil, false, false, fmt.Errorf("unsupported dpkg test %q", ref)
	}
	objectRef, stateRef, _ := test.refs()
	object, objectOK := objectDefs[objectRef]
	state, stateOK := states[stateRef]
	packages := objects[objectRef]
	if !objectOK || !stateOK || !debObjectShape(object, packages) {
		return nil, false, false, fmt.Errorf("unsupported dpkg object or state for test %q", ref)
	}
	fixed, suppressed, err := debFixedBoundary(state)
	if err != nil {
		return nil, false, false, fmt.Errorf("test %q: %w", ref, err)
	}
	if suppressed {
		return map[string]advisory.AffectedPackage{}, false, true, nil
	}
	facts := make(map[string]advisory.AffectedPackage, len(packages))
	for _, pkg := range packages {
		key := ecosystem + "\x00" + pkg
		facts[key] = advisory.AffectedPackage{
			Ecosystem:    ecosystem,
			Package:      pkg,
			Ranges:       []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}},
			FixedVersion: fixed,
		}
	}
	return facts, false, false, nil
}

func debApplicabilityCriterion(criterion ovalCriterion, ecosystem string) bool {
	comment := strings.ToLower(strings.TrimSpace(criterion.Comment))
	if comment == "all architecture" {
		return true
	}
	if strings.HasPrefix(ecosystem, "Debian:") {
		release := strings.TrimPrefix(ecosystem, "Debian:")
		return comment == strings.ToLower("Debian "+release+" is installed")
	}
	if strings.HasPrefix(ecosystem, "Ubuntu:") {
		release := strings.TrimPrefix(ecosystem, "Ubuntu:")
		return comment == strings.ToLower("Ubuntu "+release+" is installed") || comment == strings.ToLower("Ubuntu "+release+" LTS is installed")
	}
	return false
}

func debTestShape(test ovalTest) bool {
	if !rpmElement(test.XMLName, "dpkginfo_test") || len(test.Other) != 0 || len(test.Objects) != 1 || len(test.States) != 1 {
		return false
	}
	if !rpmElement(test.Objects[0].XMLName, "object") || !rpmElement(test.States[0].XMLName, "state") {
		return false
	}
	check := strings.ToLower(strings.TrimSpace(test.Check))
	if check != "all" && check != "at least one" {
		return false
	}
	checkExistence := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(test.CheckExistence), "_", " "))
	if checkExistence != "" && checkExistence != "at least one exists" {
		return false
	}
	stateOperator := strings.ToUpper(strings.TrimSpace(test.StateOperator))
	if stateOperator != "" && stateOperator != "AND" {
		return false
	}
	_, _, ok := test.refs()
	return ok
}

func debObjectShape(object ovalObject, packages []string) bool {
	if !rpmElement(object.XMLName, "dpkginfo_object") || len(object.Names) != 1 || len(object.Other) != 0 || len(packages) == 0 {
		return false
	}
	name := object.Names[0]
	if !rpmElement(name.XMLName, "name") || strings.TrimSpace(name.Operation) != "" || strings.TrimSpace(name.Datatype) != "" {
		return false
	}
	literal := strings.TrimSpace(name.Value)
	variable := strings.TrimSpace(name.VarRef)
	return literal != "" && variable == "" || literal == "" && variable != ""
}

func debFixedBoundary(state ovalState) (string, bool, error) {
	if !rpmElement(state.XMLName, "dpkginfo_state") || len(state.Architectures) != 0 || len(state.Signatures) != 0 || len(state.Other) != 0 {
		return "", false, fmt.Errorf("unsupported dpkg state shape")
	}
	operation, value, ok := state.fixed()
	if !ok {
		return "", false, fmt.Errorf("missing or ambiguous fixed boundary")
	}
	for _, candidate := range append(append([]ovalEVR{}, state.Versions...), state.EVRs...) {
		if candidate.XMLName.Space != ovalLinuxNamespace || (candidate.XMLName.Local != "version" && candidate.XMLName.Local != "evr") || !strings.EqualFold(strings.TrimSpace(candidate.Datatype), "debian_evr_string") {
			return "", false, fmt.Errorf("unsupported fixed boundary element")
		}
	}
	fixed := strings.TrimSpace(value)
	if !strings.EqualFold(strings.TrimSpace(operation), "less than") || fixed == "" {
		return "", false, fmt.Errorf("fixed boundary is not an exact upper bound")
	}
	if isDebianZeroBound(fixed) {
		return "", true, nil
	}
	return fixed, false, nil
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
