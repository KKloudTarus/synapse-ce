package ownadvisory

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// This file parses a yum/dnf "updateinfo" errata feed (repodata updateinfo.xml[.gz]) into the owned normalized
// advisory shape. Amazon Linux publishes its ALAS security advisories only as updateinfo (there is no OVAL),
// so ingesting it natively gives Synapse offline, vendor-authoritative Amazon Linux OS-package detection
// independent of any scanner DB.
//
// Each <update type="security"> names its CVEs in <references type="cve"> and its FIXED packages
// (name + epoch:version-release) in <pkglist><collection>; the collection short/name identifies the release
// (amazon-linux-2 -> "2", amazon-linux-2023 -> "2023"). Each fixed package maps to a [0, evr) ECOSYSTEM range
// keyed "Amazon Linux:<release>", the key the scan side derives for an amzn rpm component, and the affected
// packages are UNIONED per CVE across updates so the store's upsert-by-id keeps every advisory's packages.
// Only a security update with a real CVE and a fixed package contributes; anything else is skipped.

type updateInfoUpdate struct {
	Type        string                 `xml:"type,attr"`
	ID          string                 `xml:"id"`
	Title       string                 `xml:"title"`
	Severity    string                 `xml:"severity"`
	References  []updateInfoRef        `xml:"references>reference"`
	Collections []updateInfoCollection `xml:"pkglist>collection"`
}

type updateInfoRef struct {
	Type string `xml:"type,attr"`
	ID   string `xml:"id,attr"`
}

type updateInfoCollection struct {
	Short    string          `xml:"short,attr"`
	Name     string          `xml:"name"`
	Packages []updateInfoPkg `xml:"package"`
}

type updateInfoPkg struct {
	Name    string `xml:"name,attr"`
	Epoch   string `xml:"epoch,attr"`
	Version string `xml:"version,attr"`
	Release string `xml:"release,attr"`
}

// ParseUpdateInfo parses one updateinfo errata document (optionally gzip/bzip2-compressed) into advisories. It
// returns an error only for an input it cannot soundly handle (bad XML, over-cap decompressed stream); the
// caller's hardened walk turns that into a per-file skip.
func ParseUpdateInfo(content []byte) ([]advisory.Advisory, error) {
	if int64(len(content)) > maxOVALFileBytes {
		return nil, fmt.Errorf("%w: updateinfo exceeds %d bytes", shared.ErrValidation, maxOVALFileBytes)
	}
	var r io.Reader = bytes.NewReader(content)
	var lr *io.LimitedReader
	switch {
	case bytes.HasPrefix(content, []byte("BZh")):
		lr = &io.LimitedReader{R: bzip2.NewReader(r), N: maxOVALDecompressed + 1}
		r = lr
	case bytes.HasPrefix(content, []byte{0x1f, 0x8b}):
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("parse updateinfo: gzip: %w", err)
		}
		lr = &io.LimitedReader{R: gz, N: maxOVALDecompressed + 1}
		r = lr
	}

	byCVE := map[string]*amazonAcc{}
	order := make([]string, 0)
	dec := xml.NewDecoder(r)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse updateinfo: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "update" {
			continue
		}
		var u updateInfoUpdate
		if err := dec.DecodeElement(&u, &se); err != nil {
			return nil, fmt.Errorf("decode updateinfo update: %w", err)
		}
		if !strings.EqualFold(strings.TrimSpace(u.Type), "security") {
			continue // only security errata carry a fixed-vulnerability boundary
		}
		cves := updateInfoCVEs(u)
		if len(cves) == 0 {
			continue
		}
		bindings := updateInfoBindings(u)
		if len(bindings) == 0 {
			continue
		}
		score := ovalSeverityScore(u.Severity)
		summary := strings.TrimSpace(u.Title)
		// Accumulate the SET of fixed versions per (CVE, ecosystem, package) across every security update: the
		// same CVE is often fixed for one package in several ALAS (a superseding higher fix, or a separate fix
		// per kernel lineage). Resolving to a single boundary at emit time (below) picks the max within a
		// lineage and skips a package fixed across multiple lineages, so no fixed version is silently narrowed
		// and no lineage-blind range false-matches.
		for _, cve := range cves {
			a := byCVE[cve]
			if a == nil {
				a = &amazonAcc{summary: summary, score: score, evrs: map[string]map[string]struct{}{}}
				byCVE[cve] = a
				order = append(order, cve)
			}
			if score > a.score {
				a.score = score
			}
			for _, b := range bindings {
				key := b.ecosystem + "\x00" + b.pkg
				set := a.evrs[key]
				if set == nil {
					set = map[string]struct{}{}
					a.evrs[key] = set
					a.order = append(a.order, key)
				}
				set[b.evr] = struct{}{}
			}
		}
	}
	if lr != nil && lr.N <= 0 {
		return nil, fmt.Errorf("%w: updateinfo decompressed stream exceeds %d bytes", shared.ErrValidation, maxOVALDecompressed)
	}
	out := make([]advisory.Advisory, 0, len(order))
	for _, cve := range order {
		a := byCVE[cve]
		var affected []advisory.AffectedPackage
		for _, key := range a.order {
			ecosystem, pkg, _ := strings.Cut(key, "\x00")
			fixed := resolveAmazonFixed(ecosystem, a.evrs[key])
			if fixed == "" {
				continue // no version, or fixed across multiple lineages: skip (a safe coverage gap)
			}
			affected = append(affected, advisory.AffectedPackage{
				Ecosystem:    ecosystem,
				Package:      pkg,
				Ranges:       []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}},
				FixedVersion: fixed,
			})
		}
		if len(affected) == 0 {
			continue
		}
		out = append(out, advisory.Advisory{ID: cve, Summary: a.summary, CVSSScore: a.score, Affected: affected})
	}
	return out, nil
}

type amazonAcc struct {
	summary string
	score   float64
	evrs    map[string]map[string]struct{} // "ecosystem\x00package" -> set of distinct fixed EVRs
	order   []string                       // "ecosystem\x00package" in first-seen order
}

// resolveAmazonFixed picks the single fixed boundary for a (CVE, package)'s set of fixed EVRs: the MAXIMUM
// when they all share an upstream lineage (a superseding fix supersedes the earlier ones), or "" when they
// span multiple lineages (e.g. a CVE fixed in both the 4.9 and 4.14 kernels). A lineage-blind [0, fixed) range
// over a multi-lineage set would false-match a package that is actually fixed in a different lineage, so it is
// dropped (a safe coverage gap) rather than emitted.
func resolveAmazonFixed(ecosystem string, evrs map[string]struct{}) string {
	lineages := map[string]bool{}
	max := ""
	for e := range evrs {
		lineages[rpmLineage(e)] = true
		if max == "" {
			max = e
			continue
		}
		if cmp, ok := advisory.CompareVersions(ecosystem, e, max); ok && cmp > 0 {
			max = e
		}
	}
	if len(lineages) > 1 {
		return ""
	}
	return max
}

// rpmLineage returns the upstream major.minor of an rpm EVR ("0:4.14.42-61.37.amzn2" -> "4.14"), the key used
// to decide whether a set of fixed versions belongs to one release stream.
func rpmLineage(evr string) string {
	v := evr
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[i+1:] // drop epoch
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v = v[:i] // upstream version only
	}
	parts := strings.SplitN(v, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return v
}

// updateInfoCVEs returns the update's distinct CVE references in order.
func updateInfoCVEs(u updateInfoUpdate) []string {
	seen := map[string]bool{}
	var out []string
	for _, ref := range u.References {
		if strings.EqualFold(strings.TrimSpace(ref.Type), "cve") && strings.HasPrefix(ref.ID, "CVE-") && !seen[ref.ID] {
			seen[ref.ID] = true
			out = append(out, ref.ID)
		}
	}
	return out
}

type amazonBinding struct {
	ecosystem string
	pkg       string
	evr       string
}

// updateInfoBindings resolves an update's fixed packages into raw (ecosystem, package, evr) bindings. The
// release is taken from each collection (amazon-linux-2 -> "2"); a package with no release, name, or version
// is skipped so a match always carries an actionable fixed version. De-duplication and lineage resolution
// happen at emit time (ParseUpdateInfo), across updates, so a superseding fix is not lost.
func updateInfoBindings(u updateInfoUpdate) []amazonBinding {
	var out []amazonBinding
	for _, c := range u.Collections {
		release := amazonRelease(c.Short, c.Name)
		if release == "" {
			continue // unrecognized collection: skip rather than key a package to an unknown release
		}
		ecosystem := "Amazon Linux:" + release
		for _, p := range c.Packages {
			name := strings.TrimSpace(p.Name)
			evr := rpmEVR(p.Epoch, p.Version, p.Release)
			if name == "" || evr == "" {
				continue
			}
			out = append(out, amazonBinding{ecosystem: ecosystem, pkg: name, evr: evr})
		}
	}
	return out
}

// amazonRelease extracts the Amazon Linux release from an updateinfo collection's short id
// ("amazon-linux-2" -> "2", "amazon-linux-2023" -> "2023"), falling back to the display name when it starts
// with "Amazon Linux " ("Amazon Linux 2" -> "2"). Both matches are ANCHORED so a non-Amazon collection (for
// example an "EPEL for Amazon Linux 2" name, or an "rhel-9" short) returns "" and is skipped, never keyed to
// an Amazon release.
func amazonRelease(short, name string) string {
	// The release token must be the COMPLETE remainder (all digits): a real Amazon collection is exactly
	// "amazon-linux-2" / "amazon-linux-2023" / "Amazon Linux 2". Requiring the whole remainder rejects a
	// look-alike with trailing text ("amazon-linux-2-epel", "Amazon Linux 2 EPEL") that must not be keyed to
	// an Amazon release.
	if v := strings.TrimPrefix(short, "amazon-linux-"); v != short && isAllDigits(v) {
		return v
	}
	const prefix = "amazon linux "
	trimmed := strings.TrimSpace(name)
	if strings.HasPrefix(strings.ToLower(trimmed), prefix) {
		if rest := strings.TrimSpace(trimmed[len(prefix):]); isAllDigits(rest) {
			return rest
		}
	}
	return ""
}

// isAllDigits reports whether s is a non-empty run of ASCII digits.
func isAllDigits(s string) bool {
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

// rpmEVR assembles an rpm epoch:version-release string from the updateinfo package attributes. The epoch
// defaults to 0 (the rpm convention) so the comparator orders it against an epoch-less installed version.
func rpmEVR(epoch, version, release string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return ""
	}
	epoch = strings.TrimSpace(epoch)
	if epoch == "" {
		epoch = "0"
	}
	evr := epoch + ":" + version
	if release = strings.TrimSpace(release); release != "" {
		evr += "-" + release
	}
	return evr
}
