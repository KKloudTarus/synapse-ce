package ownadvisory

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// This file parses an apk "secdb" security database (the JSON at secdb.alpinelinux.org/<rel>/<repo>.json for
// Alpine, packages.wolfi.dev/os/security.json for Wolfi, and the equivalent Chainguard feed) into the owned
// normalized advisory shape. The format is a flat list of packages, each with a "secfixes" map from a FIXED
// apk version to the vulnerability ids it fixes:
//
//	{"reponame":"wolfi","distroversion":"v3.19","packages":[
//	  {"pkg":{"name":"foo","secfixes":{"1.2.3-r0":["CVE-2024-1","GHSA-xxxx-xxxx-xxxx"], "0":["CVE-2023-9"]}}}]}
//
// Each real fixed version becomes a [0, fixed) ECOSYSTEM range keyed to the distro's ecosystem, the exact key
// the scan side derives for an apk component (Alpine:v3.19 / Wolfi / Chainguard), so an apk package matches by
// CVE against the vendor's own fixed version through the owned apk comparator. The affected packages are
// unioned per vulnerability id across the file so the advisory store's upsert-by-id keeps every package.
//
// The no-false-match bar: a secfix version of "0" is the apk convention for "triaged NOT affected" (the CVE was
// assessed as not applicable to this package), so it is SKIPPED rather than turned into a [0, 0) range that
// would false-match every installed version. Only a CVE or GHSA id is kept (a language-ecosystem GO-/RUSTSEC-
// id is left to the language SCA path and would mis-key an OS package); a vulnerability with no CVE/GHSA id is
// a safe coverage gap. When one id lists more than one distinct fixed version for a single package within one
// file (an ambiguous multi-branch fix the single-branch model cannot represent), that package is skipped rather
// than guessed.

// ghsaID matches a well-formed GHSA identifier (GitHub Security Advisory), the other universal advisory id in a
// secdb besides a CVE.
var ghsaID = regexp.MustCompile(`^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$`)

type secdbDoc struct {
	Reponame      string `json:"reponame"`
	DistroVersion string `json:"distroversion"`
	Packages      []struct {
		Pkg struct {
			Name     string              `json:"name"`
			Secfixes map[string][]string `json:"secfixes"`
		} `json:"pkg"`
	} `json:"packages"`
}

type secfixAcc struct {
	aliases map[string]struct{}
	fixed   map[string]map[string]struct{} // package name -> set of distinct fixed versions
	order   []string                       // package names in first-seen order
}

// ParseSecdb parses an apk secdb JSON document into advisories keyed by CVE (or GHSA when no CVE is listed).
func ParseSecdb(content []byte) ([]advisory.Advisory, error) {
	if int64(len(content)) > maxOVALFileBytes {
		return nil, fmt.Errorf("%w: secdb exceeds %d bytes", shared.ErrValidation, maxOVALFileBytes)
	}
	var doc secdbDoc
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("parse secdb: %w", err)
	}
	eco := secdbEcosystem(doc)
	if eco == "" {
		return nil, fmt.Errorf("%w: unrecognized secdb (reponame=%q distroversion=%q)", shared.ErrValidation, doc.Reponame, doc.DistroVersion)
	}
	byID := map[string]*secfixAcc{}
	var order []string
	for i := range doc.Packages {
		name := strings.TrimSpace(doc.Packages[i].Pkg.Name)
		if name == "" {
			continue
		}
		for fixedVer, ids := range doc.Packages[i].Pkg.Secfixes {
			fixedVer = strings.TrimSpace(fixedVer)
			if fixedVer == "" || fixedVer == "0" {
				continue // "0" is the "triaged not affected" marker, never an actionable fixed boundary
			}
			cves, ghsas := splitAdvisoryIDs(ids)
			universal := append(cves, ghsas...) // a CVE is preferred as the primary id, so list CVEs first
			if len(universal) == 0 {
				continue // no universal id: a language-only (GO/RUSTSEC) entry, a safe coverage gap for an OS feed
			}
			primary := universal[0]
			acc := byID[primary]
			if acc == nil {
				acc = &secfixAcc{aliases: map[string]struct{}{}, fixed: map[string]map[string]struct{}{}}
				byID[primary] = acc
				order = append(order, primary)
			}
			for _, id := range universal {
				if id != primary {
					acc.aliases[id] = struct{}{}
				}
			}
			set := acc.fixed[name]
			if set == nil {
				set = map[string]struct{}{}
				acc.fixed[name] = set
				acc.order = append(acc.order, name)
			}
			set[fixedVer] = struct{}{}
		}
	}
	out := make([]advisory.Advisory, 0, len(order))
	for _, primary := range order {
		acc := byID[primary]
		var affected []advisory.AffectedPackage
		for _, pkg := range acc.order {
			set := acc.fixed[pkg]
			if len(set) != 1 {
				continue // ambiguous multi-branch fix in one file: skip rather than emit a guessed range
			}
			var fixed string
			for f := range set {
				fixed = f
			}
			affected = append(affected, advisory.AffectedPackage{
				Ecosystem:    eco,
				Package:      pkg,
				Ranges:       []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}},
				FixedVersion: fixed,
			})
		}
		if len(affected) == 0 {
			continue
		}
		out = append(out, advisory.Advisory{ID: primary, Aliases: sortedAliasIDs(acc.aliases), Affected: affected})
	}
	return out, nil
}

// secdbEcosystem derives the advisory ecosystem a secdb file targets, the exact key the scan side derives for
// an apk component: Alpine keys by its release ("Alpine:v3.19"), while Wolfi and Chainguard are rolling and key
// by family name alone. An unrecognized shape returns "" (the whole file is skipped rather than mis-keyed).
func secdbEcosystem(doc secdbDoc) string {
	// reponame is authoritative: Wolfi and Chainguard key by family name regardless of any distroversion the
	// file carries. Checking reponame FIRST is what prevents a Wolfi feed that ships a stray distroversion from
	// being mis-keyed as Alpine (a false negative for Wolfi plus a foreign match against Alpine packages).
	switch strings.ToLower(strings.TrimSpace(doc.Reponame)) {
	case "wolfi":
		return "Wolfi"
	case "chainguard":
		return "Chainguard"
	}
	// Alpine's repos ("main"/"community") carry a "v3.19" distroversion; normalize to the
	// "Alpine:v<major>.<minor>" key the scan side keys on (drop a leading "v" and any patch segment).
	if dv := strings.TrimSpace(doc.DistroVersion); dv != "" {
		v := strings.TrimPrefix(dv, "v")
		p := strings.SplitN(v, ".", 3)
		if len(p) >= 2 && p[0] != "" && p[1] != "" {
			return "Alpine:v" + p[0] + "." + p[1]
		}
	}
	return ""
}

// splitAdvisoryIDs partitions a secfix's id list into CVE ids and GHSA ids (in order), dropping any other id
// scheme (GO-, RUSTSEC-, ...) that belongs to a language ecosystem rather than an OS package.
func splitAdvisoryIDs(ids []string) (cves, ghsas []string) {
	for _, id := range ids {
		switch {
		case cveID.MatchString(id):
			cves = append(cves, id)
		case ghsaID.MatchString(id):
			ghsas = append(ghsas, id)
		}
	}
	return cves, ghsas
}

func sortedAliasIDs(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
