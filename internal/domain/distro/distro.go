// Package distro captures the operating-system distribution of a scanned target (from its OS
// packages) and flags releases that are past End-of-Life – i.e. no longer receiving security
// updates, a first-class posture finding for a container/host scan. It is LLM-free and
// deterministic: the EOL dates are a curated, source-cited snapshot (endoflife.date), and a release
// the table does not know is reported as "unknown" – never guessed EOL (fail-open on
// the negative claim: we never assert "supported" or "EOL" without data).
package distro

import (
	"strings"
	"time"
)

// Release identifies a distribution release, e.g. {ID: "debian", Version: "9", Codename: "stretch"}.
// Version is normalised to the granularity the EOL table is keyed by (Debian: major; Ubuntu/Alpine:
// major.minor).
type Release struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	Codename string `json:"codename,omitempty"`
}

// Status is a Release plus its End-of-Life verdict as of a given time. Known=false means the curated
// table has no entry for the release, so EndOfLife is not asserted (neither EOL nor "supported").
type Status struct {
	Release
	EndOfLife bool   `json:"end_of_life"`
	EOLDate   string `json:"eol_date,omitempty"` // the release's EOL date (YYYY-MM-DD) when known
	Known     bool   `json:"known"`
	Source    string `json:"source,omitempty"` // provenance of the EOL date
}

// eolSource is the provenance cited for every EOL date below.
const eolSource = "endoflife.date (curated snapshot 2026-06)"

// eolDates is the curated End-of-Life table, keyed "id:version". Dates are the end of FREE security
// support (Debian/Ubuntu LTS end; Alpine 2-year window) – deliberately conservative so a release is
// only flagged EOL once even paid/extended support has lapsed for the common case. Source:
// endoflife.date. A release absent here is reported Known=false (no EOL claim).
var eolDates = map[string]string{
	// Debian – LTS end-of-life (https://endoflife.date/debian)
	"debian:7":  "2018-05-31",
	"debian:8":  "2020-06-30",
	"debian:9":  "2022-06-30",
	"debian:10": "2024-06-30",
	"debian:11": "2026-08-31",
	"debian:12": "2028-06-30",
	// Ubuntu – end of standard support, excluding paid ESM (https://endoflife.date/ubuntu)
	"ubuntu:14.04": "2019-04-30",
	"ubuntu:16.04": "2021-04-30",
	"ubuntu:18.04": "2023-05-31",
	"ubuntu:20.04": "2025-05-31",
	"ubuntu:22.04": "2027-06-01",
	"ubuntu:24.04": "2029-05-31",
	// Alpine – 2-year support window (https://endoflife.date/alpine)
	"alpine:3.14": "2023-05-01",
	"alpine:3.15": "2023-11-01",
	"alpine:3.16": "2024-05-23",
	"alpine:3.17": "2024-11-22",
	"alpine:3.18": "2025-05-09",
	"alpine:3.19": "2025-11-01",
	"alpine:3.20": "2026-04-01",
	"alpine:3.21": "2026-11-01",
	"alpine:3.22": "2027-05-01",
	// CentOS – note the early CentOS 8 EOL (https://endoflife.date/centos)
	"centos:7": "2024-06-30",
	"centos:8": "2021-12-31",
}

// codenames maps releases to their well-known codename (display only).
var codenames = map[string]string{
	"debian:7": "wheezy", "debian:8": "jessie", "debian:9": "stretch", "debian:10": "buster",
	"debian:11": "bullseye", "debian:12": "bookworm", "debian:13": "trixie",
	"ubuntu:14.04": "trusty", "ubuntu:16.04": "xenial", "ubuntu:18.04": "bionic",
	"ubuntu:20.04": "focal", "ubuntu:22.04": "jammy", "ubuntu:24.04": "noble",
}

// ParseTag parses a Syft "distro" PURL qualifier (e.g. "debian-9", "alpine-3.18.12", "ubuntu-22.04")
// into a Release, normalising the version to the EOL table's granularity. Returns ok=false for an
// empty/unrecognised tag.
func ParseTag(tag string) (Release, bool) {
	id, ver, ok := strings.Cut(strings.TrimSpace(tag), "-")
	if !ok || id == "" || ver == "" {
		return Release{}, false
	}
	id = strings.ToLower(id)
	switch id {
	case "debian", "rhel", "centos", "rocky", "almalinux", "fedora", "ol", "oracle", "amzn":
		ver = major(ver) // these are keyed by major release
	case "ubuntu", "alpine":
		ver = majorMinor(ver)
	}
	if ver == "" {
		return Release{}, false
	}
	r := Release{ID: id, Version: ver, Codename: codenames[id+":"+ver]}
	return r, true
}

// Detect picks the dominant release from a set of raw "distro" tags (each OS package carries one).
// The most frequent parseable tag wins; ties break deterministically by tag string. Returns ok=false
// when no tag parses (e.g. a non-OS scan).
func Detect(tags []string) (Release, bool) {
	counts := map[string]int{}
	for _, t := range tags {
		if _, ok := ParseTag(t); ok {
			counts[t]++
		}
	}
	best := ""
	for t, c := range counts {
		if best == "" || c > counts[best] || (c == counts[best] && t < best) {
			best = t
		}
	}
	if best == "" {
		return Release{}, false
	}
	return ParseTag(best)
}

// Evaluate returns the release's End-of-Life status as of asOf. A release the table does not know is
// Known=false (no EOL assertion either way).
func Evaluate(r Release, asOf time.Time) Status {
	st := Status{Release: r}
	date, ok := eolDates[r.ID+":"+r.Version]
	if !ok {
		return st // unknown release: do not claim EOL
	}
	d, err := time.Parse("2006-01-02", date)
	if err != nil {
		return st // malformed table entry → report unknown, never a date-less "supported"/"EOL" claim
	}
	st.Known = true
	st.EOLDate = date
	st.Source = eolSource
	st.EndOfLife = !asOf.Before(d) // EOL once asOf >= the EOL date (boundary inclusive)
	return st
}

// major returns the leading numeric component ("9.13" → "9", "9" → "9").
func major(v string) string {
	if i := strings.IndexByte(v, '.'); i >= 0 {
		return v[:i]
	}
	return v
}

// majorMinor returns the first two dot components ("3.18.12" → "3.18", "22.04" → "22.04").
func majorMinor(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return parts[0]
}
