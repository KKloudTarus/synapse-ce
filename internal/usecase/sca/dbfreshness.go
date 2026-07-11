package sca

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// dbFreshnessWarnings surfaces reference DBs whose captured date is older than maxAgeDays, so a scan running
// against stale advisory / risk data – a failed live fetch that fell back to a stale cache, or an
// air-gapped DB pinned to an old build – can't silently under-report or mis-prioritize. Trivy uses a stale
// DB SILENTLY under --skip-db-update (only a schema mismatch errors); Synapse warns, in keeping with its
// "no silent gap" posture. Dates that are absent or unparseable are skipped (never a false alarm), and
// maxAgeDays <= 0 disables the check. Deterministic: DB keys are sorted, so the warning order is stable.
func dbFreshnessWarnings(tv map[string]string, now time.Time, maxAgeDays int) []string {
	if maxAgeDays <= 0 || tv == nil {
		return nil
	}
	maxAge := time.Duration(maxAgeDays) * 24 * time.Hour
	var out []string
	warn := func(label, dateStr string, t time.Time) {
		if age := now.Sub(t); age > maxAge {
			out = append(out, fmt.Sprintf("%s is %d days old (built %s) – older than the %d-day freshness policy; re-sync so recent advisories / exploited-CVE data are not missed",
				label, int(age.Hours()/24), dateStr, maxAgeDays))
		}
	}
	// A DB is PRESENT but its date can't be read: don't skip silently (that would let the freshness guarantee
	// itself vanish if a feed changes its date format) – surface it so freshness is visibly unverifiable.
	unverifiable := func(label, dateStr string) string {
		return fmt.Sprintf("%s reports a build date %q in an unrecognized format – freshness cannot be verified; check the DB source", label, dateStr)
	}
	checkFixed := func(label, key, layout string) {
		v := strings.TrimSpace(tv[key])
		if v == "" {
			return // truly absent → a different concern (a missing DB), not this check's to flag
		}
		if t, err := time.Parse(layout, v); err == nil {
			warn(label, v, t)
		} else {
			out = append(out, unverifiable(label, v))
		}
	}
	// The risk-priority reference feeds (CISA KEV, FIRST EPSS): each carries the fetched/cached snapshot date.
	checkFixed("CISA KEV catalog", "kev-catalog", "2006.01.02")
	checkFixed("EPSS dataset", "epss-date", "2006-01-02")
	// Vulnerability-DB build dates (a "schema-N@<built>" label, e.g. Grype's pinned offline DB).
	var dbKeys []string
	for k := range tv {
		if strings.HasSuffix(k, "-db") {
			dbKeys = append(dbKeys, k)
		}
	}
	sort.Strings(dbKeys)
	for _, k := range dbKeys {
		at := strings.LastIndexByte(tv[k], '@')
		if at < 0 {
			continue // no "@<date>" build marker → not a dated DB label
		}
		built := strings.TrimSpace(tv[k][at+1:])
		if built == "" {
			continue // marker present but empty → absent build date, skip
		}
		if t, ok := parseFlexibleDate(built); ok {
			warn(k+" vulnerability DB", built, t)
		} else {
			out = append(out, unverifiable(k+" vulnerability DB", built))
		}
	}
	return out
}

// parseFlexibleDate parses the common date/timestamp layouts a DB build marker may use.
func parseFlexibleDate(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
