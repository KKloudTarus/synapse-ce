package nvd

import (
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// CVSSMetric is one NVD CVSS metric object of any version; only the vector and the base score are read.
type CVSSMetric struct {
	CVSSData struct {
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
	} `json:"cvssData"`
}

// CVSSMetrics is the CVSS block of an NVD API-2.0 CVE record. It is the single parse model shared by the
// compact-DB builder (BuildDB), the online CVSS enricher, and the NVDProvider, so the metric-group
// precedence and the compute-from-vector fallback live in exactly one place (EPIC #860 D1.10). The four
// version groups are decoded by their NVD JSON keys; the legacy 1.1 feed (impact.baseMetricV3) has a
// different shape and is parsed separately by BuildDB.
type CVSSMetrics struct {
	V40 []CVSSMetric `json:"cvssMetricV40"`
	V31 []CVSSMetric `json:"cvssMetricV31"`
	V30 []CVSSMetric `json:"cvssMetricV30"`
	V2  []CVSSMetric `json:"cvssMetricV2"`
}

// BestCVSS returns the strongest CVSS (vector, score) from an NVD metrics block, preferring v3.1 > v3.0 >
// v4.0 > v2: v3.x is kept ahead of v4.0 so an existing corpus does not shift its published band, and v4.0
// outranks the far weaker v2 so a v4-only CVE (a growing NVD share) still carries a band. When the feed
// omits or zeroes the base score, it is computed from the vector (any CVSS version) so a vectored record
// never yields a bare zero; a vector that carries neither a usable score nor a parseable form is skipped.
// Returns ok=false when no metric carries a vector.
func BestCVSS(m CVSSMetrics) (vector string, score float64, ok bool) {
	for _, group := range [][]CVSSMetric{m.V31, m.V30, m.V40, m.V2} {
		for _, metric := range group {
			v := strings.TrimSpace(metric.CVSSData.VectorString)
			if v == "" {
				continue
			}
			if s := metric.CVSSData.BaseScore; s > 0 && s <= 10 { // excludes 0, NaN, and Inf by comparison
				return v, s, true
			}
			if computed, cok := shared.CVSSBaseScore(v); cok {
				return v, computed, true
			}
			// A vector with no usable score and no parseable form is not a band: skip it, try the next metric.
		}
	}
	return "", 0, false
}
