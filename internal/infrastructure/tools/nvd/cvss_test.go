package nvd

import (
	"encoding/json"
	"math"
	"testing"
)

// TestBestCVSSSharedParser proves the single NVD CVSS parse model (EPIC #860 D1.10): one metrics JSON
// block decodes into CVSSMetrics and BestCVSS picks the strongest metric with the documented precedence and
// the compute-from-vector fallback. This is the shared fixture the compact-DB builder, the online enricher,
// and the NVDProvider all now run through, so a change here moves all three in lock-step.
func TestBestCVSSSharedParser(t *testing.T) {
	cases := []struct {
		name       string
		metrics    string
		wantVector string
		wantScore  float64
		wantOK     bool
	}{
		{
			name:       "v31 preferred over v40 and v2",
			metrics:    `{"cvssMetricV40":[{"cvssData":{"vectorString":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N","baseScore":9.3}}],"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":9.8}}],"cvssMetricV2":[{"cvssData":{"vectorString":"AV:N/AC:L/Au:N/C:C/I:C/A:C","baseScore":10.0}}]}`,
			wantVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", wantScore: 9.8, wantOK: true,
		},
		{
			name:       "v40 only is scored",
			metrics:    `{"cvssMetricV40":[{"cvssData":{"vectorString":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N","baseScore":9.3}}]}`,
			wantVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", wantScore: 9.3, wantOK: true,
		},
		{
			name:       "missing base score is computed from the vector",
			metrics:    `{"cvssMetricV40":[{"cvssData":{"vectorString":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}]}`,
			wantVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", wantScore: 9.3, wantOK: true,
		},
		{
			name:       "v2 is the last resort",
			metrics:    `{"cvssMetricV2":[{"cvssData":{"vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P","baseScore":7.5}}]}`,
			wantVector: "AV:N/AC:L/Au:N/C:P/I:P/A:P", wantScore: 7.5, wantOK: true,
		},
		{
			name:    "no metric with a vector",
			metrics: `{}`,
			wantOK:  false,
		},
		{
			name:       "zero base score with a real vector is recomputed, never a bare zero",
			metrics:    `{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":0}}]}`,
			wantVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", wantScore: 9.8, wantOK: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var m CVSSMetrics
			if err := json.Unmarshal([]byte(c.metrics), &m); err != nil {
				t.Fatalf("decode metrics: %v", err)
			}
			vector, score, ok := BestCVSS(m)
			if ok != c.wantOK {
				t.Fatalf("ok=%v, want %v", ok, c.wantOK)
			}
			if ok && (vector != c.wantVector || math.Abs(score-c.wantScore) > 0.05) {
				t.Fatalf("got (%q, %.2f), want (%q, %.1f)", vector, score, c.wantVector, c.wantScore)
			}
		})
	}
}
