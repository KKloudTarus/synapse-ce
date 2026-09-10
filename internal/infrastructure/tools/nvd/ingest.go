package nvd

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// BuildDB parses NVD JSON feed files and writes a compact CVSS database as JSONL (one
// {"id","v","s"} object per CVE) to out. It accepts both the NVD API 2.0 shape
// ("vulnerabilities":[{"cve":{"id","metrics":{...}}}]) and the legacy 1.1 feed shape
// ("CVE_Items":[{"cve":{"CVE_data_meta":{"ID"}},"impact":{...}}]), gzip-compressed or plain. For
// each CVE it records the strongest available vector via BestCVSS (v3.1 > v3.0 > v4.0 > v2). A CVE
// with no CVSS vector is skipped (nothing to store). Returns the number of entries written.
func BuildDB(inPaths []string, out io.Writer) (int, error) {
	w := bufio.NewWriter(out)
	defer func() { _ = w.Flush() }()
	enc := json.NewEncoder(w)
	total := 0
	for _, p := range inPaths {
		n, err := ingestFile(p, enc)
		if err != nil {
			return total, fmt.Errorf("ingest %s: %w", filepath.Base(p), err)
		}
		total += n
	}
	return total, nil
}

func ingestFile(path string, enc *json.Encoder) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	var r io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, gerr := gzip.NewReader(f)
		if gerr != nil {
			return 0, fmt.Errorf("gunzip: %w", gerr)
		}
		defer func() { _ = gz.Close() }()
		r = gz
	}
	var doc nvdFeed
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return 0, fmt.Errorf("decode json: %w", err)
	}

	n := 0
	write := func(id, vector string, score float64) {
		id = cveID(id)
		if id == "" || vector == "" {
			return
		}
		_ = enc.Encode(dbEntry{ID: id, Vector: vector, Score: score})
		n++
	}
	// NVD API 2.0
	for _, item := range doc.Vulnerabilities {
		if v, s, ok := BestCVSS(item.CVE.Metrics); ok {
			write(item.CVE.ID, v, s)
		}
	}
	// Legacy 1.1 feed
	for _, item := range doc.CVEItems {
		if v := item.Impact.BaseMetricV3.CVSSV3.Vector; v != "" {
			write(item.CVE.Meta.ID, v, item.Impact.BaseMetricV3.CVSSV3.Base)
		} else if v := item.Impact.BaseMetricV2.CVSSV2.Vector; v != "" {
			write(item.CVE.Meta.ID, v, item.Impact.BaseMetricV2.CVSSV2.Base)
		}
	}
	return n, nil
}

// --- NVD JSON shapes (only the CVSS-relevant subset) ---

type nvdFeed struct {
	Vulnerabilities []struct {
		CVE struct {
			ID      string      `json:"id"`
			Metrics CVSSMetrics `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
	CVEItems []struct {
		CVE struct {
			Meta struct {
				ID string `json:"ID"`
			} `json:"CVE_data_meta"`
		} `json:"cve"`
		Impact struct {
			BaseMetricV3 struct {
				CVSSV3 struct {
					Vector string  `json:"vectorString"`
					Base   float64 `json:"baseScore"`
				} `json:"cvssV3"`
			} `json:"baseMetricV3"`
			BaseMetricV2 struct {
				CVSSV2 struct {
					Vector string  `json:"vectorString"`
					Base   float64 `json:"baseScore"`
				} `json:"cvssV2"`
			} `json:"baseMetricV2"`
		} `json:"impact"`
	} `json:"CVE_Items"`
}
