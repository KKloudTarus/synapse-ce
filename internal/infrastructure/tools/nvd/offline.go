package nvd

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// OfflineEnricher backfills CVSS from a LOCAL NVD-derived database (built by BuildDB from the NVD
// JSON feed). Unlike the online Enricher it needs no network and is not rate-limited, so it can fill
// a real CVSS score for EVERY matching CVE — the airgapped path, and the way to give a large
// dependency tree (whose OSV/GHSA advisories often carry only a severity label, no CVSS vector) the
// CVSS numbers a commercial SCA report shows. It fills a MISSING CVSS vector/score and an UNKNOWN
// severity; it never overrides a severity a detection source already set.
type OfflineEnricher struct {
	db map[string]cvss // CVE id (upper) -> CVSS
}

var _ ports.SeverityEnricher = (*OfflineEnricher)(nil)

// dbEntry is one line of the CVSS DB (compact JSONL): id + CVSS vector + base score.
type dbEntry struct {
	ID     string  `json:"id"`
	Vector string  `json:"v"`
	Score  float64 `json:"s"`
}

// LoadOffline reads a CVSS DB (JSONL, optionally gzip-compressed) produced by BuildDB. Malformed
// lines are skipped so a partially-corrupt DB still loads what it can (best-effort, never panics).
func LoadOffline(path string) (*OfflineEnricher, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open cvss db: %w", err)
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, gerr := gzip.NewReader(f)
		if gerr != nil {
			return nil, fmt.Errorf("gunzip cvss db: %w", gerr)
		}
		defer gz.Close()
		r = gz
	}

	db := make(map[string]cvss, 1<<16)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20) // long lines OK
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e dbEntry
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		id := cveID(e.ID)
		if id == "" || strings.TrimSpace(e.Vector) == "" {
			continue
		}
		db[id] = cvss{score: e.Score, vector: e.Vector}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read cvss db: %w", err)
	}
	return &OfflineEnricher{db: db}, nil
}

// Size reports how many CVEs are loaded (diagnostic).
func (o *OfflineEnricher) Size() int { return len(o.db) }

// Enrich fills a missing CVSS vector/score (and an unknown severity) from the local DB. It is a
// pure in-memory lookup, so it fills EVERY matching CVE regardless of scan size and ignores ctx
// timeouts. A detection source's non-unknown severity is preserved.
func (o *OfflineEnricher) Enrich(_ context.Context, vulns []vulnerability.Vulnerability) ports.SeverityResult {
	res := ports.SeverityResult{Vulns: vulns, Source: "nvd-offline"}
	if len(o.db) == 0 {
		return res
	}
	for i := range vulns {
		needVector := strings.TrimSpace(vulns[i].CVSSVector) == ""
		needSeverity := vulns[i].Severity == shared.SeverityUnknown
		if !needVector && !needSeverity {
			continue
		}
		c, ok := o.db[cveID(vulns[i].ID)]
		if !ok {
			continue
		}
		if needVector {
			vulns[i].CVSSVector = c.vector
			if vulns[i].CVSSScore == 0 {
				vulns[i].CVSSScore = c.score
			}
		}
		if needSeverity {
			vulns[i].Severity = shared.SeverityFromScore(c.score)
		}
		res.Matches++
	}
	return res
}
