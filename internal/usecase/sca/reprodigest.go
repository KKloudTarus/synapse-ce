package sca

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

// ReproDigest is a stable content fingerprint of a scan's REPRODUCIBLE output (the
// swappability invariant as a verifiable feature): the SBOM component SET + the promoted findings (with each
// vuln finding's advisory content – fix version + CVSS vector – folded in), hashed over a canonical (sorted,
// order-independent) form. It makes reproducibility CHECKABLE – the SAME inputs (same target, pinned SBOM
// producer, pinned advisory/vuln-DB snapshot) yield the SAME digest; two scans match ⟺ their digests match,
// and a DIFFERENT advisory DB (new fix version, changed CVSS, new/dropped vuln) changes the digest.
//
// Scope (deliberate): it fingerprints the component SET + finding identity/severity/fix/CVSS – NOT the SBOM
// dependency-graph EDGES and NOT raw component license strings (denied-license *outcomes* re-enter as their
// own license findings, so policy results are captured). It EXCLUDES per-run/timestamped data so the digest
// reflects only what is reproducible: no ToolVersions / VulnDBSnapshot (both embed the scan time / feed-sync
// date), no finding id (engagement-derived), no Audit timestamps. Field separator is NUL (\x00), which the
// inputs (PURLs, "vuln:id:component:version" dedup keys, enum kinds/severities) never contain.
//
// It is a provenance/regression fingerprint, NOT a security hash – it carries no secret and proves nothing on
// its own; a human/CI compares two digests to assert a scan reproduced.
func ReproDigest(res *ScanResult) string {
	if res == nil {
		return ""
	}
	byVuln := make(map[string]vulnerability.Vulnerability, len(res.Vulnerabilities))
	for _, v := range res.Vulnerabilities {
		byVuln[vulnDedupKey(v)] = v // shared key: a vuln finding's DedupKey == its vuln's key
	}
	lines := make([]string, 0, len(res.Findings)+1)
	if res.SBOM != nil {
		for _, c := range res.SBOM.Components {
			lines = append(lines, "comp\x00"+sbom.ComponentID(c.Name, c.Version, c.PURL))
		}
	}
	for _, f := range res.Findings {
		// CONTENT only: kind + dedup key + severity, plus the correlated advisory's fix version + CVSS vector
		// (so a remediation/score change in a new DB snapshot is reflected) – never the id or any timestamp.
		line := "find\x00" + string(f.Kind) + "\x00" + f.DedupKey + "\x00" + string(f.Severity)
		if v, ok := byVuln[f.DedupKey]; ok {
			line += "\x00" + v.FixedVersion + "\x00" + v.CVSSVector
		}
		lines = append(lines, line)
	}
	sort.Strings(lines) // canonical: independent of component/finding emission order
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}
