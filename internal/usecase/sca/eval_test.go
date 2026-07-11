package sca

// Eval harness (NOT a CI test): drives Synapse's REAL detection + license pipeline over a CycloneDX SBOM
// and writes the vuln + license result as JSON, so it can be diffed against a Trivy report. Gated by
// SYNAPSE_EVAL_SBOM (path to the SBOM) so `go test./...` skips it. Uses OSV (live) + Grype (offline DB
// if available) as vuln sources – the same sources the scan pipeline runs – then Correlate + classifyVulns
// (cross-source dedup + risk), and the license Scanner (normalize declared licenses → SPDX + risk).
//
// SYNAPSE_EVAL_SBOM=/abs/SBOM.cdx.json SYNAPSE_EVAL_OUT=/abs/out.json \
// go test./internal/usecase/sca/ -run TestEvalSBOM -v -count=1 -timeout 300s

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/grype"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/license"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/osv"
)

func TestEvalSBOM(t *testing.T) {
	sbomPath := os.Getenv("SYNAPSE_EVAL_SBOM")
	if sbomPath == "" {
		t.Skip("SYNAPSE_EVAL_SBOM not set – eval harness, not a CI test")
	}
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseCycloneDX(data)
	if err != nil {
		t.Fatal(err)
	}
	doc := &sbom.SBOM{TargetRef: "eval", Source: "imported-cyclonedx", Components: parsed.Components, Dependencies: parsed.Dependencies, Raw: data}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	// --- vuln sources: OSV (live) + Grype (offline DB if present) – same as the scan pipeline ---
	var raws []vulnerability.RawFinding
	if r, e := osv.New("", nil).Scan(ctx, doc); e != nil {
		t.Logf("OSV: %v", e)
	} else {
		t.Logf("OSV raws: %d", len(r))
		raws = append(raws, r...)
	}
	if r, e := grype.New("grype", os.Getenv("GRYPE_DB_DIR")).Scan(ctx, doc); e != nil {
		t.Logf("Grype: %v (skipping – DB/binary unavailable)", e)
	} else {
		t.Logf("Grype raws: %d", len(r))
		raws = append(raws, r...)
	}

	vulns := vulnerability.Correlate(raws)
	classifyVulns(doc, vulns)

	// --- licenses: normalize declared licenses in place (SPDX + category) ---
	lics, err := license.New().Scan(ctx, doc)
	if err != nil {
		t.Fatalf("license scan: %v", err)
	}

	// --- collect vuln keys (unique pkg|version|cve) + severities ---
	type vrow struct{ Component, Version, CVE, Severity string }
	sevCount := map[string]int{}
	vseen := map[string]bool{}
	var vrows []vrow
	for _, v := range vulns {
		key := v.Component + "|" + v.Version + "|" + v.ID
		if vseen[key] {
			continue // pipeline already dedups; guard anyway to prove no dup rows
		}
		vseen[key] = true
		vrows = append(vrows, vrow{v.Component, v.Version, v.ID, string(v.Severity)})
		sevCount[string(v.Severity)]++
	}
	sort.Slice(vrows, func(i, j int) bool {
		if vrows[i].Component != vrows[j].Component {
			return vrows[i].Component < vrows[j].Component
		}
		return vrows[i].CVE < vrows[j].CVE
	})

	// --- collect per-component normalized licenses (Trivy-comparable) ---
	type lrow struct{ Component, Version, License, Category string }
	var lrows []lrow
	licSeen := map[string]bool{}
	for _, c := range doc.Components {
		if len(c.Licenses) == 0 {
			k := c.Name + "|UNKNOWN"
			if !licSeen[k] {
				licSeen[k] = true
				lrows = append(lrows, lrow{c.Name, c.Version, "UNKNOWN", "unknown"})
			}
			continue
		}
		for _, l := range c.Licenses {
			id := l.SPDXID
			if id == "" {
				id = l.Name
			}
			k := c.Name + "|" + id
			if licSeen[k] {
				continue
			}
			licSeen[k] = true
			lrows = append(lrows, lrow{c.Name, c.Version, id, string(l.Category)})
		}
	}
	sort.Slice(lrows, func(i, j int) bool {
		if lrows[i].Component != lrows[j].Component {
			return lrows[i].Component < lrows[j].Component
		}
		return lrows[i].License < lrows[j].License
	})

	out := map[string]any{
		"components":          len(doc.Components),
		"vuln_unique_keys":    len(vrows),
		"vuln_severity":       sevCount,
		"vulns":               vrows,
		"license_policy_rows": len(lics),
		"license_rows":        len(lrows),
		"licenses":            lrows,
	}
	t.Logf("components=%d vulns=%d (%v) license_rows=%d", len(doc.Components), len(vrows), sevCount, len(lrows))

	if outPath := os.Getenv("SYNAPSE_EVAL_OUT"); outPath != "" {
		b, _ := json.MarshalIndent(out, "", "  ")
		if err := os.WriteFile(outPath, b, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", outPath)
	}
}
