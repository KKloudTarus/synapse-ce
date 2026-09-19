package ast

// semgrep_sarif.go normalizes Semgrep SARIF output into the sastbench.Finding shape so the owned SAST engine
// and Semgrep CE can be scored on the same answer key. Semgrep is a COMPARISON baseline, not ground truth:
// its findings are reduced to (file, line, CWE) exactly as the owned engine's are, and the head-to-head is
// reported, never used to gate the owned engine. The CWE is read from the matched rule's tags (Semgrep encodes
// it as a "CWE-<n>: <title>" tag), so a Semgrep finding with no CWE tag is dropped rather than misclassified.

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/sastbench"
)

var cweTagPattern = regexp.MustCompile(`^(CWE-\d+)`)

// sarifDocument is the minimal subset of SARIF 2.1.0 the Semgrep normalizer reads.
type sarifDocument struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []struct {
					ID         string `json:"id"`
					Properties struct {
						Tags []string `json:"tags"`
					} `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

// parseSemgrepSARIF reads a Semgrep SARIF report and returns one sastbench.Finding per result that carries a
// CWE tag and a location, keyed by base filename (to match a base-filename answer key) and line. A result
// without a CWE-tagged rule or without a location is skipped; the returned count of such skips lets the caller
// report how much of Semgrep's output was not CWE-classifiable.
func parseSemgrepSARIF(r io.Reader) (findings []sastbench.Finding, skipped int, err error) {
	var doc sarifDocument
	dec := json.NewDecoder(r)
	if derr := dec.Decode(&doc); derr != nil {
		return nil, 0, fmt.Errorf("decode semgrep sarif: %w", derr)
	}
	for _, run := range doc.Runs {
		ruleCWE := make(map[string]string, len(run.Tool.Driver.Rules))
		for _, rule := range run.Tool.Driver.Rules {
			if cwe := cweFromTags(rule.Properties.Tags); cwe != "" {
				ruleCWE[rule.ID] = cwe
			}
		}
		for _, res := range run.Results {
			cwe := ruleCWE[res.RuleID]
			if cwe == "" || len(res.Locations) == 0 {
				skipped++
				continue
			}
			loc := res.Locations[0].PhysicalLocation
			findings = append(findings, sastbench.Finding{
				File: filepath.Base(loc.ArtifactLocation.URI),
				Line: loc.Region.StartLine,
				CWE:  cwe,
			})
		}
	}
	return findings, skipped, nil
}

// cweFromTags extracts the first "CWE-<n>" tag Semgrep attaches to a rule (e.g.
// "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')").
func cweFromTags(tags []string) string {
	for _, tag := range tags {
		if m := cweTagPattern.FindStringSubmatch(strings.TrimSpace(tag)); m != nil {
			return m[1]
		}
	}
	return ""
}
