package export

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
)

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	infoURI      = "https://github.com/KKloudTarus/synapse-ce"
)

// SARIF 2.1.0 subset (the fields Synapse emits).

type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID                   string       `json:"id"`
	ShortDescription     SARIFText    `json:"shortDescription"`
	HelpURI              string       `json:"helpUri,omitempty"`
	DefaultConfiguration *SARIFConfig `json:"defaultConfiguration,omitempty"`
}

type SARIFConfig struct {
	Level string `json:"level"`
}

type SARIFText struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    SARIFText       `json:"message"`
	Locations  []SARIFLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type SARIFLocation struct {
	// A first-party finding (SAST/secret/misconfig) has a source file:line -> physicalLocation, so a
	// code-scanning UI annotates the exact line. An SCA finding is about a dependency, not a source
	// line -> logicalLocation module. Exactly one is set per location.
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"` // repo-relative path (GitHub matches it against the PR diff)
}

type SARIFRegion struct {
	StartLine int `json:"startLine"` // 1-based; SARIF requires >= 1
}

type SARIFLogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

// SARIFOptions carries optional per-finding resolvers that enrich SCA results. Both fields are nil-safe.
type SARIFOptions struct {
	// Manifest returns the repo-relative manifest/lockfile that declares a dependency finding's
	// component, so the result gets a physical location a code-scanning UI can annotate. "" when unknown.
	Manifest func(finding.Finding) string
	// Fix returns the version that remediates a dependency finding. "" when there is no fix or it is unknown.
	Fix func(finding.Finding) string
}

func buildSARIF(findings []finding.Finding, version string, opts SARIFOptions) *SARIFLog {
	rules := make([]SARIFRule, 0)
	seen := map[string]bool{}
	results := make([]SARIFResult, 0, len(findings))

	for _, f := range findings {
		p := parseDedup(f.DedupKey)
		ruleID := p.advisory
		if ruleID == "" {
			ruleID = f.ID.String()
		}

		var locations []SARIFLocation
		if rid, file, line, ok := firstPartyLoc(f.DedupKey); ok {
			// SAST/secret/misconfig: the engine's own rule id + the source file:line it flagged.
			ruleID = rid
			phys := &SARIFPhysicalLocation{ArtifactLocation: SARIFArtifactLocation{URI: file}}
			if line >= 1 {
				phys.Region = &SARIFRegion{StartLine: line}
			}
			locations = []SARIFLocation{{PhysicalLocation: phys}}
		} else if strings.HasPrefix(f.DedupKey, "sast:ai:") {
			// A gated taint (E39) SAST finding is judgment-anchored, not file:line-anchored – group
			// them under one stable rule id rather than leaking the per-finding anchor as the rule id.
			ruleID = "synapse-taint-sast"
		} else if p.component != "" {
			// SCA: point at the manifest/lockfile that declares the vulnerable dependency, so a
			// code-scanning UI annotates it (GitHub rejects a location that has only a logical/module
			// location). When the manifest is unknown, emit NO location – a result with no location is a
			// valid repo-level alert, but a logical-only location is not.
			manifest := ""
			if opts.Manifest != nil {
				manifest = opts.Manifest(f)
			}
			if manifest != "" {
				locations = []SARIFLocation{{
					PhysicalLocation: &SARIFPhysicalLocation{ArtifactLocation: SARIFArtifactLocation{URI: manifest}},
					LogicalLocations: []SARIFLogicalLocation{{Name: p.component + "@" + p.version, Kind: "module"}},
				}}
			}
		}

		level := sarifLevel(f.Severity)
		if !seen[ruleID] {
			seen[ruleID] = true
			rule := SARIFRule{
				ID:                   ruleID,
				ShortDescription:     SARIFText{Text: ruleTitle(f.Title)},
				DefaultConfiguration: &SARIFConfig{Level: level},
			}
			if strings.HasPrefix(ruleID, "CVE-") {
				rule.HelpURI = "https://nvd.nist.gov/vuln/detail/" + ruleID
			}
			rules = append(rules, rule)
		}

		res := SARIFResult{
			RuleID:  ruleID,
			Level:   level,
			Message: SARIFText{Text: f.Title},
			Properties: map[string]any{
				"severity":  string(f.Severity),
				"kev":       f.KEV,
				"riskScore": f.RiskScore,
				"status":    string(f.Status),
			},
			Locations: locations,
		}
		if f.CVSSVector != "" {
			res.Properties["cvssVector"] = f.CVSSVector
		}
		if f.ClassReachability != "" {
			// Coarse JVM class-reachability: "reachable" | "unreferenced". Advisory – lets a
			// consumer separate/deprioritize deps the app never references (priority already reflects it).
			res.Properties["componentReachability"] = f.ClassReachability
		}
		if p.component != "" && opts.Fix != nil {
			// Only dependency (SCA) findings have a fix version; the p.component gate makes that structural
			// rather than relying on the resolver returning "". Surface it as a property and inline in the
			// message so a code-scanning alert shows the fix without opening the finding.
			if fix := opts.Fix(f); fix != "" {
				res.Properties["fixedVersion"] = fix
				res.Message.Text = f.Title + " (fixed in " + fix + ")"
			}
		}
		results = append(results, res)
	}

	return &SARIFLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:           "synapse",
				Version:        version,
				InformationURI: infoURI,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

// firstPartyLoc parses a first-party finding dedup key of the form
// "<kind>:<ruleID>:<file>:<line>" (kind in sast|secret|misconfig, as written by the SCA
// finding builders) into the engine rule id and its physical file:line. The rule id and the
// trailing line never contain ':', so a file path that does is recovered as the middle join.
// Returns ok=false for any other key (SCA "vuln:...", "license:...") or a malformed one.
func firstPartyLoc(key string) (ruleID, file string, line int, ok bool) {
	var rest string
	matched := false
	for _, kind := range []string{"sast:", "secret:", "misconfig:", "quality:", "reliability:"} {
		if r, has := strings.CutPrefix(key, kind); has {
			rest, matched = r, true
			break
		}
	}
	if !matched {
		return "", "", 0, false
	}
	parts := strings.Split(rest, ":")
	if len(parts) < 3 {
		return "", "", 0, false
	}
	n, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil || n < 1 {
		return "", "", 0, false
	}
	file = strings.Join(parts[1:len(parts)-1], ":")
	if parts[0] == "" || file == "" {
		return "", "", 0, false
	}
	return parts[0], file, n, true
}

// ruleTitle strips a trailing " (file:line)" occurrence marker from a first-party finding title so a
// deduped rule's shortDescription reads generically ("MD5 is a weak hash") instead of embedding one
// occurrence's location. The per-result message keeps the full, located title. SCA titles (no such
// suffix) are returned unchanged.
func ruleTitle(title string) string {
	if !strings.HasSuffix(title, ")") {
		return title
	}
	open := strings.LastIndex(title, " (")
	if open < 0 {
		return title
	}
	inner := title[open+2 : len(title)-1] // between the "(" and the trailing ")"
	colon := strings.LastIndex(inner, ":")
	if colon < 0 {
		return title
	}
	if _, err := strconv.Atoi(inner[colon+1:]); err != nil {
		return title // not a "<path>:<line>" marker – leave the title intact
	}
	return title[:open]
}

// MarshalSARIF renders findings as an indented SARIF 2.1.0 log – the artifact a code-scanning
// uploader (e.g. GitHub `codeql-action/upload-sarif`) consumes. It is deterministic and templated
// purely from stored findings: no clock, no LLM (golden rule 5). version is the synapse driver
// version recorded on the run's tool driver. opts carries optional per-finding resolvers: Manifest gives
// SCA findings a physical location (a repo-relative manifest path), and Fix adds the remediating version.
// Both are nil-safe; pass the zero SARIFOptions to enrich nothing.
func MarshalSARIF(findings []finding.Finding, version string, opts SARIFOptions) ([]byte, error) {
	return json.MarshalIndent(buildSARIF(findings, version, opts), "", "  ")
}
