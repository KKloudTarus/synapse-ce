package export

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
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
	ID               string     `json:"id"`
	Name             string     `json:"name,omitempty"`
	ShortDescription SARIFText  `json:"shortDescription"`
	FullDescription  *SARIFText `json:"fullDescription,omitempty"`
	// Help is what a code-scanning UI shows when a reader opens the alert, so the remediation goes here
	// rather than only in the message.
	Help                 *SARIFMultiformatText `json:"help,omitempty"`
	HelpURI              string                `json:"helpUri,omitempty"`
	DefaultConfiguration *SARIFConfig          `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any        `json:"properties,omitempty"`
}

// SARIFMultiformatText is SARIF's multiformatMessageString. GitHub renders the markdown variant.
type SARIFMultiformatText struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

// SARIFRuleMeta is the published catalog metadata for one rule. It fills in the fields that tell a
// reader what the rule checks, why it matters, and how to fix it, which a bare id and title do not.
type SARIFRuleMeta struct {
	Name        string   // catalog name, when it is more precise than the finding title
	Description string   // what the rule checks -> fullDescription
	Rationale   string   // why it matters -> help
	Remediation string   // how to fix it -> help
	HelpURI     string   // a page that resolves today -> helpUri
	Tags        []string // language / category tags -> properties.tags
	CWE         []string
	OWASP       []string
	Precision   string // "high" | "medium" | "low", when the catalog states it
}

type SARIFConfig struct {
	Level string `json:"level"`
}

type SARIFText struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID       string             `json:"ruleId"`
	Level        string             `json:"level"`
	Message      SARIFText          `json:"message"`
	Locations    []SARIFLocation    `json:"locations,omitempty"`
	CodeFlows    []SARIFCodeFlow    `json:"codeFlows,omitempty"`
	Suppressions []SARIFSuppression `json:"suppressions,omitempty"`
	Properties   map[string]any     `json:"properties,omitempty"`
}

type SARIFSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
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
	StartLine   int `json:"startLine"` // 1-based; SARIF requires >= 1
	StartColumn int `json:"startColumn,omitempty"`
}

type SARIFLogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

type SARIFCodeFlow struct {
	ThreadFlows []SARIFThreadFlow `json:"threadFlows"`
}

type SARIFThreadFlow struct {
	Locations []SARIFThreadFlowLocation `json:"locations"`
}

type SARIFThreadFlowLocation struct {
	Location SARIFLocation `json:"location"`
}

// SARIFOptions carries optional per-finding resolvers. Every field is nil-safe.
type SARIFOptions struct {
	// Manifest returns the repo-relative manifest/lockfile that declares a dependency finding's
	// component, so the result gets a physical location a code-scanning UI can annotate. "" when unknown.
	Manifest func(finding.Finding) string
	// Fix returns the version that remediates a dependency finding. "" when there is no fix or it is unknown.
	Fix func(finding.Finding) string
	// AIGateExemption returns policy metadata only when the finding's exemption has already passed the
	// server-owned authorization re-check. SARIF renders it as an external accepted suppression while
	// retaining the result. Advisory or review-required opinions must return false.
	AIGateExemption func(finding.Finding) (ports.AIGateExemption, bool)
	// RuleMeta returns the catalog entry for a rule id. Without it a result carries only an id, a title
	// and a level, which is what made the output hard to act on: no rule link, no rationale, no fix.
	// Returning false leaves the rule with just the fields derived from the finding.
	RuleMeta func(ruleID string) (SARIFRuleMeta, bool)
}

// advisoryHelp names the concrete remediation for a dependency advisory: the release to upgrade to. A
// catalog rule states its fix in the catalog; an advisory states it as a fixed version on the finding.
func advisoryHelp(f finding.Finding, p parsedKey, opts SARIFOptions) string {
	if p.component == "" || opts.Fix == nil {
		return ""
	}
	fix := strings.TrimSpace(opts.Fix(f))
	if fix == "" {
		return ""
	}
	return "Upgrade " + p.component + " to " + fix + " or later."
}

// applyRuleMeta fills a rule's descriptive fields from the catalog. A help URI already derived from the
// finding (an advisory's own NVD page) wins, because it is specific to that advisory.
func applyRuleMeta(rule *SARIFRule, meta SARIFRuleMeta) {
	if name := strings.TrimSpace(meta.Name); name != "" {
		rule.Name = name
	}
	if desc := strings.TrimSpace(meta.Description); desc != "" {
		rule.FullDescription = &SARIFText{Text: desc}
	}
	if rule.HelpURI == "" {
		rule.HelpURI = strings.TrimSpace(meta.HelpURI)
	}
	// help pairs why it matters with how to fix it, which is what a reader needs when they open the alert.
	var text, markdown strings.Builder
	if why := strings.TrimSpace(meta.Rationale); why != "" {
		text.WriteString(why)
		markdown.WriteString(why)
	}
	if fix := strings.TrimSpace(meta.Remediation); fix != "" {
		if text.Len() > 0 {
			text.WriteString("\n\n")
			markdown.WriteString("\n\n")
		}
		text.WriteString("Remediation: " + fix)
		markdown.WriteString("**Remediation:** " + fix)
	}
	if text.Len() > 0 {
		rule.Help = &SARIFMultiformatText{Text: text.String(), Markdown: markdown.String()}
	}
	props := map[string]any{}
	// external/cwe/cwe-89 and external/owasp/... are the tag shapes a code-scanning UI groups by.
	tags := make([]string, 0, len(meta.Tags)+len(meta.CWE)+len(meta.OWASP))
	for _, tag := range meta.Tags {
		if t := strings.TrimSpace(tag); t != "" {
			tags = append(tags, t)
		}
	}
	for _, id := range meta.CWE {
		if t := strings.TrimSpace(id); t != "" {
			tags = append(tags, "external/cwe/"+strings.ToLower(t))
		}
	}
	for _, id := range meta.OWASP {
		if t := strings.TrimSpace(id); t != "" {
			tags = append(tags, "external/owasp/"+t)
		}
	}
	if p := strings.TrimSpace(meta.Precision); p != "" {
		props["precision"] = p
	}
	if rule.Properties == nil {
		rule.Properties = map[string]any{}
	}
	// The class tags set before this call say whether the rule is a security rule; the catalog's tags add
	// the language and category, so they are appended rather than replacing them.
	if existing, ok := rule.Properties["tags"].([]string); ok {
		tags = append(existing, tags...)
	}
	if len(tags) > 0 {
		rule.Properties["tags"] = tags
	}
	for k, v := range props {
		rule.Properties[k] = v
	}
	if len(rule.Properties) == 0 {
		rule.Properties = nil
	}
}

// ruleClassProperties tells a code-scanning UI whether a rule is a security rule and how serious it is.
// GitHub places an alert in the security view when the rule carries security-severity and uses
// problem.severity for everything else, so a maintainability rule that carries no security-severity stops
// arriving as a vulnerability. That separation is what keeps a few hundred style findings from burying the
// handful of real advisories in one undifferentiated list.
func ruleClassProperties(kind finding.Kind, severity shared.Severity) map[string]any {
	props := map[string]any{"problem.severity": problemSeverity(severity)}
	switch kind {
	case finding.KindQuality:
		props["tags"] = []string{"maintainability"}
	case finding.KindReliability:
		props["tags"] = []string{"reliability"}
	default:
		props["tags"] = []string{"security"}
		props["security-severity"] = securitySeverity(severity)
	}
	return props
}

// problemSeverity is SARIF's non-security seriousness axis.
func problemSeverity(sev shared.Severity) string {
	switch sev {
	case shared.SeverityCritical, shared.SeverityHigh:
		return "error"
	case shared.SeverityLow, shared.SeverityInfo:
		return "recommendation"
	default: // medium / unknown
		return "warning"
	}
}

// securitySeverity is the CVSS-shaped number GitHub reads to bucket a security alert: >= 9.0 critical,
// >= 7.0 high, >= 4.0 medium, > 0 low. The exact value is not a CVSS score for the finding, it is the
// bucket the finding's own severity already states.
func securitySeverity(sev shared.Severity) string {
	switch sev {
	case shared.SeverityCritical:
		return "9.0"
	case shared.SeverityHigh:
		return "7.0"
	case shared.SeverityMedium:
		return "5.0"
	case shared.SeverityLow:
		return "2.0"
	default: // info / unknown: known to be a finding, not claimed to be a vulnerability
		return "0.0"
	}
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

		structuredRule := f.Kind.IsRuleBased() && f.RuleKey != ""
		if structuredRule {
			ruleID = f.RuleKey
		}

		var locations []SARIFLocation
		if rid, file, line, ok := firstPartyFindingLoc(f); ok {
			// First-party rule finding: the engine's own rule id + the source file:line it flagged.
			if !structuredRule {
				ruleID = rid
			}
			phys := &SARIFPhysicalLocation{ArtifactLocation: SARIFArtifactLocation{URI: file}}
			if line >= 1 {
				phys.Region = &SARIFRegion{StartLine: line}
			}
			locations = []SARIFLocation{{PhysicalLocation: phys}}
		} else if !structuredRule && strings.HasPrefix(f.DedupKey, "sast:ai:") {
			// A gated taint (E39) SAST finding is judgment-anchored, not file:line-anchored – group
			// them under one stable rule id rather than leaking the per-finding anchor as the rule id.
			ruleID = "synapse-taint-sast"
		} else if !structuredRule && p.component != "" {
			// SCA: point at the manifest/lockfile that declares the vulnerable dependency, so a
			// code-scanning UI annotates it (GitHub rejects a location that has only a logical/module
			// location). When the manifest is unknown, emit NO location – a result with no location is a
			// valid repo-level alert, but a logical-only location is not.
			manifest := ""
			if opts.Manifest != nil {
				manifest = opts.Manifest(f)
			}
			if manifest != "" {
				location := finding.SourceLocation{File: manifest, StartLine: 1, EndLine: 1}
				if location.Validate() == nil {
					locations = []SARIFLocation{{
						PhysicalLocation: &SARIFPhysicalLocation{ArtifactLocation: SARIFArtifactLocation{URI: manifest}},
						LogicalLocations: []SARIFLogicalLocation{{Name: p.component + "@" + p.version, Kind: "module"}},
					}}
				}
			}
		}

		level := sarifLevel(f.Severity)
		if !seen[ruleID] {
			seen[ruleID] = true
			rule := SARIFRule{
				ID:                   ruleID,
				ShortDescription:     SARIFText{Text: ruleTitle(f.Title)},
				DefaultConfiguration: &SARIFConfig{Level: level},
				Properties:           ruleClassProperties(f.Kind, f.Severity),
			}
			if strings.HasPrefix(ruleID, "CVE-") {
				rule.HelpURI = "https://nvd.nist.gov/vuln/detail/" + ruleID
			}
			if opts.RuleMeta != nil {
				if meta, ok := opts.RuleMeta(ruleID); ok {
					applyRuleMeta(&rule, meta)
				}
			}
			// An advisory is not in the rule catalog, so it would otherwise carry only an id, a title and
			// an NVD link. The finding's own description is the advisory summary and already names the
			// release that fixes it, so it fills the same two fields a catalog rule gets.
			if rule.FullDescription == nil {
				if desc := strings.TrimSpace(f.Description); desc != "" {
					rule.FullDescription = &SARIFText{Text: desc}
				}
			}
			if rule.Help == nil {
				if help := advisoryHelp(f, p, opts); help != "" {
					rule.Help = &SARIFMultiformatText{Text: help}
				}
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
		if codeFlows := sarifDataFlows(f.DataFlow); len(codeFlows) > 0 {
			res.CodeFlows = codeFlows
			res.Properties["synapse.dataFlowLanguage"] = f.DataFlow.Language
			res.Properties["synapse.coverageComplete"] = f.DataFlow.CoverageComplete
			res.Properties["synapse.graphTruncated"] = f.DataFlow.GraphTruncated
		}
		if f.CVSSVector != "" {
			res.Properties["cvssVector"] = f.CVSSVector
		}
		if !structuredRule && p.component != "" && f.ClassReachability != "" {
			// Coarse JVM class-reachability: "reachable" | "unreferenced". Advisory – lets a
			// consumer separate/deprioritize deps the app never references (priority already reflects it).
			res.Properties["componentReachability"] = f.ClassReachability
		}
		if !structuredRule && p.component != "" && opts.Fix != nil {
			// Only dependency (SCA) findings have a fix version; the p.component gate makes that structural
			// rather than relying on the resolver returning "". Surface it as a property and inline in the
			// message so a code-scanning alert shows the fix without opening the finding.
			if fix := opts.Fix(f); fix != "" {
				res.Properties["fixedVersion"] = fix
				res.Message.Text = f.Title + " (fixed in " + fix + ")"
			}
		}
		// Minimal-upgrade remediation (D3.8): the direct dependencies to bump to remove a transitive vuln.
		// It rides on the finding itself, so no resolver is needed; a code-scanning consumer gets the
		// upgrade path directly.
		if len(f.DirectBumps) > 0 {
			res.Properties["upgradePath"] = strings.Join(f.DirectBumps, ", ")
		}
		// Public-exploit exploitation-risk signal (D1.3), surfaced for a code-scanning consumer to prioritize.
		if f.PublicExploit {
			res.Properties["publicExploit"] = "true"
		}
		// EPSS percentile (D1.3): the exploit-prediction rank among all CVEs, a triage-ordering aid.
		if f.EPSSPercentile > 0 {
			res.Properties["epssPercentile"] = strconv.FormatFloat(f.EPSSPercentile, 'f', 4, 64)
		}
		if opts.AIGateExemption != nil {
			findingKey := strings.TrimSpace(f.DedupKey)
			if exemption, ok := opts.AIGateExemption(f); ok && findingKey != "" &&
				strings.TrimSpace(exemption.DedupKey) == findingKey &&
				strings.TrimSpace(exemption.PolicyVersion) != "" && strings.TrimSpace(exemption.PolicyReason) != "" {
				version := strings.TrimSpace(exemption.PolicyVersion)
				reason := strings.TrimSpace(exemption.PolicyReason)
				res.Suppressions = []SARIFSuppression{{
					Kind:          "external",
					Status:        "accepted",
					Justification: "Synapse AI gate exemption: policy=" + version + "; reason=" + reason,
				}}
				res.Properties["synapse.aiGateExempt"] = true
				res.Properties["synapse.aiPolicyVersion"] = version
				res.Properties["synapse.aiPolicyReason"] = reason
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

// firstPartyFindingLoc prefers producer-owned structured identity because a
// colon-bearing rule key cannot be recovered unambiguously from DedupKey. Stored
// findings created before SourceLocation persistence use a RuleKey-anchored
// legacy fallback; findings without RuleKey retain the original parser.
func firstPartyFindingLoc(f finding.Finding) (ruleID, file string, line int, ok bool) {
	if f.Kind.IsRuleBased() && f.RuleKey != "" {
		if f.SourceLocation != nil {
			if f.SourceLocation.Validate() == nil {
				return f.RuleKey, f.SourceLocation.File, f.SourceLocation.StartLine, true
			}
			return "", "", 0, false
		}
		if f.DataFlow != nil && f.DataFlow.Validate() == nil {
			return f.RuleKey, f.DataFlow.Sink.File, f.DataFlow.Sink.StartLine, true
		}
		if file, line, ok := legacyLocationForRule(f.DedupKey, f.RuleKey); ok {
			return f.RuleKey, file, line, true
		}
		return "", "", 0, false
	}
	return firstPartyLoc(f.DedupKey)
}

func sarifDataFlows(trace *finding.DataFlowTrace) []SARIFCodeFlow {
	if trace == nil || trace.Validate() != nil {
		return nil
	}
	locations := make([]SARIFThreadFlowLocation, 0, len(trace.Steps))
	for _, step := range trace.Steps {
		region := &SARIFRegion{StartLine: step.StartLine}
		if step.StartColumn != nil {
			region.StartColumn = *step.StartColumn + 1
		}
		locations = append(locations, SARIFThreadFlowLocation{Location: SARIFLocation{
			PhysicalLocation: &SARIFPhysicalLocation{
				ArtifactLocation: SARIFArtifactLocation{URI: step.File},
				Region:           region,
			},
		}})
	}
	return []SARIFCodeFlow{{ThreadFlows: []SARIFThreadFlow{{Locations: locations}}}}
}

func legacyLocationForRule(key, ruleID string) (file string, line int, ok bool) {
	var rest string
	for _, kind := range []string{"cq:sast:", "cq:quality:", "cq:reliability:", "sast:", "secret:", "misconfig:"} {
		if value, has := strings.CutPrefix(key, kind); has {
			rest = value
			break
		}
	}
	location, has := strings.CutPrefix(rest, ruleID+":")
	if !has {
		return "", 0, false
	}
	return validatedLegacyLocation(location)
}

// firstPartyLoc parses a legacy first-party finding dedup key of the form
// "<kind>:<ruleID>:<file>:<line>" or "cq:<kind>:<ruleID>:<file>:<line>" into the engine rule id
// and its physical file:line. Legacy rule ids and trailing lines never contain ':', so a file path that does
// is recovered as the middle join. Returns ok=false for SCA "vuln:...", "license:...", or malformed keys.
func firstPartyLoc(key string) (ruleID, file string, line int, ok bool) {
	var rest string
	matched := false
	for _, kind := range []string{"cq:sast:", "cq:quality:", "cq:reliability:", "sast:", "secret:", "misconfig:"} {
		if r, has := strings.CutPrefix(key, kind); has {
			rest, matched = r, true
			break
		}
	}
	if !matched {
		return "", "", 0, false
	}
	separator := strings.IndexByte(rest, ':')
	if separator <= 0 || separator == len(rest)-1 {
		return "", "", 0, false
	}
	file, line, ok = validatedLegacyLocation(rest[separator+1:])
	if !ok {
		return "", "", 0, false
	}
	return rest[:separator], file, line, true
}

func validatedLegacyLocation(value string) (file string, line int, ok bool) {
	location, ok := finding.SourceLocationFromLegacy(value)
	if !ok {
		return "", 0, false
	}
	return location.File, location.StartLine, true
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
// SCA findings a physical location (a repo-relative manifest path), Fix adds the remediating version,
// and AIGateExemption explains policy-authorized external suppression without removing the result.
// All are nil-safe; pass the zero SARIFOptions to enrich nothing.
func MarshalSARIF(findings []finding.Finding, version string, opts SARIFOptions) ([]byte, error) {
	return json.MarshalIndent(buildSARIF(findings, version, opts), "", "  ")
}
