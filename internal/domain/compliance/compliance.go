// Package compliance maps a finding's CWE to the regulatory/standard controls it bears on (compliance
// mapping). It is the CURATED TABLE – deterministic, human-curated reference data sourced from each
// framework's PUBLISHED CWE/category guidance, NEVER inferred at runtime (an AI-assisted mapping is a later,
// separately-gated layer, per the phase plan's "curated table first"). So a compliance tag is auditable: it
// is a lookup, not a model output, and the report path stays LLM-free.
//
// Coverage: the CWEs Synapse actually emits today (the pattern-SAST rules – CWE-327/295/798) plus the common
// injection/SSRF/deserialization classes (the taint packs + advisory findings). An UNMAPPED CWE returns no
// controls – fail-open-to-nothing (never a fabricated mapping). Frameworks:
// OWASP Top 10 2021: the authoritative per-CWE category (each CWE is listed under exactly one category).
// PCI DSS 4.0 req 6.2.4: secure-coding for the attack classes 6.2.4 explicitly enumerates (injection,
// XSS, crypto, access control, auth) – NOT claimed for classes it doesn't name.
// ISO/IEC 27001:2022 A.8.28: "Secure coding" – applies to every code-weakness CWE here.
package compliance

import (
	"sort"
	"strconv"
	"strings"
)

// Control is one mapped compliance control: which framework, the control/category id, and its title.
type Control struct {
	Framework string // "OWASP-2021" | "PCI-DSS-4.0" | "ISO-27001-2022"
	ID        string // e.g. "A03:2021" | "6.2.4" | "A.8.28"
	Title     string
}

// OWASP Top 10 2021 categories (each CWE below is listed under exactly one, per the OWASP 2021 CWE lists).
var (
	owaspA01 = Control{"OWASP-2021", "A01:2021", "Broken Access Control"}
	owaspA02 = Control{"OWASP-2021", "A02:2021", "Cryptographic Failures"}
	owaspA03 = Control{"OWASP-2021", "A03:2021", "Injection"}
	owaspA07 = Control{"OWASP-2021", "A07:2021", "Identification and Authentication Failures"}
	owaspA08 = Control{"OWASP-2021", "A08:2021", "Software and Data Integrity Failures"}
	owaspA10 = Control{"OWASP-2021", "A10:2021", "Server-Side Request Forgery (SSRF)"}

	pci624  = Control{"PCI-DSS-4.0", "6.2.4", "Secure-coding techniques to prevent common software attacks"}
	isoA828 = Control{"ISO-27001-2022", "A.8.28", "Secure coding"}
)

// cweControls is the curated CWE → controls table. ISO A.8.28 (secure coding) applies to every entry; PCI
// 6.2.4 is added only to the attack classes that requirement explicitly enumerates.
//
// Sources (each mapping traces to PUBLISHED guidance – this is reference data, not inference):
// OWASP Top 10 2021 per-category CWE lists (https://owasp.org/Top10/): each category page enumerates its
// "Mapped CWEs" – e.g. A03:2021-Injection lists CWE-79/89/78/94; A10:2021 lists CWE-918; A08:2021 CWE-502.
// PCI DSS v4.0 requirement 6.2.4 (PCI SSC, 2022): secure-coding to prevent the attacks it explicitly names
// – injection, XSS, broken access control, crypto failures, auth flaws. NOT claimed for classes it omits.
// ISO/IEC 27001:2022 Annex A control 8.28 "Secure coding" – applies to every code-weakness CWE here.
var cweControls = map[string][]Control{
	"CWE-89":  {owaspA03, pci624, isoA828}, // SQL injection
	"CWE-79":  {owaspA03, pci624, isoA828}, // cross-site scripting
	"CWE-78":  {owaspA03, pci624, isoA828}, // OS command injection
	"CWE-94":  {owaspA03, pci624, isoA828}, // code injection
	"CWE-22":  {owaspA01, pci624, isoA828}, // path traversal (broken access control)
	"CWE-918": {owaspA10, isoA828},         // SSRF (not enumerated by PCI 6.2.4 – not claimed)
	"CWE-327": {owaspA02, pci624, isoA828}, // use of broken/risky cryptographic algorithm
	"CWE-295": {owaspA02, isoA828},         // improper certificate validation (crypto failure)
	"CWE-798": {owaspA07, pci624, isoA828}, // use of hard-coded credentials
	"CWE-502": {owaspA08, isoA828},         // deserialization of untrusted data
}

// ControlsFor returns the curated compliance controls a CWE maps to, in deterministic order (framework, then
// id). The CWE is normalized (trimmed, upper-cased, "CWE-" prefix tolerated with or without). An unmapped or
// empty CWE returns nil – a finding simply carries no compliance tags rather than a guessed one.
func ControlsFor(cwe string) []Control {
	key := normalizeCWE(cwe)
	if key == "" {
		return nil
	}
	src := cweControls[key]
	if len(src) == 0 {
		return nil
	}
	out := make([]Control, len(src))
	copy(out, src)
	sortControls(out)
	return out
}

func cisAWS(id, title string) Control { return Control{"CIS-AWS-3.0", id, title} }
func cisK8s(id, title string) Control { return Control{"CIS-Kubernetes-1.10", id, title} }

// ruleControls is the curated misconfiguration-RULE → controls table. A CIS Benchmark control is per-resource
// (e.g. "EBS Volume Encryption"), too specific to key by CWE, so it is keyed by the rule's stable catalog key
// instead. Like cweControls it is reference data, NEVER inferred: every entry is a verbatim lookup of a
// PUBLISHED CIS Benchmark control (ids + titles verbatim from CIS AWS Foundations Benchmark v3.0.0 and CIS
// Kubernetes Benchmark v1.10.0, as transcribed in Prowler's Apache-2.0 compliance specs), and ONLY rules
// whose detection matches EXACTLY what the control requires are mapped –
// an approximate match (e.g. an "any 0.0.0.0/0 ingress" rule against CIS 5.2, which is admin-ports-only) is
// deliberately left unmapped rather than claimed, because a wrong control id is false compliance assurance.
// Interpretive frameworks (NIST-800-53 / SOC2 / HIPAA) are intentionally excluded: claiming a specific
// sub-control there for a bespoke rule cannot be done without an authoritative mapping we do not have.
var ruleControls = map[string][]Control{
	// CIS AWS Foundations Benchmark v3.0.0. Each mapped rule detects a per-RESOURCE property that is exactly
	// the control's condition. Deliberately NOT mapped (approximate, would be false assurance): a per-volume
	// EBS-encrypted check vs the account-level default-encryption control 2.2.1; a per-trail "not multi-region"
	// flag vs the account-level "at least one multi-region trail" control 3.1 (a supplementary single-region
	// trail is not itself noncompliant); a "KMS key without rotation" flag vs 3.6, which is symmetric CMKs only
	// (asymmetric/HMAC keys cannot rotate).
	"cloudformation-rds-unencrypted":              {cisAWS("2.3.1", "Ensure that encryption is enabled for RDS Instances")},
	"cloudformation-rds-public":                   {cisAWS("2.3.3", "Ensure that public access is not given to RDS Instance")},
	"cloudformation-efs-unencrypted":              {cisAWS("2.4.1", "Ensure that encryption is enabled for EFS file systems")},
	"cloudformation-cloudtrail-no-log-validation": {cisAWS("3.2", "Ensure CloudTrail log file validation is enabled")},
	"cloudformation-ec2-imdsv2":                   {cisAWS("5.6", "Ensure that EC2 Metadata Service only allows IMDSv2")},
	// CIS Kubernetes Benchmark v1.10.0 (pod-security controls; each is an explicit per-manifest predicate).
	// Deliberately NOT mapped: "may run as root" (no manifest runAsNonRoot) is broader than 5.2.7's root
	// containers (a non-root image USER with no manifest setting is not a root container); a repo-scoped
	// "namespace has no NetworkPolicy" is approximate against 5.3.2's per-cluster-namespace requirement.
	"kubernetes-privileged":            {cisK8s("5.2.2", "Minimize the admission of privileged containers")},
	"kubernetes-host-pid":              {cisK8s("5.2.3", "Minimize the admission of containers wishing to share the host process ID namespace")},
	"kubernetes-host-ipc":              {cisK8s("5.2.4", "Minimize the admission of containers wishing to share the host IPC namespace")},
	"kubernetes-host-network":          {cisK8s("5.2.5", "Minimize the admission of containers wishing to share the host network namespace")},
	"kubernetes-allow-priv-escalation": {cisK8s("5.2.6", "Minimize the admission of containers with allowPrivilegeEscalation")},
	"kubernetes-run-as-root":           {cisK8s("5.2.7", "Minimize the admission of root containers")},
	"kubernetes-host-path":             {cisK8s("5.2.12", "Minimize the admission of HostPath volumes")},
	"kubernetes-host-port":             {cisK8s("5.2.13", "Minimize the admission of containers which use HostPorts")},
	"kubernetes-default-namespace":     {cisK8s("5.7.4", "The default namespace should not be used")},
}

// ControlsForRule returns the curated CIS Benchmark controls a misconfiguration rule KEY maps to, in
// deterministic order. An unmapped or empty key returns nil – the rule simply carries no CIS tag rather than
// a guessed one (fail-open-to-nothing, same contract as ControlsFor).
func ControlsForRule(ruleKey string) []Control {
	src := ruleControls[strings.TrimSpace(ruleKey)]
	if len(src) == 0 {
		return nil
	}
	out := make([]Control, len(src))
	copy(out, src)
	sortControls(out)
	return out
}

// ControlsForFinding returns the union of a finding's CWE-mapped controls (OWASP/PCI/ISO) and its
// rule-key-mapped controls (CIS), de-duplicated by (framework, id) and deterministically ordered. This is the
// single call a client-facing reader uses so a misconfiguration finding carries both its weakness-class and
// its benchmark controls.
func ControlsForFinding(cwe, ruleKey string) []Control {
	seen := map[string]bool{}
	var out []Control
	for _, c := range ControlsFor(cwe) {
		if k := c.Framework + "\x00" + c.ID; !seen[k] {
			seen[k] = true
			out = append(out, c)
		}
	}
	for _, c := range ControlsForRule(ruleKey) {
		if k := c.Framework + "\x00" + c.ID; !seen[k] {
			seen[k] = true
			out = append(out, c)
		}
	}
	sortControls(out)
	return out
}

// sortControls orders controls by framework then id, in place.
func sortControls(cs []Control) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Framework != cs[j].Framework {
			return cs[i].Framework < cs[j].Framework
		}
		return cs[i].ID < cs[j].ID
	})
}

// normalizeCWE canonicalizes a CWE id to "CWE-<n>" (upper-case, "CWE-" prefix added if the caller passed a
// bare number, zero-padding dropped so "CWE-079" == "CWE-79"); a non-CWE/garbage token normalizes to ""
// (unmapped – fail-closed, never a guessed mapping). Tolerant of "cwe-89", "CWE-89", "89", "079".
//
// The numeric tail is parsed with ParseUint (base 10): a sign prefix, internal spaces, empty input, or an
// out-of-range value all error → "". This deliberately accepts only an unsigned decimal CWE number.
func normalizeCWE(cwe string) string {
	s := strings.ToUpper(strings.TrimSpace(cwe))
	s = strings.TrimPrefix(s, "CWE-")
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return ""
	}
	return "CWE-" + strconv.FormatUint(n, 10)
}

// MappedRuleKeys returns the misconfiguration rule keys that carry a curated CIS control mapping. A guard
// test in the rule catalog uses it to assert every mapped key is a real, current rule (so a rule rename can
// never silently drop its compliance mapping).
func MappedRuleKeys() []string {
	keys := make([]string, 0, len(ruleControls))
	for k := range ruleControls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
