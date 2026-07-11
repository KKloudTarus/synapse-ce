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
	sort.Slice(out, func(i, j int) bool {
		if out[i].Framework != out[j].Framework {
			return out[i].Framework < out[j].Framework
		}
		return out[i].ID < out[j].ID
	})
	return out
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
