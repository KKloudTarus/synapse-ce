// Package writeup holds the built-in finding-writeup library: reusable,
// curated finding text + remediation an operator inserts when authoring a manual
// finding, so report prose is consistent. It is static reference data – pure,
// deterministic, no I/O – and carries no LLM in the path. The
// authored finding (with this text) is what later flows into the report.
package writeup

import "github.com/KKloudTarus/synapse-ce/internal/domain/shared"

// Writeup is one reusable finding template.
type Writeup struct {
	ID          string          `json:"id"`       // stable slug, e.g. "xss-stored"
	Title       string          `json:"title"`    // suggested finding title
	Category    string          `json:"category"` // grouping label, e.g. "Web"
	CWE         string          `json:"cwe"`      // e.g. "CWE-79"
	Severity    shared.Severity `json:"severity"` // suggested severity
	CVSSVector  string          `json:"cvssVector"`
	Description string          `json:"description"`
	Remediation string          `json:"remediation"`
	References  []string        `json:"references"`
}

// Catalog returns the built-in writeup library in a stable order. It builds a fresh
// slice on each call so callers cannot mutate the shared reference data.
func Catalog() []Writeup {
	return []Writeup{
		{
			ID: "xss-stored", Title: "Stored Cross-Site Scripting (XSS)", Category: "Web", CWE: "CWE-79",
			Severity: shared.SeverityHigh, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
			Description: "User-supplied input is persisted and later rendered into a page without contextual output encoding, allowing an attacker to store script that executes in the browser of any user who views the affected content.",
			Remediation: "Apply contextual output encoding at render time, validate and normalize input on the server, and deploy a restrictive Content-Security-Policy. Prefer framework auto-escaping over hand-rolled sanitization.",
			References:  []string{"CWE-79", "OWASP A03:2021 – Injection"},
		},
		{
			ID: "xss-reflected", Title: "Reflected Cross-Site Scripting (XSS)", Category: "Web", CWE: "CWE-79",
			Severity: shared.SeverityMedium, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
			Description: "A request parameter is reflected into the response without output encoding, allowing an attacker to craft a link that executes script in the victim's browser session.",
			Remediation: "Contextually encode all reflected values, validate input server-side, and set a restrictive Content-Security-Policy.",
			References:  []string{"CWE-79", "OWASP A03:2021 – Injection"},
		},
		{
			ID: "sqli", Title: "SQL Injection", Category: "Web", CWE: "CWE-89",
			Severity: shared.SeverityCritical, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Description: "Untrusted input is concatenated into a SQL statement, allowing an attacker to alter query logic to read, modify, or delete data, and in some configurations achieve code execution on the database host.",
			Remediation: "Use parameterized queries / prepared statements for all data access. Apply least-privilege database accounts and validate input as defense in depth.",
			References:  []string{"CWE-89", "OWASP A03:2021 – Injection"},
		},
		{
			ID: "idor", Title: "Insecure Direct Object Reference (IDOR)", Category: "Access Control", CWE: "CWE-639",
			Severity: shared.SeverityHigh, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
			Description: "An endpoint exposes a direct reference to an internal object (record id, file, account) without verifying that the authenticated principal is authorized for that specific object, letting an attacker access or modify another tenant's or user's data.",
			Remediation: "Enforce per-object authorization on every request server-side (ownership/tenancy checks), not just at the menu/UI layer. Prefer unguessable references only as defense in depth, never as the sole control.",
			References:  []string{"CWE-639", "OWASP A01:2021 – Broken Access Control"},
		},
		{
			ID: "ssrf", Title: "Server-Side Request Forgery (SSRF)", Category: "Web", CWE: "CWE-918",
			Severity: shared.SeverityHigh, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",
			Description: "The application fetches a URL supplied or influenced by the user without adequate validation, allowing an attacker to make the server issue requests to internal services, cloud metadata endpoints, or arbitrary hosts.",
			Remediation: "Validate and allow-list destinations, resolve and pin hostnames, block link-local and private ranges (incl. cloud metadata 169.254.169.254), and disable unneeded URL schemes/redirects.",
			References:  []string{"CWE-918", "OWASP A10:2021 – SSRF"},
		},
		{
			ID: "missing-security-headers", Title: "Missing Security Headers", Category: "Configuration", CWE: "CWE-693",
			Severity: shared.SeverityLow, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
			Description: "Responses omit hardening headers (e.g. Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options), weakening defense-in-depth against XSS, clickjacking, and protocol-downgrade attacks.",
			Remediation: "Set Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options: nosniff, and a frame-ancestors/X-Frame-Options policy at the edge or framework layer.",
			References:  []string{"CWE-693", "OWASP Secure Headers Project"},
		},
		{
			ID: "outdated-dependency", Title: "Outdated Component with Known Vulnerabilities", Category: "Dependencies", CWE: "CWE-1395",
			Severity: shared.SeverityMedium, CVSSVector: "",
			Description: "The project ships a third-party component pinned to a version with published vulnerabilities. Risk depends on whether the vulnerable code path is reachable, but the component should be upgraded regardless.",
			Remediation: "Upgrade to a fixed release, add the advisory to dependency monitoring, and adopt automated SCA in CI to catch regressions. Where upgrade is blocked, document a compensating control and a remediation date.",
			References:  []string{"CWE-1395", "OWASP A06:2021 – Vulnerable and Outdated Components"},
		},
		{
			ID: "hardcoded-secret", Title: "Hardcoded Credential / Secret in Source", Category: "Secrets", CWE: "CWE-798",
			Severity: shared.SeverityHigh, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			Description: "A credential, API key, or token is embedded in source or configuration committed to the repository, exposing it to anyone with read access to the code or its history.",
			Remediation: "Revoke and rotate the exposed secret, move secrets to a managed vault / environment injection, and add secret scanning to CI and pre-commit. Purge the value from git history if widely exposed.",
			References:  []string{"CWE-798", "OWASP A07:2021 – Identification and Authentication Failures"},
		},
	}
}

// Get returns the writeup with the given id, or ok=false if none matches.
func Get(id string) (Writeup, bool) {
	for _, w := range Catalog() {
		if w.ID == id {
			return w, true
		}
	}
	return Writeup{}, false
}
