package dastcheck

// Catalog is the complete production-safe DAST corpus. Entries deliberately
// cover passive response observations only; injection and state-changing probes
// are never included.
var Catalog = []CatalogEntry{
	{ID: "auth-configured-weakness", CWE: "CWE-287", Class: ClassAuthenticationWeakness, Title: "Configured authentication weakness", Description: "A configured, deterministic authentication weakness signature was observed.", Remediation: "Remove the weak authentication behavior and require the intended authentication control."},
	{ID: "cookie-security-flags", CWE: "CWE-614", Class: ClassMisconfiguration, Title: "Cookie security flags", Description: "An observed cookie omitted a configured transport, script, or cross-site protection flag.", Remediation: "Set Secure, HttpOnly, and an appropriate SameSite attribute on session cookies."},
	{ID: "security-headers", CWE: "CWE-693", Class: ClassMisconfiguration, Title: "Security response headers", Description: "A supported HTTP response omitted a required security header.", Remediation: "Set the required response security headers at the application or edge."},
	{ID: "sensitive-public-artifact", CWE: "CWE-200", Class: ClassSensitiveDataExposure, Title: "Sensitive public artifact", Description: "A deterministic source-map or well-known sensitive artifact signature was exposed.", Remediation: "Remove the artifact from public deployment or restrict it to authorized users."},
}

// Checks is the executable counterpart of Catalog. ValidateParity keeps the
// public catalog and implementation set from drifting apart.
var Checks = []Check{
	{ID: "auth-configured-weakness", CWE: "CWE-287", Class: ClassAuthenticationWeakness, BlastRadius: RadiusReadOnly, ProductionSafe: true, ProofClass: "configured_signature"},
	{ID: "cookie-security-flags", CWE: "CWE-614", Class: ClassMisconfiguration, BlastRadius: RadiusReadOnly, ProductionSafe: true, ProofClass: "cookie_flags"},
	{ID: "security-headers", CWE: "CWE-693", Class: ClassMisconfiguration, BlastRadius: RadiusReadOnly, ProductionSafe: true, ProofClass: "response_headers"},
	{ID: "sensitive-public-artifact", CWE: "CWE-200", Class: ClassSensitiveDataExposure, BlastRadius: RadiusReadOnly, ProductionSafe: true, ProofClass: "artifact_signature"},
}
