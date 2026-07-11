package compliance

// BaselineSpec is the owned "Synapse AppSec Baseline" benchmark: a small, deterministic control set that
// re-projects Synapse's own findings (pattern-SAST CWEs, secret + misconfig kinds, severity) into
// auditor-citable pass/fail. It is a STARTER spec that exercises the engine end to end; ingesting a
// third-party benchmark verbatim (a CIS/PSS YAML, joined by check id) is a follow-up – the engine is the
// same, only the spec source differs. Each control's join keys trace to what Synapse actually detects, so a
// FAIL is always backed by a real, listed finding.
func BaselineSpec() Spec {
	return Spec{
		ID:      "synapse-appsec-baseline",
		Title:   "Synapse AppSec Baseline",
		Version: "1.0",
		Controls: []SpecControl{
			{
				ID:    "SAB-INJ-1",
				Title: "No injection weaknesses (SQL, command, code, XSS, NoSQL, XXE, SSTI, LDAP)",
				CWEs:  []string{"CWE-89", "CWE-78", "CWE-94", "CWE-95", "CWE-79", "CWE-943", "CWE-611", "CWE-1336", "CWE-90", "CWE-643"},
			},
			{
				ID:    "SAB-CRYPTO-1",
				Title: "No weak cryptography (broken hash/cipher, cert validation, key size, weak PRNG)",
				CWEs:  []string{"CWE-327", "CWE-295", "CWE-326", "CWE-338", "CWE-916"},
			},
			{
				ID:    "SAB-SECRET-1",
				Title: "No hardcoded secrets or credentials",
				CWEs:  []string{"CWE-798"},
				Kinds: []string{"secret"},
			},
			{
				ID:    "SAB-ACCESS-1",
				Title: "No access-control, SSRF, path-traversal, or open-redirect gaps",
				CWEs:  []string{"CWE-22", "CWE-918", "CWE-639", "CWE-601", "CWE-284", "CWE-732"},
			},
			{
				ID:    "SAB-INTEGRITY-1",
				Title: "No unsafe deserialization or token-integrity failures",
				CWEs:  []string{"CWE-502", "CWE-347"},
			},
			{
				ID:    "SAB-IAC-1",
				Title: "No insecure infrastructure-as-code / container configuration",
				Kinds: []string{"misconfig"},
			},
			{
				ID:          "SAB-SEV-1",
				Title:       "No critical-severity findings",
				MinSeverity: "critical",
			},
		},
	}
}
