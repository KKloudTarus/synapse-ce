package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type notebookRuleSpec struct {
	key, name, cwe, compliant, noncompliant, remediation, source string
	type_                                                        rule.Type
	quality                                                      rule.Quality
	severity                                                     shared.Severity
}

func notebookRules() []rule.Rule {
	bearerExample := "print(authScheme + ' ' + redactedToken)"
	credentialURLExample := "print(buildURL(user, redactedCredential, host))"
	specs := []notebookRuleSpec{
		{"ipynb-secret-in-output", "Sensitive value saved in notebook output", "CWE-798", "# Clear outputs before committing", "print('token=' + token)", "Clear output before sharing and rotate any exposed secret.", "https://cwe.mitre.org/data/definitions/798.html", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityHigh},
		{"ipynb-hardcoded-credential", "Credential literal in notebook cell", "CWE-798", "token = os.environ['TOKEN']", "token = 'change-this-secret'", "Read credentials from the environment or a secrets manager.", "https://cwe.mitre.org/data/definitions/798.html", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityHigh},
		{"ipynb-private-key-in-output", "Private key saved in notebook output", "CWE-798", "print('key loaded')", "print('-----BEGIN PRIVATE KEY-----')", "Clear the output and rotate the key.", "https://cwe.mitre.org/data/definitions/798.html", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityHigh},
		{"ipynb-aws-access-key-in-output", "AWS access key saved in notebook output", "CWE-798", "print('credential configured')", "print('AKIAABCDEFGHIJKLMNOP')", "Clear output and rotate the related AWS credential.", "https://cwe.mitre.org/data/definitions/798.html", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityHigh},
		{"ipynb-bearer-token-in-output", "Bearer token saved in notebook output", "CWE-798", "print('authorized')", bearerExample, "Clear output and revoke or rotate the token.", "https://cwe.mitre.org/data/definitions/798.html", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityHigh},
		{"ipynb-password-url-in-output", "Password-bearing URL saved in notebook output", "CWE-798", "print('connected')", credentialURLExample, "Remove the URL from output and rotate the password.", "https://cwe.mitre.org/data/definitions/798.html", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityHigh},
		{"ipynb-html-script-output", "Suspicious executable markup saved in notebook output", "CWE-79", "display(HTML('<script>renderChart()</script>'))", "display(HTML('<script>document.write(value)</script>'))", "Review executable output with injection signals and remove it before sharing.", "https://cwe.mitre.org/data/definitions/79.html", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityMedium},
		{"ipynb-traceback-sensitive-path", "Sensitive path saved in notebook output", "CWE-200", "print('failed')", "Traceback: /home/alice/project/private.py", "Clear traceback output before distributing the notebook.", "https://cwe.mitre.org/data/definitions/200.html", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityMedium},
		{"ipynb-shell-magic-injection", "Shell magic interpolates a variable", "CWE-78", "!pip install package==1.0.0", "!cat {user_path}", "Avoid shell escapes or strictly validate values before passing them to a shell.", "https://cwe.mitre.org/data/definitions/78.html", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh},
		{"ipynb-system-magic-injection", "System magic interpolates a variable", "CWE-78", "%system ls -- /tmp", "%system cat {user_path}", "Use fixed commands or validate every interpolated argument.", "https://cwe.mitre.org/data/definitions/78.html", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh},
		{"ipynb-bash-cell-magic-injection", "Bash cell magic interpolates a variable", "CWE-78", "%%bash\necho ready", "%%bash\ncat {user_path}", "Do not interpolate untrusted values into shell cell magics.", "https://cwe.mitre.org/data/definitions/78.html", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh},
		{"ipynb-non-linear-execution", "Notebook execution order is non-linear", "", "execution_count: 1, 2, 3", "execution_count: 4, 2", "Restart and run all cells in order before saving.", "https://nbformat.readthedocs.io/en/latest/format_description.html", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"ipynb-unpinned-cell-dependency", "Notebook installs an unpinned dependency", "", "!pip install package==1.2.3", "!pip install package", "Pin an exact dependency version in a reproducible environment file or install command.", "https://packaging.python.org/en/latest/guides/repeatable-installs/", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"ipynb-stale-output", "Unexecuted cell retains output", "", "execution_count: 1, outputs: []", "execution_count: null, outputs: ['old result']", "Clear stale output or execute the cell before saving.", "https://nbformat.readthedocs.io/en/latest/format_description.html", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"ipynb-missing-kernelspec", "Notebook has no kernel specification", "", "metadata: { kernelspec: { name: 'python3', language: 'python' } }", "metadata: {}", "Add kernelspec metadata so users can reproduce the intended kernel.", "https://nbformat.readthedocs.io/en/latest/format_description.html", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
	}
	rules := make([]rule.Rule, 0, len(specs))
	for _, spec := range specs {
		rules = append(rules, rule.Rule{
			Key: rule.Key(spec.key), Name: spec.name, Language: "IPython Notebooks", Type: spec.type_, Qualities: []rule.Quality{spec.quality}, DefaultSeverity: spec.severity,
			Tags: []string{"ipynb", "notebook", "parse"}, CWE: optionalCWE(spec.cwe), OWASP: []string{},
			Description: "Detects " + lowerFirst(spec.name) + " in IPython notebook content.",
			Rationale:   "Notebook state can expose security-sensitive data or make results difficult to reproduce.\n\nSource: " + spec.source,
			Remediation: spec.remediation, CompliantExample: spec.compliant, NoncompliantExample: spec.noncompliant, RemediationEffort: 15, Detection: rule.DetectionParse,
		})
	}
	return rules
}
