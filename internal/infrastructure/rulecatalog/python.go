package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type pythonRuleSpec struct {
	key, name, cwe, compliant, noncompliant, remediation string
	type_                                                rule.Type
	quality                                              rule.Quality
	severity                                             shared.Severity
}

func pythonRules() []rule.Rule {
	specs := []pythonRuleSpec{
		{"python-mutable-default-argument", "Mutable default argument", "CWE-398", "def collect(items=None):\n    items = [] if items is None else items", "def collect(items=[]):\n    items.append(1)", "Use None as the default and allocate the mutable value inside the function.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh},
		{"python-return-in-finally", "Control flow in finally suppresses exceptions", "CWE-584", "try:\n    work()\nfinally:\n    cleanup()", "try:\n    work()\nfinally:\n    return", "Move return or loop control outside finally so active exceptions remain visible.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium},
		{"python-bare-except", "Bare except catches every exception", "CWE-396", "try:\n    work()\nexcept ValueError:\n    recover()", "try:\n    work()\nexcept:\n    recover()", "Catch only the exception types that the operation is expected to raise.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium},
		{"python-duplicate-dict-key", "Duplicate dictionary key", "CWE-561", "headers = {'accept': 'application/json'}", "headers = {'accept': 'text/plain', 'accept': 'application/json'}", "Remove the earlier duplicate key or use distinct keys.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium},
		{"python-assert-for-validation", "Runtime assert used for validation", "CWE-617", "if not user_id:\n    raise ValueError('user_id is required')", "assert user_id", "Raise an explicit exception because assertions can be disabled at runtime.", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityMedium},
		{"python-eq-none", "Compare None with is", "", "if value is None:\n    return", "if value == None:\n    return", "Use is None or is not None for singleton identity checks.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"python-star-import", "Wildcard import", "", "from package import useful_name", "from package import *", "Import the names used by the module explicitly.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"python-open-no-context", "File opened without a context manager", "", "with open(path) as source:\n    return source.read()", "source = open(path)\nreturn source.read()", "Use with open(...) so the resource is closed when execution leaves the block.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"python-type-eq-vs-isinstance", "Use isinstance instead of type equality", "", "if isinstance(value, str):\n    return value", "if type(value) == str:\n    return value", "Use isinstance when subclasses should be accepted.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"python-global-statement", "Global statement", "", "def increment(counter):\n    return counter + 1", "def increment():\n    global counter\n    counter += 1", "Pass state explicitly or encapsulate it in an object.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"python-too-many-args", "Function has too many arguments", "", "def configure(host, port, timeout):\n    return host", "def configure(a, b, c, d, e, f, g, h):\n    return a", "Group related parameters into a value object or configuration structure.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"python-f-string-logging", "Eager f-string logging", "", "logger.info('connected to %s', host)", "logger.info(f'connected to {host}')", "Pass values as logging arguments so formatting is deferred until needed.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityInfo},
		{"python-len-eq-zero", "Compare a collection directly", "", "if not items:\n    return", "if len(items) == 0:\n    return", "Use the collection's truth value instead of comparing its length to zero.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityInfo},
		{"python-unused-import", "Unused import", "", "import json\njson.dumps({})", "import json\nreturn 1", "Remove the import or reference the bound name.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityInfo},
		{"python-broad-raise", "Broad Exception raised", "", "raise ValueError('invalid value')", "raise Exception('invalid value')", "Raise the narrowest exception type callers can handle deliberately.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
	}
	rules := make([]rule.Rule, 0, len(specs))
	for _, s := range specs {
		rules = append(rules, rule.Rule{
			Key: rule.Key(s.key), Name: s.name, Language: "Python", Type: s.type_, Qualities: []rule.Quality{s.quality}, DefaultSeverity: s.severity,
			Tags: []string{"python", "ast"}, CWE: optionalCWE(s.cwe), OWASP: []string{},
			Description: "Detects " + lowerFirst(s.name) + " in Python source.",
			Rationale:   "This rule highlights a Python construct that can make behavior less safe, reliable, or maintainable.\n\nSource: https://docs.python.org/3/reference/",
			Remediation: s.remediation, CompliantExample: s.compliant, NoncompliantExample: s.noncompliant, RemediationEffort: 15, Detection: rule.DetectionAST,
		})
	}
	return rules
}

func optionalCWE(cwe string) []string {
	if cwe == "" {
		return []string{}
	}
	return []string{cwe}
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return string(s[0]+32) + s[1:]
}
