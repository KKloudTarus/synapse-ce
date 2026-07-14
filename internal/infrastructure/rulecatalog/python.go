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
		{"python-is-literal", "Identity check against a literal", "CWE-480", "if status == 404:\n    handle()", "if status is 404:\n    handle()", "Use == to compare values; reserve is for None and other singletons.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium},
		{"python-broad-except", "Broad except clause", "CWE-396", "try:\n    work()\nexcept ValueError:\n    recover()", "try:\n    work()\nexcept Exception:\n    recover()", "Catch the specific exception types the operation can raise, not Exception/BaseException.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium},
		{"python-lambda-assignment", "Lambda assigned to a variable", "", "def area(r):\n    return r * r", "area = lambda r: r * r", "Use a def statement so the function has a proper name in tracebacks.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"python-multiple-imports", "Multiple imports on one line", "", "import os\nimport sys", "import os, sys", "Put each import on its own line.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"python-fstring-no-placeholder", "f-string without placeholders", "", "message = 'ready'", "message = f'ready'", "Drop the f prefix from a string that has no placeholders.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityInfo},
		{"python-subprocess-shell", "subprocess with shell=True", "CWE-78", "subprocess.run(['ls', '-la'])", "subprocess.run(command, shell=True)", "Pass an argument list and shell=False so shell metacharacters cannot inject commands.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh},
		{"python-shadow-builtin", "Shadowing a builtin name", "", "item_list = fetch()", "list = fetch()", "Rename the variable so it does not shadow a builtin.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"python-assert-tuple", "Assert on a tuple is always true", "CWE-571", "assert count > 0, 'count must be positive'", "assert (count > 0, 'count must be positive')", "Remove the parentheses so the message is the second assert argument, not part of a tuple.", rule.TypeBug, rule.QualityReliability, shared.SeverityHigh},
		{"python-bind-all-interfaces", "Bind to all network interfaces", "CWE-605", "sock.bind(('127.0.0.1', 8080))", "sock.bind(('0.0.0.0', 8080))", "Bind to a specific interface address instead of 0.0.0.0 unless external exposure is intended.", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityMedium},
		{"python-mktemp-insecure", "Insecure tempfile.mktemp", "CWE-377", "fd, path = tempfile.mkstemp()", "path = tempfile.mktemp()", "Use tempfile.mkstemp or NamedTemporaryFile, which create the file atomically.", rule.TypeSecurityHotspot, rule.QualitySecurity, shared.SeverityMedium},
		{"python-yaml-unsafe-load", "Unsafe yaml.load", "CWE-502", "data = yaml.safe_load(text)", "data = yaml.load(text)", "Use yaml.safe_load for untrusted input.", rule.TypeVulnerability, rule.QualitySecurity, shared.SeverityHigh},
		{"python-return-in-init", "Return value in __init__", "", "def __init__(self):\n    self.value = 0", "def __init__(self):\n    return self.value", "Do not return a value from __init__; it must return None.", rule.TypeBug, rule.QualityReliability, shared.SeverityLow},
		{"python-too-long-function", "Overly long function", "", "def build():\n    return assemble(parts)", "def build():\n    # more than fifty sequential statements\n    return result", "Split the function into smaller, focused functions.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"python-mutable-class-attribute", "Mutable class attribute", "", "class Cart:\n    def __init__(self):\n        self.items = []", "class Cart:\n    items = []", "Assign mutable state in __init__ so it is per-instance, not shared across the class.", rule.TypeBug, rule.QualityReliability, shared.SeverityMedium},
		{"python-nested-conditional", "Nested conditional expression", "", "grade = high if score > 90 else classify(score)", "grade = high if score > 90 else (mid if score > 70 else low)", "Use an if/else statement instead of nesting conditional expressions.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"python-large-class", "Class has too many methods", "", "class Small:\n    def a(self):\n        return 1", "class God:\n    # more than twenty methods\n    def a(self):\n        return 1", "Split the class along its distinct responsibilities.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"python-compare-empty-collection", "Comparison to an empty collection", "", "if not items:\n    return", "if items == []:\n    return", "Use a truthiness check (if not items) instead of comparing to an empty literal.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"python-compare-bool-literal", "Comparison to a boolean literal", "", "if enabled:\n    run()", "if enabled == True:\n    run()", "Use the boolean value directly instead of comparing to True/False.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"python-too-many-returns", "Function has too many return statements", "", "def classify(x):\n    return grade(x)", "def classify(x):\n    if x == 1: return \"a\"\n    if x == 2: return \"b\"\n    if x == 3: return \"c\"\n    if x == 4: return \"d\"\n    if x == 5: return \"e\"\n    if x == 6: return \"f\"\n    return \"g\"", "Reduce the number of exit points; use a lookup or a single result variable.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"python-except-pass", "Exception silently passed", "CWE-390", "try:\n    work()\nexcept ValueError:\n    recover()", "try:\n    work()\nexcept ValueError:\n    pass", "Handle or log the exception instead of silently passing.", rule.TypeBug, rule.QualityReliability, shared.SeverityLow},
		{"python-deep-nesting", "Deeply nested control flow", "", "def handle(x):\n    if not x:\n        return\n    process(x)", "def handle(x):\n    if a:\n        for i in items:\n            while b:\n                with lock:\n                    if c:\n                        run()", "Flatten the logic with guard clauses and by extracting nested blocks into functions.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityMedium},
		{"python-nested-loop", "Deeply nested loops", "", "for row in grid:\n    process(row)", "for i in rows:\n    for j in cols:\n        for k in depth:\n            total += grid[i][j][k]", "Extract inner loops into functions, or rework the algorithm to reduce nesting.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityMedium},
		{"python-complex-condition", "Overly complex boolean condition", "", "if is_eligible(request):\n    accept()", "if a and b and c and d and e and f:\n    accept()", "Extract the sub-conditions into well-named boolean variables or helper functions.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityLow},
		{"python-high-complexity", "Function has high cyclomatic complexity", "", "def score(order):\n    return TABLE[order.type]", "def score(order):\n    # many if/elif, loops, and and/or branches\n    return computed", "Reduce the number of decision points by extracting helper functions or using a lookup.", rule.TypeCodeSmell, rule.QualityMaintainability, shared.SeverityMedium},
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
