package taint

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// cweID is the canonical CWE identifier shape, so a typo like "CWE-not-a-number" is rejected.
var cweID = regexp.MustCompile(`^CWE-[0-9]+$`)

// Custom taint rules let a deployment extend the built-in Python catalog with its own sources and sinks
// (Semgrep-style), loaded from a reviewable config file without regenerating Go. They are strictly
// ADDITIVE: a custom rule can only ADD detection (a new source or a new dangerous sink), never remove or
// weaken a built-in one. There are deliberately NO custom sanitizers, so a custom rule can never suppress a
// real flow; false positives on a custom sink are managed with the existing accepted-risk / ignore
// mechanisms, exactly as for a built-in finding.

const (
	maxCustomTaintRules   = 500 // cap total custom sources + sinks so a hostile config cannot bloat the catalog
	maxCustomPatternParts = 64  // cap modules/names per rule
)

// CustomRules is the whole custom-rule document.
type CustomRules struct {
	Python CustomPythonRules `yaml:"python" json:"python"`
	JS     CustomJsRules     `yaml:"js" json:"js"`
	Java   CustomJavaRules   `yaml:"java" json:"java"`
}

// CustomJavaRules extends the Java value-flow catalog. A custom Java source/sink is import-anchored (modules
// + names), the sound match the built-in catalog trusts most; the receiver-name floor the built-ins use for
// auto-imported/runtime-receiver sinks is deliberately NOT exposed to custom rules, so an operator cannot
// author an unanchored pattern that fires broadly.
type CustomJavaRules struct {
	Sources []CustomSource `yaml:"sources" json:"sources"`
	Sinks   []CustomSink   `yaml:"sinks" json:"sinks"`
}

// CustomPythonRules extends the Python value-flow catalog.
type CustomPythonRules struct {
	Sources []CustomSource `yaml:"sources" json:"sources"`
	Sinks   []CustomSink   `yaml:"sinks" json:"sinks"`
}

// CustomJsRules extends the JavaScript/TypeScript value-flow catalog. A custom JS source/sink is
// import-anchored (modules + names), the sound match the built-in catalog trusts most; the free-form global
// and receiver-name conventions are deliberately NOT exposed to custom rules, so an operator cannot author an
// unanchored pattern that fires broadly.
type CustomJsRules struct {
	Sources []CustomSource `yaml:"sources" json:"sources"`
	Sinks   []CustomSink   `yaml:"sinks" json:"sinks"`
}

// CustomSource marks a call result as untrusted for every taint class (a new entry point of attacker data).
type CustomSource struct {
	Modules []string `yaml:"modules" json:"modules"`
	Names   []string `yaml:"names" json:"names"`
}

// CustomSink marks a call's argument as dangerous for one taint class.
type CustomSink struct {
	Modules  []string `yaml:"modules" json:"modules"`
	Names    []string `yaml:"names" json:"names"`
	Class    string   `yaml:"class" json:"class"`       // must be a known TaintClass (e.g. "sql", "command")
	CWE      string   `yaml:"cwe" json:"cwe"`           // must be "CWE-<n>"
	Rule     string   `yaml:"rule" json:"rule"`         // short rule id
	Argument int      `yaml:"argument" json:"argument"` // zero-based tainted argument index
}

// Empty reports whether the document declares no custom rules.
func (r CustomRules) Empty() bool {
	return len(r.Python.Sources) == 0 && len(r.Python.Sinks) == 0 &&
		len(r.JS.Sources) == 0 && len(r.JS.Sinks) == 0 &&
		len(r.Java.Sources) == 0 && len(r.Java.Sinks) == 0
}

// Validate rejects a document that is malformed or that could bloat the catalog. It never fails open: an
// invalid rule is an error, not a silently-dropped entry, so an operator sees the mistake.
func (r CustomRules) Validate() error {
	total := len(r.Python.Sources) + len(r.Python.Sinks) + len(r.JS.Sources) + len(r.JS.Sinks) +
		len(r.Java.Sources) + len(r.Java.Sinks)
	if total > maxCustomTaintRules {
		return fmt.Errorf("%w: %d custom taint rules exceeds the cap of %d", shared.ErrValidation, total, maxCustomTaintRules)
	}
	if err := validateRuleSet("python", r.Python.Sources, r.Python.Sinks); err != nil {
		return err
	}
	if err := validateRuleSet("js", r.JS.Sources, r.JS.Sinks); err != nil {
		return err
	}
	return validateRuleSet("java", r.Java.Sources, r.Java.Sinks)
}

// validateRuleSet checks one language's custom sources and sinks: every pattern is a well-formed
// module+name anchor, and every sink names a known taint class, a CWE-<number>, a non-empty rule id, and a
// non-negative argument index. An invalid rule is an error, never a silently-dropped entry.
func validateRuleSet(lang string, sources []CustomSource, sinks []CustomSink) error {
	for i, s := range sources {
		if err := validatePattern(s.Modules, s.Names); err != nil {
			return fmt.Errorf("%w: %s custom source %d: %s", shared.ErrValidation, lang, i, err)
		}
	}
	for i, s := range sinks {
		if err := validatePattern(s.Modules, s.Names); err != nil {
			return fmt.Errorf("%w: %s custom sink %d: %s", shared.ErrValidation, lang, i, err)
		}
		if !TaintClass(strings.TrimSpace(s.Class)).Valid() {
			return fmt.Errorf("%w: %s custom sink %d: unknown taint class %q", shared.ErrValidation, lang, i, s.Class)
		}
		if !cweID.MatchString(strings.TrimSpace(s.CWE)) || strings.TrimSpace(s.Rule) == "" {
			return fmt.Errorf("%w: %s custom sink %d: cwe must be CWE-<number> and rule must be non-empty", shared.ErrValidation, lang, i)
		}
		if s.Argument < 0 {
			return fmt.Errorf("%w: %s custom sink %d: argument index must be non-negative", shared.ErrValidation, lang, i)
		}
	}
	return nil
}

func validatePattern(modules, names []string) error {
	if len(modules) == 0 || len(names) == 0 {
		return fmt.Errorf("modules and names are both required")
	}
	if len(modules) > maxCustomPatternParts || len(names) > maxCustomPatternParts {
		return fmt.Errorf("too many modules/names")
	}
	for _, m := range append(append([]string{}, modules...), names...) {
		if strings.TrimSpace(m) == "" {
			return fmt.Errorf("a module/name entry is empty")
		}
	}
	return nil
}

// WithCustomPython returns a copy of the catalog extended with the validated custom rules. It is additive:
// the built-in sources, sinks, and sanitizers are preserved unchanged, and the custom entries are appended.
// The caller must have called Validate first (WithCustomPython trusts the input shape).
func (c PythonCatalog) WithCustomPython(rules CustomPythonRules) PythonCatalog {
	out := c
	for _, s := range rules.Sources {
		out.Sources = append(out.Sources, PythonSourceModel{
			Pattern: PythonCallablePattern{Modules: normalizePatternList(s.Modules), Names: normalizePatternList(s.Names)},
			Classes: append([]TaintClass(nil), allPythonTaintClasses...),
		})
	}
	for _, s := range rules.Sinks {
		out.Sinks = append(out.Sinks, PythonSinkModel{
			Pattern:         PythonCallablePattern{Modules: normalizePatternList(s.Modules), Names: normalizePatternList(s.Names)},
			Class:           TaintClass(strings.TrimSpace(s.Class)),
			CWE:             strings.TrimSpace(s.CWE),
			Rule:            strings.TrimSpace(s.Rule),
			ArgumentIndexes: []int{s.Argument},
		})
	}
	return out
}

// WithCustomJs returns a copy of the JS catalog extended with the validated custom rules. Like the Python
// twin it is additive (built-ins are preserved, custom entries appended) and import-anchored (each custom
// source/sink matches only via its modules + names, never the free-form global or receiver-name conventions),
// so a custom rule can only ADD detection, never suppress or fire unanchored. Validate must have been called.
func (c JsCatalog) WithCustomJs(rules CustomJsRules) JsCatalog {
	out := c
	for _, s := range rules.Sources {
		out.Sources = append(out.Sources, JsSourceModel{
			Pattern: JsCallablePattern{Modules: normalizePatternList(s.Modules), Names: normalizePatternList(s.Names)},
			Classes: append([]TaintClass(nil), allJsTaintClasses...),
		})
	}
	for _, s := range rules.Sinks {
		out.Sinks = append(out.Sinks, JsSinkModel{
			Pattern:         JsCallablePattern{Modules: normalizePatternList(s.Modules), Names: normalizePatternList(s.Names)},
			Class:           TaintClass(strings.TrimSpace(s.Class)),
			CWE:             strings.TrimSpace(s.CWE),
			Rule:            strings.TrimSpace(s.Rule),
			ArgumentIndexes: []int{s.Argument},
		})
	}
	return out
}

// WithCustomJava returns a copy of the Java catalog extended with the validated custom rules. Like the JS
// twin it is additive (built-ins preserved, custom entries appended) and import-anchored (each custom
// source/sink matches only via its modules + names, never the receiver-name floor), so a custom rule can only
// ADD detection, never suppress or fire unanchored. Validate must have been called.
func (c JavaCatalog) WithCustomJava(rules CustomJavaRules) JavaCatalog {
	out := c
	for _, s := range rules.Sources {
		out.Sources = append(out.Sources, JavaSourceModel{
			Pattern: JavaCallablePattern{Modules: normalizePatternList(s.Modules), Names: normalizePatternList(s.Names)},
			Classes: append([]TaintClass(nil), allJavaTaintClasses...),
		})
	}
	for _, s := range rules.Sinks {
		out.Sinks = append(out.Sinks, JavaSinkModel{
			Pattern:         JavaCallablePattern{Modules: normalizePatternList(s.Modules), Names: normalizePatternList(s.Names)},
			Class:           TaintClass(strings.TrimSpace(s.Class)),
			CWE:             strings.TrimSpace(s.CWE),
			Rule:            strings.TrimSpace(s.Rule),
			ArgumentIndexes: []int{s.Argument},
		})
	}
	return out
}

func normalizePatternList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}
