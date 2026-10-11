package msgtemplate

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/template"
	"unicode/utf8"
)

// errArgument is the only error an allowlisted function returns for bad data. It carries no
// argument value, so a render error can never echo template data.
var errArgument = errors.New("msgtemplate: invalid function argument")

// escapeFunc is appended to every output action after validation (rewrite.go). Templates cannot
// call it: it is not in funcSpecs, so the validator rejects the identifier.
const escapeFunc = "msgtemplate_escape_value"

// funcs implements the allowlisted functions for one render. Every function charges the runes it
// processes to the render's meter. eq and ne replace the text/template builtins so that string
// comparisons are metered too; and, or and not stay builtins because they are O(1).
type funcs struct {
	meter *meter
}

// funcMap binds the implementations to m. Compile binds a throwaway meter, because parsing only
// needs the signatures; Render binds a fresh meter per execution.
func funcMap(m *meter) template.FuncMap {
	f := funcs{meter: m}
	return template.FuncMap{
		"default":        f.fallback,
		"upper":          f.upper,
		"lower":          f.lower,
		"truncate":       f.truncate,
		"join":           f.join,
		"severity_label": f.severityLabel,
		"count":          f.count,
		"plural":         f.plural,
		"eq":             f.eq,
		"ne":             f.ne,
		escapeFunc:       f.escape,
	}
}

// fallback implements default, written for pipelines: {{.owner | default "unassigned"}}.
func (f funcs) fallback(fallback, value string) (string, error) {
	if err := f.meter.charge(len(value)); err != nil {
		return "", err
	}
	if strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	return value, nil
}

func (f funcs) upper(value string) (string, error) {
	if err := f.meter.charge(len(value)); err != nil {
		return "", err
	}
	return strings.ToUpper(value), nil
}

func (f funcs) lower(value string) (string, error) {
	if err := f.meter.charge(len(value)); err != nil {
		return "", err
	}
	return strings.ToLower(value), nil
}

// truncate clamps n to [0, MaxOutputRunes] and marks a cut with an ellipsis. It does not set
// Output.Truncated, which reports only the caller's maxRunes cap.
func (f funcs) truncate(n int, value string) (string, error) {
	if err := f.meter.charge(len(value)); err != nil {
		return "", err
	}
	return truncateRunes(value, min(max(n, 0), MaxOutputRunes)), nil
}

// join joins one field of every item: {{join "title" ", " .items}} or {{.items | join "title" ", "}}.
// The validator has already checked that field exists in the list schema.
func (f funcs) join(field, sep string, items []map[string]string) (string, error) {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		value, ok := item[field]
		if !ok {
			return "", errArgument
		}
		if err := f.meter.charge(len(value) + len(sep)); err != nil {
			return "", err
		}
		parts = append(parts, value)
	}
	return strings.Join(parts, sep), nil
}

// severityLabel returns the English display label; localized labels belong to the templates.
func (f funcs) severityLabel(severity string) (string, error) {
	if err := f.meter.charge(len(severity)); err != nil {
		return "", err
	}
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "Critical", nil
	case "high":
		return "High", nil
	case "medium":
		return "Medium", nil
	case "low":
		return "Low", nil
	case "info", "informational":
		return "Info", nil
	}
	return "Unknown", nil
}

func (f funcs) count(items []map[string]string) (int, error) {
	return len(items), f.meter.charge(0)
}

// plural accepts a number or a decimal string, because template variables are strings.
func (f funcs) plural(n any, one, many string) (string, error) {
	if err := f.meter.charge(0); err != nil {
		return "", err
	}
	count, err := toInt(n)
	if err != nil {
		return "", err
	}
	if count == 1 {
		return one, nil
	}
	return many, nil
}

// eq reports whether first equals any of others. The validator guarantees one basic kind.
func (f funcs) eq(first any, others ...any) (bool, error) {
	for _, other := range others {
		equal, err := f.equal(first, other)
		if err != nil || equal {
			return equal, err
		}
	}
	return false, nil
}

func (f funcs) ne(a, b any) (bool, error) {
	equal, err := f.equal(a, b)
	return !equal, err
}

func (f funcs) equal(a, b any) (bool, error) {
	if err := f.meter.charge(len(printValue(a)) + len(printValue(b))); err != nil {
		return false, err
	}
	switch a.(type) {
	case string, int, bool, float64:
		return a == b, nil
	}
	return false, errArgument
}

// escape makes an interpolated value literal text in the Markdown subset.
func (f funcs) escape(value any) (string, error) {
	text := printValue(value)
	if err := f.meter.charge(2 * utf8.RuneCountInString(text)); err != nil {
		return "", err
	}
	return EscapeMarkdown(Sanitize(text)), nil
}

func toInt(n any) (int, error) {
	switch v := n.(type) {
	case int:
		return v, nil
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0, errArgument
		}
		return parsed, nil
	}
	return 0, errArgument
}

func printValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case bool:
		return strconv.FormatBool(v)
	}
	return fmt.Sprint(value)
}
