package msgtemplate

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/template"
)

// errArgument is the only error an allowlisted function returns. It carries no argument value, so a
// render error can never echo template data.
var errArgument = errors.New("msgtemplate: invalid function argument")

// escapeFunc is appended to every output action after validation (rewrite.go). Templates cannot
// call it: it is not in funcSpecs, so the validator rejects the identifier.
const escapeFunc = "msgtemplate_escape_value"

// funcMap registers the implementations of the non-builtin functions in funcSpecs, plus the
// internal escape function.
func funcMap() template.FuncMap {
	return template.FuncMap{
		"default":        fnDefault,
		"upper":          strings.ToUpper,
		"lower":          strings.ToLower,
		"truncate":       fnTruncate,
		"join":           fnJoin,
		"severity_label": fnSeverityLabel,
		"count":          fnCount,
		"plural":         fnPlural,
		escapeFunc:       escapeValue,
	}
}

// fnDefault is written for pipelines: {{.owner | default "unassigned"}}.
func fnDefault(fallback, value string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// fnTruncate clamps n to [0, MaxOutputRunes] and marks a cut with an ellipsis.
func fnTruncate(n int, value string) string {
	return truncateRunes(value, min(max(n, 0), MaxOutputRunes))
}

// fnJoin joins one field of every item: {{join "title" ", " .items}} or {{.items | join "title" ", "}}.
// The validator has already checked that field exists in the list schema.
func fnJoin(field, sep string, items []map[string]string) (string, error) {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		value, ok := item[field]
		if !ok {
			return "", errArgument
		}
		parts = append(parts, value)
	}
	return strings.Join(parts, sep), nil
}

// fnSeverityLabel returns the English display label; localized labels belong to the templates.
func fnSeverityLabel(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "info", "informational":
		return "Info"
	}
	return "Unknown"
}

func fnCount(items []map[string]string) int {
	return len(items)
}

// fnPlural accepts a number or a decimal string, because template variables are strings.
func fnPlural(n any, one, many string) (string, error) {
	count, err := toInt(n)
	if err != nil {
		return "", err
	}
	if count == 1 {
		return one, nil
	}
	return many, nil
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

// escapeValue makes an interpolated value literal text in the Markdown subset.
func escapeValue(value any) string {
	return EscapeMarkdown(Sanitize(printValue(value)))
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
