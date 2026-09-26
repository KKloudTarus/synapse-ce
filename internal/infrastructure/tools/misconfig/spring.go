package misconfig

import (
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Spring Boot application config is a security surface, not just wiring. Actuator publishes live
// introspection endpoints over HTTP, and which ones are published is a property of this file alone:
// management.endpoints.web.exposure.include is the allow-list, and /actuator/env, /actuator/configprops and
// /actuator/heapdump return resolved configuration and process memory. The H2 console is a remote SQL shell.
//
// Detection is over the FILE's own keys, so it holds for a repository with no running instance, and both
// config dialects are handled: nested YAML, the flattened `a.b.c:` YAML key Spring also accepts, and
// .properties. Nothing here inspects Spring Security, so a finding says an endpoint is published, never that
// it is unauthenticated; the description says so and the severities reflect it.

// springSensitiveEndpoints are the Actuator endpoint IDs whose response discloses configuration, memory,
// request history or session state, or which mutate the running application. health, info, metrics and
// prometheus are deliberately absent: publishing those is the normal reason Actuator is enabled.
var springSensitiveEndpoints = map[string]string{
	"env":            "resolved configuration properties",
	"configprops":    "resolved @ConfigurationProperties beans",
	"heapdump":       "a full heap dump of the process",
	"threaddump":     "every thread's stack",
	"logfile":        "the application log",
	"loggers":        "runtime log-level changes (write)",
	"shutdown":       "application shutdown (write)",
	"sessions":       "active session identifiers",
	"beans":          "the bean graph",
	"mappings":       "every request mapping",
	"conditions":     "auto-configuration decisions",
	"auditevents":    "the audit trail",
	"httptrace":      "recent HTTP exchanges",
	"httpexchanges":  "recent HTTP exchanges",
	"startup":        "the startup step timings",
	"quartz":         "scheduled Quartz jobs",
	"scheduledtasks": "scheduled tasks",
	"liquibase":      "database changelog history",
	"flyway":         "database migration history",
	"caches":         "cache contents and eviction (write)",
}

// isSpringConfigName reports whether a basename is a Spring Boot application config. The profile suffix
// (application-dev.yml) and the .properties dialect are included; bootstrap.yml is the Spring Cloud
// equivalent and carries the same keys.
func isSpringConfigName(name string) bool {
	lower := strings.ToLower(name)
	var stem string
	switch {
	case strings.HasSuffix(lower, ".yml"):
		stem = strings.TrimSuffix(lower, ".yml")
	case strings.HasSuffix(lower, ".yaml"):
		stem = strings.TrimSuffix(lower, ".yaml")
	case strings.HasSuffix(lower, ".properties"):
		stem = strings.TrimSuffix(lower, ".properties")
	default:
		return false
	}
	return stem == "application" || strings.HasPrefix(stem, "application-") ||
		stem == "bootstrap" || strings.HasPrefix(stem, "bootstrap-")
}

// looksSpringConfig is the content pre-filter: the file must declare one of the two top-level trees these
// rules read. A file merely NAMED application.yml (a fixture, an unrelated config) contributes nothing.
func looksSpringConfig(data []byte) bool {
	t := string(data)
	for _, marker := range []string{"management:", "spring:", "management.", "spring."} {
		if strings.Contains(t, marker) {
			return true
		}
	}
	return false
}

// springValue is one resolved config entry: the scalar values at a dotted key, and the line they sit on.
type springValue struct {
	values []string
	line   int
}

// scanSpringConfig returns the findings for one Spring Boot application config.
func scanSpringConfig(rel string, data []byte) []ports.MisconfigRawFinding {
	cfg := springConfig(rel, data)
	if cfg == nil {
		return nil
	}
	var out []ports.MisconfigRawFinding
	add := func(rule, title, desc string, sev shared.Severity, line int) {
		if line == 0 {
			line = 1
		}
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: rule, Title: title, Severity: sev,
			Resource: "spring-config", Description: desc,
		})
	}

	if v, ok := cfg["management.endpoints.web.exposure.include"]; ok {
		wildcard := false
		var named []string
		for _, entry := range v.values {
			entry = strings.ToLower(strings.Trim(strings.TrimSpace(entry), `'"`))
			if entry == "*" {
				wildcard = true
				continue
			}
			if _, sensitive := springSensitiveEndpoints[entry]; sensitive {
				named = append(named, entry)
			}
		}
		if wildcard {
			add("spring-actuator-exposure-wildcard", "Actuator exposes every endpoint",
				"management.endpoints.web.exposure.include is \"*\", so every Actuator endpoint is published over HTTP, including heapdump (a full memory image) and env (resolved configuration). List only the endpoints the service needs.",
				shared.SeverityHigh, v.line)
		}
		if len(named) > 0 {
			sort.Strings(named)
			var described []string
			for _, name := range named {
				described = append(described, name+" ("+springSensitiveEndpoints[name]+")")
			}
			add("spring-actuator-sensitive-endpoint-exposed", "Actuator publishes a sensitive endpoint",
				"management.endpoints.web.exposure.include publishes "+clip(strings.Join(described, ", "))+
					". Each discloses internal state or mutates the running application, so it must be removed from the allow-list or reachable only from an authenticated management port.",
				shared.SeverityMedium, v.line)
		}
	}
	if v, ok := cfg["management.endpoint.shutdown.enabled"]; ok && springTrue(v.values) {
		add("spring-actuator-shutdown-enabled", "Actuator shutdown endpoint enabled",
			"management.endpoint.shutdown.enabled is true, so a POST to the shutdown endpoint stops the application. Leave it disabled and stop the process through the platform.",
			shared.SeverityHigh, v.line)
	}
	if v, ok := cfg["spring.h2.console.enabled"]; ok && springTrue(v.values) {
		add("spring-h2-console-enabled", "H2 web console enabled",
			"spring.h2.console.enabled is true, which serves a browser SQL shell against the application's datasource. It has been the entry point for remote code execution in H2, and it is not meant to be reachable outside a developer's machine. Disable it for every profile that ships.",
			shared.SeverityHigh, v.line)
	}
	if v, ok := cfg["management.endpoint.health.show-details"]; ok {
		for _, entry := range v.values {
			if strings.EqualFold(strings.Trim(strings.TrimSpace(entry), `'"`), "always") {
				add("spring-actuator-health-details-always", "Health endpoint always shows details",
					"management.endpoint.health.show-details is \"always\", so the health endpoint reports every component's detail (database hostnames, broker addresses, disk paths) to any caller. Use when_authorized.",
					shared.SeverityLow, v.line)
				break
			}
		}
	}
	return out
}

// springConfig flattens one config file into dotted keys. Both YAML dialects Spring accepts are handled: a
// nested tree, and a key that already carries dots. A .properties file is read line by line.
func springConfig(rel string, data []byte) map[string]springValue {
	if strings.HasSuffix(strings.ToLower(rel), ".properties") {
		return springProperties(data)
	}
	if tooDeepYAML(data) {
		return nil
	}
	out := make(map[string]springValue)
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			break // EOF or a stream syntax error: keep whatever earlier documents produced
		}
		for _, root := range doc.Content {
			springFlatten(root, "", out)
		}
	}
	return out
}

// springFlattenMaxDepth bounds the recursion independently of the YAML depth guard, so a config with a
// deeply nested but syntactically shallow map cannot drive this walk without limit.
const springFlattenMaxDepth = 64

func springFlatten(node *yaml.Node, prefix string, out map[string]springValue) {
	springFlattenAt(node, prefix, out, 0)
}

func springFlattenAt(node *yaml.Node, prefix string, out map[string]springValue, depth int) {
	if node == nil || depth > springFlattenMaxDepth {
		return
	}
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			value := node.Content[i+1]
			name := strings.ToLower(strings.TrimSpace(key.Value))
			if name == "" {
				continue
			}
			next := name
			if prefix != "" {
				next = prefix + "." + name
			}
			springFlattenAt(value, next, out, depth+1)
		}
	case yaml.SequenceNode:
		var values []string
		for _, item := range node.Content {
			if item.Kind == yaml.ScalarNode {
				values = append(values, item.Value)
			}
		}
		if prefix != "" && len(values) > 0 {
			out[prefix] = springValue{values: values, line: node.Line}
		}
	case yaml.ScalarNode:
		if prefix == "" {
			return
		}
		// Spring reads a comma-separated scalar as a list, which is how the exposure allow-list is often
		// written, so one scalar becomes the same shape as a sequence.
		out[prefix] = springValue{values: springSplit(node.Value), line: node.Line}
	case yaml.AliasNode:
		springFlattenAt(node.Alias, prefix, out, depth+1)
	}
}

func springProperties(data []byte) map[string]springValue {
	out := make(map[string]springValue)
	for i, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!") {
			continue
		}
		key, value, found := strings.Cut(trimmed, "=")
		if !found {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(key))
		if name == "" {
			continue
		}
		out[name] = springValue{values: springSplit(value), line: i + 1}
	}
	return out
}

// springSplit turns a scalar into the list Spring would bind it to: comma separated, brackets stripped.
func springSplit(raw string) []string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func springTrue(values []string) bool {
	for _, v := range values {
		if strings.EqualFold(strings.Trim(strings.TrimSpace(v), `'"`), "true") {
			return true
		}
	}
	return false
}
