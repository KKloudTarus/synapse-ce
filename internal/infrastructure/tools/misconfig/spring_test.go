package misconfig

import "testing"

// The exposure allow-list is the one place a repository decides which Actuator endpoints are reachable, and
// a JHipster-generated config publishes several sensitive ones. Semgrep found this class on 9 of 24 live
// repositories where this engine found nothing.
func TestSpringActuatorSensitiveEndpointsInBlockList(t *testing.T) {
	cfg := `spring:
  application:
    name: api
management:
  endpoints:
    web:
      base-path: /management
      exposure:
        include:
          [
            'configprops',
            'env',
            'health',
            'info',
            'logfile',
            'loggers',
            'prometheus',
            'threaddump',
          ]
`
	got := ruleIDs(scan(t, map[string]string{"src/main/resources/config/application.yml": cfg}))
	f, ok := got["spring-actuator-sensitive-endpoint-exposed"]
	if !ok {
		t.Fatalf("expected the sensitive-endpoint rule to fire, got %v", keys(got))
	}
	for _, want := range []string{"configprops", "env", "logfile", "loggers", "threaddump"} {
		if !contains(f.Description, want) {
			t.Errorf("description should name %q, got %q", want, f.Description)
		}
	}
	// health, info, metrics and prometheus are the ordinary reason Actuator is on: never named as a defect.
	for _, benign := range []string{"health (", "info (", "prometheus ("} {
		if contains(f.Description, benign) {
			t.Errorf("description must not name the benign endpoint %q: %q", benign, f.Description)
		}
	}
	if _, bad := got["spring-actuator-exposure-wildcard"]; bad {
		t.Error("an explicit list is not a wildcard")
	}
}

// A config that publishes only the benign endpoints is clean, which is what keeps this rule out of every
// Spring repository that simply enables Actuator.
func TestSpringActuatorBenignExposureQuiet(t *testing.T) {
	cfg := "management:\n  endpoints:\n    web:\n      exposure:\n        include: health,info,metrics,prometheus\n"
	for id := range ruleIDs(scan(t, map[string]string{"application.yml": cfg})) {
		if len(id) > 7 && id[:7] == "spring-" {
			t.Errorf("a benign exposure list must yield no Spring finding, got %s", id)
		}
	}
}

func TestSpringWildcardExposure(t *testing.T) {
	cfg := "management:\n  endpoints:\n    web:\n      exposure:\n        include: \"*\"\n"
	if _, ok := ruleIDs(scan(t, map[string]string{"application.yml": cfg}))["spring-actuator-exposure-wildcard"]; !ok {
		t.Error("expected the wildcard rule to fire")
	}
}

// server.shutdown: graceful is a lifecycle setting and appears in ordinary configs. It must never be read as
// the Actuator shutdown ENDPOINT, which is a different key entirely.
func TestSpringGracefulShutdownIsNotTheEndpoint(t *testing.T) {
	cfg := "server:\n  shutdown: graceful\n  compression:\n    enabled: true\nspring:\n  application:\n    name: api\n"
	if _, bad := ruleIDs(scan(t, map[string]string{"application.yml": cfg}))["spring-actuator-shutdown-enabled"]; bad {
		t.Error("server.shutdown: graceful must not be read as the Actuator shutdown endpoint")
	}
}

func TestSpringShutdownEndpointAndH2Console(t *testing.T) {
	cfg := `spring:
  h2:
    console:
      enabled: true
management:
  endpoint:
    shutdown:
      enabled: true
    health:
      show-details: always
`
	got := ruleIDs(scan(t, map[string]string{"application-dev.yml": cfg}))
	for _, id := range []string{"spring-h2-console-enabled", "spring-actuator-shutdown-enabled", "spring-actuator-health-details-always"} {
		if _, ok := got[id]; !ok {
			t.Errorf("expected %s to fire, got %v", id, keys(got))
		}
	}
}

// show-details: when_authorized is the secure setting and is what the live corpus uses, so it must be quiet.
func TestSpringHealthWhenAuthorizedQuiet(t *testing.T) {
	cfg := "management:\n  endpoint:\n    health:\n      show-details: when_authorized\n      roles: 'ROLE_ADMIN'\n"
	if _, bad := ruleIDs(scan(t, map[string]string{"application.yml": cfg}))["spring-actuator-health-details-always"]; bad {
		t.Error("when_authorized must not be flagged")
	}
}

// Spring accepts the flattened dotted key and the .properties dialect for the same setting, so both must
// reach the same rule.
func TestSpringFlattenedAndPropertiesDialects(t *testing.T) {
	flat := "management.endpoints.web.exposure.include: health,env\n"
	if _, ok := ruleIDs(scan(t, map[string]string{"application.yml": flat}))["spring-actuator-sensitive-endpoint-exposed"]; !ok {
		t.Error("a flattened dotted YAML key must be read")
	}
	props := "spring.application.name=api\nmanagement.endpoints.web.exposure.include=health,heapdump\n"
	if _, ok := ruleIDs(scan(t, map[string]string{"application.properties": props}))["spring-actuator-sensitive-endpoint-exposed"]; !ok {
		t.Error("a .properties key must be read")
	}
}

// A YAML file merely NAMED application.yml with none of the two trees contributes nothing.
func TestSpringUnrelatedApplicationYamlIgnored(t *testing.T) {
	if got := scan(t, map[string]string{"application.yml": "name: fixture\nitems:\n  - a\n  - b\n"}); len(got) != 0 {
		t.Errorf("an unrelated application.yml must yield no findings, got %+v", got)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
