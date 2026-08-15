package api_test

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestSLAOpenAPIContract protects the public surface of the feature. Router-only tests cannot detect
// a renamed path, missing optimistic-concurrency field, or undocumented policy activation response.
func TestSLAOpenAPIContract(t *testing.T) {
	b, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	paths := doc["paths"].(map[string]any)
	want := map[string]map[string]string{
		"/api/v1/sla/policies": {
			"get": "listSLAPolicies", "post": "activateSLAPolicy",
		},
		"/api/v1/engagements/{id}/slas": {
			"get": "listEngagementSLAs",
		},
		"/api/v1/engagements/{id}/slas/{fid}": {
			"get": "getFindingSLA",
		},
		"/api/v1/engagements/{id}/slas/{fid}/assessments": {
			"get": "listSLAAssessmentHistory",
		},
		"/api/v1/engagements/{id}/slas/{fid}/events": {
			"get": "listSLALifecycleEvents",
		},
		"/api/v1/engagements/{id}/slas/{fid}/transition": {
			"post": "transitionFindingSLA",
		},
	}
	for path, methods := range want {
		route, ok := paths[path].(map[string]any)
		if !ok {
			t.Errorf("SLA route %s missing", path)
			continue
		}
		for method, operationID := range methods {
			op, ok := route[method].(map[string]any)
			if !ok {
				t.Errorf("SLA route %s missing %s", path, method)
				continue
			}
			if got := op["operationId"]; got != operationID {
				t.Errorf("%s %s operationId=%v, want %s", method, path, got, operationID)
			}
		}
	}

	transition := paths["/api/v1/engagements/{id}/slas/{fid}/transition"].(map[string]any)["post"].(map[string]any)
	responses := transition["responses"].(map[string]any)
	for _, status := range []string{"200", "400", "401", "403", "404", "409"} {
		if _, ok := responses[status]; !ok {
			t.Errorf("SLA transition response %s missing", status)
		}
	}

	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	request := schemas["SLATransitionRequest"].(map[string]any)
	required := stringSet(request["required"].([]any))
	for _, field := range []string{"to", "reason", "version"} {
		if !required[field] {
			t.Errorf("SLATransitionRequest.%s must be required", field)
		}
	}
	status := schemas["SLARemediationStatus"].(map[string]any)
	wantStatuses := []string{"open", "mitigating", "remediated", "accepted_risk"}
	gotStatuses := status["enum"].([]any)
	if len(gotStatuses) != len(wantStatuses) {
		t.Fatalf("SLA status count=%d, want %d", len(gotStatuses), len(wantStatuses))
	}
	for i, wantStatus := range wantStatuses {
		if gotStatuses[i] != wantStatus {
			t.Errorf("SLA status[%d]=%v, want %s", i, gotStatuses[i], wantStatus)
		}
	}
}

func stringSet(values []any) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result[text] = true
		}
	}
	return result
}
